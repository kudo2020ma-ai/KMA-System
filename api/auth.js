// POST /api/auth — تسجيل الدخول (v2).
// الطلب:  { "username": "...", "password": "..." }
// النجاح: { "token": "...", "user": { "username", "fullName", "role", "permissions", "userId" }, "companyId": "..." }
// الفشل:  401 { "error": "بيانات الدخول غير صحيحة" }
// القفل:  423 بعد 5 محاولات فاشلة متتالية لنفس المستخدم خلال 15 دقيقة.
//
// - كلمات المرور تُقارن بصيغة scrypt فقط (passwordHash)؛ لا نص صريح
//   ولا SHA-256 قديم؛ قاعدة البيانات فارغة وبداية جديدة.
// - الدخول الافتراضي للمدير 1/1 يعمل فقط عند عدم وجود أي مستخدم في
//   قاعدة البيانات إطلاقاً (تهيئة أول مرة): يُنشأ حينها سجل مدير النظام
//   «1» في قاعدة البيانات بكلمة مرور مشفرة (passwordHash لكلمة «1»)
//   ثم يُصدر التوكن. بعد ذلك لا يعمل 1/1 إلا إن كانت هي كلمة المرور
//   الحالية فعلاً في السجل.
// - بلا قاعدة بيانات (لا DATABASE_URL ولا وضع اختبار): 503.
// - في الإنتاج (Postgres) لا نعمل بلا JWT_SECRET أبداً.
// - التوكن JWT مبسّط بتوقيع HMAC-SHA256 بمفتاح JWT_SECRET.

const crypto = require('crypto');
const lib = require('./_lib');

const LOCKOUT_MAX_FAILURES = 5;
const LOCKOUT_WINDOW_MS = 15 * 60 * 1000;

// سجل التدقيق لعمليات الدخول (خادم): يُسجَّل كل دخول ناجح وفاشل في
// مجموعة audit_log — أفضل جهد، فلا يعطّل الدخول أبداً عند فشل الكتابة.
async function auditAuth(companyId, username, role, action, summary) {
  try {
    const id = 'al-' + Date.now().toString(36) + '-' + crypto.randomBytes(6).toString('hex');
    await lib.upsertRecord(companyId, 'audit_log', id, {
      id,
      at: new Date().toISOString(),
      username,
      userId: username,
      role: role || '—',
      action,
      collection: 'users',
      docId: username,
      screen: 'الدخول',
      summary,
    });
  } catch (e) {
    /* audit best-effort — never break login */
  }
}

// عدد محاولات الدخول الفاشلة المتتالية لنفس المستخدم خلال 15 دقيقة،
// محسوبة من audit_log. عند أي فشل في العد نعيد -1 (غير معروف)
// فيُسمح بالدخول ولا يُحجب.
async function countRecentFailures(companyId, username) {
  try {
    const rows = await lib.listRecords(companyId, 'audit_log');
    const since = Date.now() - LOCKOUT_WINDOW_MS;
    const mine = rows
      .filter((r) => r.data && r.data.username === username)
      .sort((a, b) => String(b.data.at || '').localeCompare(String(a.data.at || '')));
    let fails = 0;
    for (const row of mine) {
      const at = Date.parse(row.data.at || '');
      if (!Number.isNaN(at) && at < since) break; // أقدم من النافذة
      if (row.data.action === 'login_success') break; // نجاح يقطع التتالي
      if (row.data.action === 'login_failed') fails += 1;
    }
    return fails;
  } catch (e) {
    return -1;
  }
}

module.exports = async function handler(req, res) {
  lib.setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    return lib.sendJson(res, 405, { error: 'الطريقة غير مدعومة — استخدم POST' });
  }

  // بلا قاعدة بيانات: لا دخول أصلاً (لا وضع محلي).
  if (lib.getMode() === 'none') {
    return lib.sendJson(res, 503, {
      error: 'لا توجد قاعدة بيانات مربوطة — اربط Vercel Postgres بالمشروع ثم أعد النشر',
    });
  }

  // في الإنتاج (Postgres) لا نعمل بلا JWT_SECRET أبداً.
  if (lib.isPostgresMode() && !lib.isJwtSecretConfigured()) {
    return lib.sendJson(res, 500, { error: 'JWT_SECRET غير مضبوط في متغيرات بيئة Vercel' });
  }

  const body = lib.parseBody(req);
  const username = String(body.username || '').trim();
  const password = String(body.password || '');

  if (!username || !password) {
    if (username) await auditAuth(lib.DEFAULT_COMPANY_ID, username, '—', 'login_failed', 'محاولة دخول فاشلة — بيانات ناقصة');
    return lib.sendJson(res, 400, { error: 'اسم المستخدم وكلمة المرور مطلوبان' });
  }

  const companyId = lib.DEFAULT_COMPANY_ID;

  // قفل الحساب: 5 محاولات فاشلة متتالية خلال 15 دقيقة.
  const recentFailures = await countRecentFailures(companyId, username);
  if (recentFailures >= LOCKOUT_MAX_FAILURES) {
    await auditAuth(companyId, username, '—', 'login_failed', 'محاولة دخول مرفوضة — الحساب مقفل مؤقتًا بعد 5 محاولات فاشلة');
    return lib.sendJson(res, 423, {
      error: 'الحساب مقفل مؤقتًا بعد 5 محاولات دخول فاشلة — أعد المحاولة بعد 15 دقيقة',
    });
  }

  // 1) المستخدمون من مجموعة users في قاعدة البيانات — بما فيها حساب
  //    المدير "1" إن وُجد؛ كلمة المرور تُقارن بالمخزنة المشفرة فقط
  //    (scrypt)، ولا يوجد أي تجاوز ثابت 1/1.
  try {
    const record =
      (await lib.getRecord(companyId, 'users', username)) ||
      (await lib.listRecords(companyId, 'users')).find(
        (r) => r.data && r.data.username === username
      );

    if (record && record.data) {
      const data = record.data;
      if (data.active === false) {
        await auditAuth(companyId, username, data.role || '—', 'login_failed', 'محاولة دخول فاشلة للمستخدم ' + username + ' — الحساب موقوف');
        return lib.sendJson(res, 401, { error: 'بيانات الدخول غير صحيحة' });
      }
      if (lib.verifyPassword(data.passwordHash, password)) {
        const user = {
          username,
          fullName: data.fullName || username,
          role: data.role || 'user',
          permissions: Array.isArray(data.permissions) ? data.permissions.slice() : [],
          userId: data.id || record.id || username,
          rev: Number(data.rev) || 1,
        };
        await auditAuth(companyId, username, user.role, 'login_success', 'تسجيل دخول ناجح للمستخدم ' + username);
        return lib.sendJson(res, 200, {
          token: lib.createToken(user, companyId),
          user: {
            username: user.username,
            fullName: user.fullName,
            role: user.role,
            permissions: user.permissions,
            userId: user.userId,
          },
          companyId,
        });
      }
    }
  } catch (err) {
    console.error('auth lookup error:', err);
    return lib.sendJson(res, 500, { error: 'خطأ داخلي أثناء التحقق من المستخدم' });
  }

  // 2) تهيئة أول مرة فقط: إن لم يوجد أي مستخدم في قاعدة البيانات إطلاقاً
  //    يُسمح بالدخول 1/1، ويُنشأ سجل مدير النظام «1» في قاعدة البيانات
  //    بكلمة مرور مشفرة (passwordHash) قبل إصدار التوكن.
  //    إن وُجد أي مستخدم — ومنه حساب "1" بعد تغيير كلمة مروره — لا يعمل 1/1 أبداً.
  if (username === '1' && password === '1') {
    try {
      const existing = await lib.listRecords(companyId, 'users');
      if (existing.length === 0) {
        const adminData = {
          id: 'u-1',
          username: '1',
          passwordHash: lib.hashPassword('1'),
          fullName: 'مدير النظام',
          role: 'admin',
          permissions: lib.FULL_PERMS.slice(),
          phone: '',
          active: true,
          rev: 1,
          companyId,
        };
        await lib.upsertRecord(companyId, 'users', 'u-1', adminData);
        const user = {
          username: '1',
          fullName: 'مدير النظام',
          role: 'admin',
          permissions: lib.FULL_PERMS.slice(),
          userId: 'u-1',
          rev: 1,
        };
        await auditAuth(companyId, username, 'admin', 'login_success', 'تسجيل دخول ناجح للمستخدم 1 (تهيئة أول مرة)');
        return lib.sendJson(res, 200, {
          token: lib.createToken(user, companyId),
          user: {
            username: user.username,
            fullName: user.fullName,
            role: user.role,
            permissions: user.permissions,
            userId: user.userId,
          },
          companyId,
        });
      }
    } catch (err) {
      console.error('auth bootstrap check error:', err);
    }
  }

  await auditAuth(companyId, username, '—', 'login_failed', 'محاولة دخول فاشلة للمستخدم ' + username + ' — بيانات غير صحيحة');
  return lib.sendJson(res, 401, { error: 'بيانات الدخول غير صحيحة' });
};
