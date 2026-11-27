// POST /api/auth — تسجيل الدخول.
// الطلب:  { "username": "...", "password": "..." }
// النجاح: { "token": "...", "user": { "username", "fullName", "role" }, "companyId": "..." }
// الفشل:  401 { "error": "بيانات الدخول غير صحيحة" }
//
// - الدخول الافتراضي للمدير 1/1 يعمل فقط عند عدم وجود أي مستخدم في قاعدة
//   البيانات إطلاقاً (تهيئة أول مرة)؛ بعد زرع المدير تُقارن كلمة المرور المخزنة فقط.
// - المستخدمون الآخرون يُقرأون من مجموعة "users" في قاعدة البيانات
//   (سجل لكل مستخدم: id = اسم المستخدم، و data = { username, password, fullName, role }).
//   يُنشئ المدير هؤلاء المستخدمين من داخل النظام (شاشة المستخدمين) فيحفظون
//   في مجموعة users، فيعمل دخولهم فوراً من أي جهاز.
// - التوكن JWT مبسّط بتوقيع HMAC-SHA256 بمفتاح JWT_SECRET من متغيرات البيئة.

const crypto = require('crypto');
const lib = require('./_lib');

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function passwordMatches(stored, supplied) {
  if (stored === undefined || stored === null) return false;
  // كلمة المرور قد تكون مخزّنة نصاً صريحاً (توافقاً مع النظام الحالي)
  // أو بصيغة SHA-256 hex. نقبل الصيغتين.
  if (String(stored) === String(supplied)) return true;
  if (String(stored) === sha256(supplied)) return true;
  return false;
}

// سجل التدقيق لعمليات الدخول (خادم): يُسجَّل كل دخول ناجح وفاشل في
// مجموعة audit_log — أفضل جهد، فلا يعطّل الدخول أبداً عند فشل الكتابة.
// (دخول الوضع المحلي يُسجَّل من الواجهة نفسها؛ أما هنا فيُسجَّل كل
// محاولة تصل إلى الخادم، فيراها المدير من أي جهاز.)
async function auditAuth(companyId, username, role, action, summary) {
  try {
    const id = 'al-' + Date.now().toString(36) + '-' + crypto.randomBytes(6).toString('hex');
    await lib.upsertRecord(companyId, 'audit_log', id, {
      id,
      at: new Date().toISOString(),
      username,
      fullName: username,
      role: role || '—',
      action,
      screen: 'الدخول',
      docNo: '',
      summary,
    });
  } catch (e) {
    /* audit best-effort — never break login */
  }
}

module.exports = async function handler(req, res) {
  lib.setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') {
    return lib.sendJson(res, 405, { error: 'الطريقة غير مدعومة — استخدم POST' });
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


  // 1) المستخدمون من مجموعة users في قاعدة البيانات — بما فيها حساب المدير "1"
  //    إن وُجد؛ كلمة المرور تُقارن دائماً بالمخزنة، ولا يوجد أي تجاوز ثابت 1/1.
  try {
    const companyId = lib.DEFAULT_COMPANY_ID;
    const record =
      (await lib.getRecord(companyId, 'users', username)) ||
      (await lib.listRecords(companyId, 'users')).find(
        (r) => r.data && r.data.username === username
      );

    if (record && record.data && passwordMatches(record.data.password, password)) {
      const user = {
        username,
        fullName: record.data.fullName || username,
        role: record.data.role || 'user',
        rev: Number(record.data.rev) || 1,
      };
      const userCompanyId = record.data.companyId || companyId;
      await auditAuth(userCompanyId, username, user.role, 'login_success', 'تسجيل دخول ناجح للمستخدم ' + username);
      return lib.sendJson(res, 200, {
        token: lib.createToken(user, userCompanyId),
        user,
        companyId: userCompanyId,
      });
    }
  } catch (err) {
    console.error('auth lookup error:', err);
    return lib.sendJson(res, 500, { error: 'خطأ داخلي أثناء التحقق من المستخدم' });
  }

  // 2) تهيئة أول مرة فقط: إن لم يوجد أي مستخدم في قاعدة البيانات إطلاقاً
  //    يُسمح بالدخول 1/1 (يُزرع المدير بعدها من النظام ويُحفظ في القاعدة).
  //    إن وُجد أي مستخدم — ومنه حساب "1" بعد تغيير كلمة مروره — لا يعمل 1/1 أبداً.
  if (username === '1' && password === '1') {
    try {
      const existing = await lib.listRecords(lib.DEFAULT_COMPANY_ID, 'users');
      if (existing.length === 0) {
        const user = { username: '1', fullName: 'مدير النظام', role: 'admin', rev: 1 };
        const companyId = lib.DEFAULT_COMPANY_ID;
        await auditAuth(companyId, username, 'admin', 'login_success', 'تسجيل دخول ناجح للمستخدم 1 (تهيئة أول مرة)');
        return lib.sendJson(res, 200, {
          token: lib.createToken(user, companyId),
          user,
          companyId,
        });
      }
    } catch (err) {
      console.error('auth bootstrap check error:', err);
    }
  }

  await auditAuth(lib.DEFAULT_COMPANY_ID, username, '—', 'login_failed', 'محاولة دخول فاشلة للمستخدم ' + username + ' — بيانات غير صحيحة');
  return lib.sendJson(res, 401, { error: 'بيانات الدخول غير صحيحة' });
};
