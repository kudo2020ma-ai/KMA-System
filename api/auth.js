// POST /api/auth — تسجيل الدخول.
// الطلب:  { "username": "...", "password": "..." }
// النجاح: { "token": "...", "user": { "username", "fullName", "role" }, "companyId": "..." }
// الفشل:  401 { "error": "بيانات الدخول غير صحيحة" }
//
// - الدخول الافتراضي للمدير: username = "1" و password = "1" (كما في النظام الحالي).
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
    return lib.sendJson(res, 400, { error: 'اسم المستخدم وكلمة المرور مطلوبان' });
  }

  // 1) المدير الافتراضي 1/1 — يعمل دائماً، حتى قبل إنشاء أي مستخدم.
  if (username === '1' && password === '1') {
    const user = { username: '1', fullName: 'المدير', role: 'admin' };
    const companyId = lib.DEFAULT_COMPANY_ID;
    return lib.sendJson(res, 200, {
      token: lib.createToken(user, companyId),
      user,
      companyId,
    });
  }

  // 2) المستخدمون الآخرون من مجموعة users في قاعدة البيانات.
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
      };
      const userCompanyId = record.data.companyId || companyId;
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

  return lib.sendJson(res, 401, { error: 'بيانات الدخول غير صحيحة' });
};
