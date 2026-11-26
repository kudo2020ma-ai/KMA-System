// GET /api/health — فحص سلامة الواجهة الخلفية وقاعدة البيانات.
// لا يحتاج توكن. يعيد وضع التخزين الحالي (postgres أو local-json).

const lib = require('./_lib');

module.exports = async function handler(req, res) {
  lib.setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') {
    return lib.sendJson(res, 405, { error: 'الطريقة غير مدعومة — استخدم GET' });
  }

  const mode = lib.getMode();
  let db = 'ok';
  if (lib.isPostgresMode()) {
    try {
      const { sql } = require('@vercel/postgres');
      await sql`SELECT 1 AS ok`;
    } catch (err) {
      db = 'error';
      return lib.sendJson(res, 503, {
        ok: false,
        service: 'mshry-shared-db',
        mode,
        db,
        jwtSecretConfigured: lib.isJwtSecretConfigured(),
        error: 'تعذّر الاتصال بقاعدة البيانات',
        time: new Date().toISOString(),
      });
    }
  }

  return lib.sendJson(res, 200, {
    ok: true,
    service: 'mshry-shared-db',
    mode,
    // persistent=false في وضع local-json: التخزين ملف محلي لا يدوم
    // في دوال Vercel بلا خادم (نظام ملفات للقراءة فقط + نسخ مؤقتة)،
    // فلا يجوز للعميل اعتباره قاعدة مشتركة. القاعدة الدائمة هي Postgres فقط.
    persistent: lib.isPostgresMode(),
    db,
    jwtSecretConfigured: lib.isJwtSecretConfigured(),
    time: new Date().toISOString(),
  });
};
