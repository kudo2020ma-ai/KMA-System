// GET /api/health — فحص سلامة الواجهة الخلفية وقاعدة البيانات (v2).
// لا يحتاج توكن. يعيد وضع التخزين الحالي.
// الأوضاع: 'postgres' (الإنتاج — دائم) أو 'test' (مخزن ذاكرة للاختبار
// فقط) أو 'none' (لا قاعدة بيانات — 503).
// persistent=true فقط في وضع postgres. لا وضع محلي إطلاقًا.

const lib = require('./_lib');

module.exports = async function handler(req, res) {
  lib.setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') {
    return lib.sendJson(res, 405, { error: 'الطريقة غير مدعومة — استخدم GET' });
  }

  const mode = lib.getMode();

  if (mode === 'none') {
    return lib.sendJson(res, 503, {
      ok: false,
      service: 'mshry-shared-db',
      mode,
      persistent: false,
      db: 'none',
      jwtSecretConfigured: lib.isJwtSecretConfigured(),
      error: 'لا توجد قاعدة بيانات مربوطة — اربط Vercel Postgres بالمشروع ثم أعد النشر',
      time: new Date().toISOString(),
    });
  }

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
        persistent: true,
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
    // persistent=true فقط في وضع postgres: القاعدة الدائمة الوحيدة.
    // في وضع test يكون التخزين ذاكرة داخل العملية للاختبار فقط.
    persistent: lib.isPostgresMode(),
    db,
    jwtSecretConfigured: lib.isJwtSecretConfigured(),
    time: new Date().toISOString(),
  });
};
