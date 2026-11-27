// /api/data — قراءة وكتابة وحذف سجلات الشركة المشتركة.
// كل الطلبات تتطلب ترويسة: Authorization: Bearer <token>
// (التوكن يُؤخذ من POST /api/auth).
//
// GET    /api/data?collection=X            → { "records": [{ "id", "data", "updated_at" }] }
// GET    /api/data?collection=X&id=Y      → { "record": { "id", "data", "updated_at" } }
// POST   /api/data  { "collection", "id", "data" }  → يحفظ/يحدّث → { "ok": true, "record": {...} }
// DELETE /api/data?collection=X&id=Y      → { "ok": true, "deleted": true/false }
//
// المجموعات (collections) أمثلة لنظام مشاريع المقاولات: projects, clients,
// technicians, assignments, site-reports, quotations, contracts,
// materials, payments, users, settings...
// اسم المجموعة والمعرّف: أحرف وأرقام و _ و - فقط (حتى 64 حرفاً).
// البيانات تُعزل حسب companyId الموجود في التوكن، فلا يرى موظف شركة
// بيانات شركة أخرى.

const lib = require('./_lib');

module.exports = async function handler(req, res) {
  lib.setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  const auth = lib.requireAuth(req, res);
  if (!auth) return; // requireAuth أرسل 401 بنفسه
  const companyId = auth.companyId || lib.DEFAULT_COMPANY_ID;

  // إبطال الجلسة عند تعديل المستخدم: إن تغيّر rev في سجل المستخدم بعد
  // إصدار هذا التوكن (تغيير رمز/دور/صلاحيات) يُرفض التوكن بـ 401
  // حتى يعيد المستخدم الدخول بالبيانات الجديدة.
  if (await lib.isTokenRevoked(auth)) {
    return lib.sendJson(res, 401, { error: 'انتهت الجلسة — أُجري تعديل على حسابك، سجّل الدخول مجدداً' });
  }

  try {
    // في وضع local-json على Vercel لا يوجد تخزين دائم أصلاً (ملف المشروع
    // للقراءة فقط، وكل استدعاء قد يعمل على نسخة مختلفة)، فالكتابة هنا
    // كانت تفشل بصمت (500) أو تختفي بين الطلبات. نرفضها صراحة بـ 503
    // بدلاً من إيهام العميل بنجاح كاذب؛ القراءة تبقى متاحة (تعيد فارغاً).
    if (!lib.isPostgresMode() && process.env.VERCEL && (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE')) {
      return lib.sendJson(res, 503, { error: 'التخزين المحلي المؤقت غير دائم على Vercel — أنشئ قاعدة Postgres من لوحة Vercel واربطها بالمشروع ثم أعد النشر' });
    }

    if (req.method === 'GET') {
      const collection = String((req.query && req.query.collection) || '');
      const id = req.query && req.query.id ? String(req.query.id) : '';
      if (!lib.isValidName(collection)) {
        return lib.sendJson(res, 400, { error: 'اسم المجموعة (collection) غير صالح' });
      }
      if (id) {
        if (!lib.isValidName(id)) {
          return lib.sendJson(res, 400, { error: 'المعرّف (id) غير صالح' });
        }
        const record = await lib.getRecord(companyId, collection, id);
        if (!record) return lib.sendJson(res, 404, { error: 'السجل غير موجود' });
        return lib.sendJson(res, 200, { record });
      }
      const records = await lib.listRecords(companyId, collection);
      return lib.sendJson(res, 200, { records });
    }

    if (req.method === 'POST' || req.method === 'PUT') {
      const body = lib.parseBody(req);
      const collection = String(body.collection || '');
      const id = String(body.id || '');
      const data = body.data;
      if (!lib.isValidName(collection)) {
        return lib.sendJson(res, 400, { error: 'اسم المجموعة (collection) غير صالح' });
      }
      if (!lib.isValidName(id)) {
        return lib.sendJson(res, 400, { error: 'المعرّف (id) غير صالح' });
      }
      if (!data || typeof data !== 'object' || Array.isArray(data)) {
        return lib.sendJson(res, 400, { error: 'حقل data يجب أن يكون كائناً (object)' });
      }
      const record = await lib.upsertRecord(companyId, collection, id, data);
      return lib.sendJson(res, 200, { ok: true, record });
    }

    if (req.method === 'DELETE') {
      const collection = String((req.query && req.query.collection) || '');
      const id = String((req.query && req.query.id) || '');
      if (!lib.isValidName(collection) || !lib.isValidName(id)) {
        return lib.sendJson(res, 400, { error: 'collection و id مطلوبان وصالحان' });
      }
      const deleted = await lib.deleteRecord(companyId, collection, id);
      return lib.sendJson(res, 200, { ok: true, deleted });
    }

    return lib.sendJson(res, 405, { error: 'الطريقة غير مدعومة' });
  } catch (err) {
    console.error('data handler error:', err);
    return lib.sendJson(res, 500, { error: 'خطأ داخلي في الخادم' });
  }
};
