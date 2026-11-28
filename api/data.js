// /api/data — قراءة وكتابة وحذف سجلات الشركة المشتركة (v2).
// كل الطلبات تتطلب ترويسة: Authorization: Bearer <token>
// (التوكن يُؤخذ من POST /api/auth).
//
// GET    /api/data?collection=X            → { "records": [{ "id", "data", "updated_at" }] }
// GET    /api/data?collection=X&id=Y      → { "record": { "id", "data", "updated_at" } }
// POST   /api/data  { "collection", "id", "data" }  → يحفظ/يحدّث → { "ok": true, "record": {...} }
// PUT    مثل POST
// DELETE /api/data?collection=X&id=Y      → { "ok": true, "deleted": true/false }
//
// فصل الصلاحيات في الخادم (إلزامي — §16.6 من وثيقة التصميم):
// يُفحص دور المستخدم من التوكن قبل كل عملية (قراءة/كتابة/حذف)
// حسب جداول READ_ROLES / WRITE_ROLES / DELETE_ROLES أدناه.
// أي مخالفة → 403 وتُسجَّل في audit_log. مجموعة غير معروفة → 403.
// بلا قاعدة بيانات (لا DATABASE_URL ولا وضع اختبار): كل العمليات 503.
// كلمات المرور لا تعود أبداً في أي GET، ولا تُحفظ إلا مشفرة (scrypt).

const crypto = require('crypto');
const lib = require('./_lib');

const ALL_ROLES = ['admin', 'gm', 'accounts', 'projects', 'secretariat', 'technician', 'storekeeper', 'hr'];

// الأدوار المسموح لها بالقراءة (GET) لكل مجموعة.
const READ_ROLES = {
  users: ['admin', 'accounts'],
  audit_log: ['admin'],
  settings: ['admin'],
  clients: ['admin', 'gm', 'accounts', 'projects', 'secretariat'],
  projects: ['admin', 'gm', 'accounts', 'projects', 'secretariat', 'technician'],
  assignments: ALL_ROLES.slice(),
  media: ['admin', 'gm', 'projects', 'technician'],
  quotations: ['admin', 'gm', 'accounts', 'projects'],
  approvals: ['admin', 'gm', 'accounts'],
  contracts: ['admin', 'gm', 'accounts', 'secretariat'],
  items: ['admin', 'gm', 'accounts', 'projects', 'storekeeper'],
  material_issues: ['admin', 'gm', 'accounts', 'storekeeper'],
  material_returns: ['admin', 'gm', 'accounts', 'storekeeper'],
  payments: ['admin', 'gm', 'accounts'],
  notifications: ALL_ROLES.slice(),
  counters: ['admin', 'gm', 'accounts', 'projects'],
  transactions: ['admin', 'gm', 'accounts'],
  journal: ['admin', 'gm', 'accounts'],
  employees: ['admin', 'gm', 'hr'],
  leaves: ['admin', 'gm', 'hr'],
  reset_markers: ['admin'],
};

// الأدوار المسموح لها بالكتابة (POST/PUT) لكل مجموعة.
// audit_log مرفوضة دائماً من العميل — الخادم فقط يكتبها.
const WRITE_ROLES = {
  users: ['admin', 'accounts'],
  audit_log: [],
  settings: ['admin'],
  clients: ['admin', 'gm', 'projects'],
  projects: ['admin', 'gm', 'projects', 'accounts'],
  assignments: ['admin', 'gm', 'projects'], // + الفني لتكليفه فقط (يُفحص أدناه)
  media: ['admin', 'gm', 'projects', 'technician'],
  quotations: ['admin', 'gm', 'projects', 'accounts'],
  approvals: ['admin', 'gm'],
  contracts: ['admin', 'gm', 'secretariat'],
  items: ['admin', 'gm', 'accounts', 'projects', 'storekeeper'],
  material_issues: ['admin', 'accounts', 'storekeeper', 'gm'],
  material_returns: ['admin', 'accounts', 'storekeeper'],
  payments: ['admin', 'accounts'],
  transactions: ['admin', 'accounts'],
  notifications: ['admin', 'gm', 'projects', 'technician', 'accounts'],
  counters: ['admin', 'gm', 'accounts', 'projects'],
  journal: ['admin', 'accounts'],
  employees: ['admin', 'gm', 'hr'],
  leaves: ['admin', 'gm', 'hr'],
  reset_markers: ['admin'],
};

// الأدوار المسموح لها بالحذف (DELETE): كالكتابة لنفس المجموعة،
// إلا users فمدير النظام فقط، و audit_log مرفوضة دائماً.
const DELETE_ROLES = {};
for (const key of Object.keys(WRITE_ROLES)) {
  DELETE_ROLES[key] = WRITE_ROLES[key].slice();
}
DELETE_ROLES.users = ['admin'];
DELETE_ROLES.audit_log = [];
// الحذف يبقى مقيّداً كما كان قبل توسيع الكتابة أعلاه: توسيع الكتابة
// يخدم خطوات سير العمل فقط (تعميد/اعتماد مالي/إشعار فني)، أما الحذف
// فيبقى للأدوار الأصلية دون توسعة.
DELETE_ROLES.material_issues = ['admin', 'accounts', 'storekeeper'];
DELETE_ROLES.quotations = ['admin', 'gm', 'projects'];
DELETE_ROLES.projects = ['admin', 'gm', 'projects'];
DELETE_ROLES.notifications = ['admin', 'gm', 'projects'];
// كتابة الإشعارات تشمل الأدوار التي تُنشئ إشعارات في سير العمل
// (الفني عند إرسال المعاينة، والحسابات عند الاعتماد المالي)؛ أما حذف
// الإشعارات فيبقى للأدوار الأصلية دون توسعة.

// صيغة المفرد في أفعال سجل التدقيق: create_<singular> / update_ / delete_
const SINGULAR = {
  users: 'user',
  clients: 'client',
  projects: 'project',
  quotations: 'quotation',
  assignments: 'assignment',
  material_issues: 'material_issue',
  material_returns: 'material_return',
  payments: 'payment',
  items: 'item',
  contracts: 'contract',
  approvals: 'approval',
  settings: 'setting',
  media: 'media',
  notifications: 'notification',
  transactions: 'transaction',
  counters: 'counter',
  employees: 'employee',
  leaves: 'leave',
  journal: 'journal',
  reset_markers: 'reset_marker',
};

function normRole(role) {
  if (role === 'projects_manager' || role === 'project_manager') return 'projects';
  return String(role || '');
}

// ---------- سجل التدقيق الخادمي (أفضل جهد، لا يعطّل العملية) ----------
async function writeAudit(companyId, auth, action, collection, docId, summary) {
  try {
    const id = 'al-' + Date.now().toString(36) + '-' + crypto.randomBytes(6).toString('hex');
    await lib.upsertRecord(companyId, 'audit_log', id, {
      id,
      at: new Date().toISOString(),
      username: auth.username,
      userId: auth.userId || auth.username,
      role: auth.role,
      action,
      collection,
      docId: String(docId || ''),
      summary,
    });
  } catch (e) {
    /* audit best-effort */
  }
}

// رفض صلاحية: 403 + تسجيل في audit_log (بأفضل جهد).
async function deny(res, companyId, auth, collection, docId, summary) {
  await writeAudit(companyId, auth, 'permission_denied', collection, docId || '', summary || ('محاولة مرفوضة: ' + auth.username + ' (' + auth.role + ') على ' + collection));
  return lib.sendJson(res, 403, { error: 'ليس لديك صلاحية لهذه العملية' });
}

// ---------- أدوات مساعدة ----------
function stripUserSecrets(record) {
  if (!record || !record.data) return record;
  const data = Object.assign({}, record.data);
  delete data.passwordHash;
  delete data.password;
  return { id: record.id, data, updated_at: record.updated_at };
}

function stripSecretsForCollection(collection, record) {
  if (collection === 'users') return stripUserSecrets(record);
  return record;
}

async function findUserRecord(companyId, idOrUsername) {
  const byId = await lib.getRecord(companyId, 'users', idOrUsername);
  if (byId) return byId;
  const all = await lib.listRecords(companyId, 'users');
  return all.find((r) => r.data && r.data.username === idOrUsername) || null;
}

async function userHasAssignments(companyId, userId, username) {
  const rows = await lib.listRecords(companyId, 'assignments');
  return rows.some((r) => {
    if (!r.data) return false;
    // الواجهة تكتب technicianId؛ ونقبل tech أيضاً للتوافق مع سجلات قديمة.
    const techs = [r.data.tech, r.data.technicianId].filter((v) => v !== undefined && v !== null);
    return techs.some((v) => String(v) === String(userId) || String(v) === String(username));
  });
}

// هل للصنف حركات؟ (مطابقة بالاسم كما في النظام القديم، وبالمعرّف/الرمز أيضاً)
async function itemHasMovements(companyId, item) {
  const name = String((item && item.data && item.data.name) || '').trim();
  const id = String(item ? item.id : '');
  const code = String((item && item.data && item.data.code) || '').trim();
  if (!name && !id) return false;
  const matches = (value) => {
    const v = String(value == null ? '' : value).trim();
    if (!v) return false;
    return (name && v === name) || (id && v === id) || (code && v === code);
  };
  const quotes = await lib.listRecords(companyId, 'quotations');
  for (const q of quotes) {
    const lines = (q.data && q.data.items) || [];
    for (const line of lines) {
      if (matches(line.name) || matches(line.itemId) || matches(line.item)) return true;
    }
  }
  const issues = await lib.listRecords(companyId, 'material_issues');
  for (const m of issues) {
    if (matches(m.data && m.data.itemName) || matches(m.data && m.data.itemId)) return true;
  }
  const returns = await lib.listRecords(companyId, 'material_returns');
  for (const m of returns) {
    if (matches(m.data && m.data.itemName) || matches(m.data && m.data.itemId)) return true;
  }
  return false;
}

module.exports = async function handler(req, res) {
  lib.setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();

  // بلا قاعدة بيانات: لا قراءة ولا كتابة (لا وضع محلي).
  if (lib.getMode() === 'none') {
    return lib.sendJson(res, 503, {
      error: 'لا توجد قاعدة بيانات مربوطة — اربط Vercel Postgres بالمشروع ثم أعد النشر',
    });
  }

  const auth = lib.requireAuth(req, res);
  if (!auth) return; // requireAuth أرسل 401 بنفسه
  // إبطال الجلسة عند تعديل المستخدم: إن تغيّر rev في سجل المستخدم بعد
  // إصدار هذا التوكن (تغيير رمز/دور/صلاحيات) يُرفض التوكن بـ 401
  // حتى يعيد المستخدم الدخول بالبيانات الجديدة.
  // عند خطأ قاعدة البيانات يعيد isTokenRevoked القيمة true (فشل مغلق).
  if (await lib.isTokenRevoked(auth)) {
    return lib.sendJson(res, 401, { error: 'انتهت الجلسة — أُجري تعديل على حسابك، سجّل الدخول مجدداً' });
  }
  const companyId = auth.companyId || lib.DEFAULT_COMPANY_ID;
  const role = normRole(auth.role);
  const isAdmin = role === 'admin';

  try {
    if (req.method === 'GET') {
      const collection = String((req.query && req.query.collection) || '');
      const id = req.query && req.query.id ? String(req.query.id) : '';
      if (!lib.isValidName(collection)) {
        return lib.sendJson(res, 400, { error: 'اسم المجموعة (collection) غير صالح' });
      }
      const allowed = READ_ROLES[collection] || [];
      if (!allowed.includes(role)) {
        return deny(res, companyId, auth, collection, id, 'قراءة مرفوضة: ' + auth.username + ' (' + role + ') طلب قراءة ' + collection);
      }
      if (id) {
        if (!lib.isValidName(id)) {
          return lib.sendJson(res, 400, { error: 'المعرّف (id) غير صالح' });
        }
        let record = await lib.getRecord(companyId, collection, id);
        if (!record && collection === 'users') record = await findUserRecord(companyId, id);
        if (!record) return lib.sendJson(res, 404, { error: 'السجل غير موجود' });
        return lib.sendJson(res, 200, { record: stripSecretsForCollection(collection, record) });
      }
      const records = await lib.listRecords(companyId, collection);
      return lib.sendJson(res, 200, {
        records: records.map((r) => stripSecretsForCollection(collection, r)),
      });
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

      // audit_log: الكتابة مرفوضة دائماً من العميل.
      if (collection === 'audit_log') {
        return deny(res, companyId, auth, collection, id, 'كتابة مرفوضة في سجل التدقيق من العميل');
      }

      const allowed = WRITE_ROLES[collection];
      if (!allowed) {
        return deny(res, companyId, auth, collection, id, 'مجموعة غير معروفة: ' + collection);
      }

      // الفني: يسمح له فقط بتحديث تكليف سجله tech يساوي userId في التوكن
      // (اعتماد المهمة) — ولا إنشاء تكليفات ولا تعديل تكليف غيره.
      let technicianOwnAssignment = false;
      if (collection === 'assignments' && role === 'technician') {
        const existing = await lib.getRecord(companyId, collection, id);
        // الواجهة تكتب technicianId؛ ونقبل tech أيضاً للتوافق مع سجلات قديمة.
        const techs = existing && existing.data
          ? [existing.data.tech, existing.data.technicianId].filter((v) => v !== undefined && v !== null)
          : [];
        if (
          existing &&
          existing.data &&
          techs.some((v) => String(v) === String(auth.userId || '') || String(v) === String(auth.username || ''))
        ) {
          technicianOwnAssignment = true;
        } else {
          return deny(res, companyId, auth, collection, id, 'الفني لا يعدّل إلا تكليفه الخاص (اعتماد المهمة)');
        }
      }

      // الفني: يسمح له فقط بتحديث مشروع مُسند إليه (إرسال المعاينة
      // يغيّر حالة المشروع) — ولا إنشاء مشاريع ولا تعديل مشروع غيره.
      let technicianOwnProject = false;
      if (collection === 'projects' && role === 'technician') {
        const assigns = await lib.listRecords(companyId, 'assignments');
        const mine = assigns.some(
          (a) =>
            a.data &&
            String(a.data.projectId) === String(id) &&
            [a.data.tech, a.data.technicianId].some(
              (v) =>
                v !== undefined &&
                v !== null &&
                (String(v) === String(auth.userId || '') || String(v) === String(auth.username || ''))
            )
        );
        if (mine) {
          technicianOwnProject = true;
        } else {
          return deny(res, companyId, auth, collection, id, 'الفني لا يعدّل إلا مشروعاً مُسنداً إليه (إرسال المعاينة)');
        }
      }

      if (!technicianOwnAssignment && !technicianOwnProject && !allowed.includes(role)) {
        return deny(res, companyId, auth, collection, id, 'كتابة مرفوضة: ' + auth.username + ' (' + role + ') على ' + collection);
      }

      // ----- قواعد المستخدمين -----
      if (collection === 'users') {
        const existing = await findUserRecord(companyId, id);
        const existingByUsername = data.username
          ? await findUserRecord(companyId, String(data.username))
          : null;
        const target = existing || existingByUsername;
        const targetUsername = String(
          (target && target.data && target.data.username) || data.username || ''
        );
        const isTargetOne = targetUsername === lib.ADMIN_USERNAME;

        // غير مدير النظام: لا تعديل سجل «1».
        if (!isAdmin && isTargetOne) {
          return deny(res, companyId, auth, collection, id, 'تعديل مرفوض: حساب مدير النظام «1» لا يعدّله إلا مدير النظام');
        }
        // غير مدير النظام: لا تعيين دور admin.
        if (!isAdmin && data.role === 'admin') {
          return deny(res, companyId, auth, collection, id, 'تعيين مرفوض: دور مدير النظام لا يمنحه إلا مدير النظام');
        }
        // غير مدير النظام: لا منح صلاحية التقارير الرقابية (audit) جديدة.
        if (!isAdmin && Array.isArray(data.permissions) && data.permissions.includes('audit')) {
          const hadAudit =
            target && Array.isArray(target.data.permissions) && target.data.permissions.includes('audit');
          if (!hadAudit) {
            return deny(res, companyId, auth, collection, id, 'منح مرفوض: صلاحية «التقارير الرقابية» لا يمنحها إلا مدير النظام');
          }
        }

        // تفرد اسم المستخدم: مستخدم آخر بنفس الاسم وبمعرّف مختلف → 409.
        if (data.username) {
          const allUsers = await lib.listRecords(companyId, 'users');
          const clash = allUsers.find(
            (r) =>
              r.data &&
              String(r.data.username) === String(data.username) &&
              String(r.id) !== String(id)
          );
          if (clash) {
            return lib.sendJson(res, 409, { error: 'اسم المستخدم موجود مسبقًا' });
          }
        }

        // كلمة المرور: إن وُجد حقل password نصًا يُشفَّر إلى passwordHash
        // ثم يُحذف؛ ولا يُقبل passwordHash مرسل من العميل مباشرة.
        const plain = typeof data.password === 'string' ? data.password : '';
        delete data.password;
        delete data.passwordHash;
        if (plain.length > 0) {
          data.passwordHash = lib.hashPassword(plain);
        } else if (target && target.data.passwordHash) {
          data.passwordHash = target.data.passwordHash; // إبقاء الحالية عند عدم تغييرها
        }
        if (!data.passwordHash) {
          return lib.sendJson(res, 400, { error: 'كلمة المرور مطلوبة' });
        }

        // حماية «1»: أي كتابة على سجله تُجبر القيم الكاملة دون المساس
        // بكلمة المرور (حُفظت أعلاه).
        if (isTargetOne) {
          data.username = lib.ADMIN_USERNAME;
          data.role = 'admin';
          data.fullName = 'مدير النظام';
          data.permissions = lib.FULL_PERMS.slice();
          data.active = true;
        } else if (!Array.isArray(data.permissions)) {
          // صلاحيات افتراضية من الدور عند عدم تحديدها.
          const defaults = lib.ROLE_SCREENS[data.role] || [];
          data.permissions = defaults.slice();
        }
        if (data.username === undefined) data.username = targetUsername || id;
        data.id = id;
        // رفع rev فقط عند تغيير فعلي في الحقول الأمنية (كلمة المرور أو
        // الدور أو الصلاحيات أو اسم المستخدم أو الإيقاف) حتى تُبطل
        // توكناته القديمة؛ إعادة إرسال السجل نفسه دون تغيير فعلي (كما
        // تفعل مزامنة الواجهة حين تعيد حفظ كل صفوف المستخدمين عند إنشاء
        // مستخدم آخر) لا ترفع rev ولا تُبطل جلسة أحد. هذا هو معنى rev
        // الموثق في _lib.js: يرتفع عند تغيير الرمز/الدور/الصلاحيات.
        const prev = target ? target.data : null;
        const permsNow = Array.isArray(data.permissions) ? data.permissions : [];
        const permsPrev = prev && Array.isArray(prev.permissions) ? prev.permissions : [];
        const secChanged =
          !prev ||
          plain.length > 0 ||
          (data.username !== undefined && String(data.username) !== String(prev.username || '')) ||
          (data.role !== undefined && String(data.role) !== String(prev.role || '')) ||
          JSON.stringify(permsNow) !== JSON.stringify(permsPrev) ||
          (data.active !== undefined && Boolean(data.active) !== (prev.active !== false));
        data.rev = secChanged ? ((prev ? Number(prev.rev) || 1 : 0) + 1) : (Number(prev.rev) || 1);
      }

      const record = await lib.upsertRecord(companyId, collection, id, data);
      const singular = SINGULAR[collection] || collection;
      const verb = req.method === 'PUT' ? 'update_' : 'create_';
      await writeAudit(
        companyId,
        auth,
        verb + singular,
        collection,
        id,
        (req.method === 'PUT' ? 'تعديل ' : 'إنشاء ') + collection + ': ' + id
      );
      return lib.sendJson(res, 200, {
        ok: true,
        record: stripSecretsForCollection(collection, record),
      });
    }

    if (req.method === 'DELETE') {
      const collection = String((req.query && req.query.collection) || '');
      const id = String((req.query && req.query.id) || '');
      if (!lib.isValidName(collection) || !lib.isValidName(id)) {
        return lib.sendJson(res, 400, { error: 'collection و id مطلوبان وصالحان' });
      }

      // audit_log: الحذف مرفوض دائماً.
      if (collection === 'audit_log') {
        return deny(res, companyId, auth, collection, id, 'حذف مرفوض في سجل التدقيق');
      }
      const allowed = DELETE_ROLES[collection];
      if (!allowed) {
        return deny(res, companyId, auth, collection, id, 'مجموعة غير معروفة: ' + collection);
      }
      if (!allowed.includes(role)) {
        return deny(res, companyId, auth, collection, id, 'حذف مرفوض: ' + auth.username + ' (' + role + ') على ' + collection);
      }

      // حماية «1»: حذفه → 403.
      if (collection === 'users') {
        const target = await findUserRecord(companyId, id);
        if (target && target.data && target.data.username === lib.ADMIN_USERNAME) {
          return deny(res, companyId, auth, collection, id, 'حذف مرفوض: حساب مدير النظام «1» محمي ولا يُحذف');
        }
        // حذف مستخدم لديه تكليفات → 409.
        if (target) {
          const hasAssignments = await userHasAssignments(
            companyId,
            target.id,
            target.data.username
          );
          if (hasAssignments) {
            return lib.sendJson(res, 409, { error: 'لا يمكن حذف المستخدم — لديه تكليفات مسندة إليه' });
          }
        }
      }

      // حذف صنف له حركات → 409.
      if (collection === 'items') {
        const target = await lib.getRecord(companyId, collection, id);
        if (target && (await itemHasMovements(companyId, target))) {
          return lib.sendJson(res, 409, { error: 'لا يمكن حذف الصنف — توجد عليه حركات' });
        }
      }

      const deleted = await lib.deleteRecord(companyId, collection, id);
      if (deleted) {
        const singular = SINGULAR[collection] || collection;
        await writeAudit(companyId, auth, 'delete_' + singular, collection, id, 'حذف ' + collection + ': ' + id);
      }
      return lib.sendJson(res, 200, { ok: true, deleted });
    }

    return lib.sendJson(res, 405, { error: 'الطريقة غير مدعومة' });
  } catch (err) {
    console.error('data handler error:', err);
    return lib.sendJson(res, 500, { error: 'خطأ داخلي في الخادم' });
  }
};
