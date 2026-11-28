// مكتبة مشتركة لدوال نظام إدارة مشاريع المقاولات v2: التوكن (HMAC) + طبقة التخزين.
// التخزين الوحيد في الإنتاج هو Vercel Postgres (عند وجود DATABASE_URL).
// لا يوجد وضع محلي إطلاقًا في هذا الكود: لا ملف JSON محلي — حُذف نهائيًا.
// وترفض الواجهات العمل بـ 503 حتى تُربط قاعدة البيانات.
// للاختبارات فقط: مخزن ذاكرة داخل العملية يُفعَّل بإحدى طريقتين:
//   - دالة setTestStore(store) يستدعيها ملف الاختبار داخل العملية، أو
//   - متغير البيئة MSHRY_TEST_MODE=1 فينشئ مخزن ذاكرة داخل العملية نفسها.
//   والوضع في هذه الحالة 'test'. لا ملفات، ولا وضع افتراضي غير Postgres.
// كلمات المرور: scrypt فقط (scrypt$<saltHex>$<hashHex>) — لا نص صريح
// ولا SHA-256 قديم؛ قاعدة البيانات فارغة وبداية جديدة.

const crypto = require('crypto');

const DEV_SECRET_FALLBACK = 'dev-only-change-me-NOT-FOR-PRODUCTION';
const DEFAULT_COMPANY_ID = 'mshry-default';
const ADMIN_USERNAME = '1';

// الشاشات الـ 17 الكاملة لمدير النظام (كما في النظام القديم).
const FULL_PERMS = [
  'dashboard', 'projects', 'tasks', 'quotations', 'approvals',
  'materials', 'returns', 'contracts', 'financial', 'accounts',
  'reports', 'audit', 'users', 'employees', 'notifications',
  'settings', 'items',
];

// الصلاحيات الافتراضية لكل دور عند إنشاء مستخدم دون تحديد صلاحيات.
const ROLE_SCREENS = {
  admin: FULL_PERMS.slice(),
  gm: ['dashboard', 'projects', 'quotations', 'approvals', 'financial', 'accounts', 'reports', 'notifications', 'items'],
  projects: ['dashboard', 'projects', 'tasks', 'quotations', 'approvals', 'notifications', 'items'],
  projects_manager: ['dashboard', 'projects', 'tasks', 'quotations', 'approvals', 'notifications', 'items'],
  technician: ['tasks', 'notifications'],
  accounts: ['dashboard', 'materials', 'returns', 'financial', 'accounts', 'reports', 'notifications', 'items', 'users'],
  storekeeper: ['materials', 'returns', 'notifications', 'items'],
  hr: ['employees', 'notifications'],
  secretariat: ['contracts', 'notifications'],
};

// ---------- مخزن الذاكرة للاختبار فقط (داخل العملية، بلا ملفات) ----------
let testStore = null; // { records: [...] } أو كائن بخدمات list/get/upsert/delete

function setTestStore(store) {
  if (!store) {
    testStore = { records: [] };
  } else if (Array.isArray(store)) {
    testStore = { records: store };
  } else if (Array.isArray(store.records)) {
    testStore = store;
  } else if (
    typeof store.listRecords === 'function' &&
    typeof store.upsertRecord === 'function'
  ) {
    testStore = store;
  } else {
    testStore = { records: [] };
  }
  return testStore;
}

function isTestMode() {
  if (testStore) return true;
  return process.env.MSHRY_TEST_MODE === '1';
}

function getTestStore() {
  if (!testStore) testStore = { records: [] };
  return testStore;
}

function isPostgresMode() {
  return Boolean(process.env.DATABASE_URL);
}

function getMode() {
  if (isPostgresMode()) return 'postgres';
  if (isTestMode()) return 'test';
  return 'none';
}

function getJwtSecret() {
  return process.env.JWT_SECRET || DEV_SECRET_FALLBACK;
}

function isJwtSecretConfigured() {
  return Boolean(process.env.JWT_SECRET);
}

// ---------- كلمات المرور: scrypt فقط ----------
// الصيغة المخزنة: scrypt$<saltHex>$<hashHex>
// المعاملات: N=16384, r=8, p=1, keylen=64.

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(pw), salt, 64, { N: 16384, r: 8, p: 1 });
  return 'scrypt$' + salt.toString('hex') + '$' + hash.toString('hex');
}

function verifyPassword(stored, supplied) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  try {
    const salt = Buffer.from(parts[1], 'hex');
    const expected = Buffer.from(parts[2], 'hex');
    if (!salt.length || expected.length !== 64) return false;
    const actual = crypto.scryptSync(String(supplied), salt, 64, { N: 16384, r: 8, p: 1 });
    if (actual.length !== expected.length) return false;
    return crypto.timingSafeEqual(actual, expected);
  } catch (e) {
    return false;
  }
}

// ---------- التوكن: JWT مبسّط بتوقيع HMAC-SHA256، بلا اعتماديات ----------
// الصيغة: base64url(header).base64url(payload).base64url(signature)
// الـ payload: { username, fullName, role, permissions, userId, companyId, rev, jti, exp }
// rev = رقم نسخة المستخدم لحظة إصدار التوكن؛ عند أي تعديل على المستخدم
// (رمز/دور/صلاحيات) يرتفع rev في سجله، فتُرفض توكناته القديمة في /api/data.

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function createToken(user, companyId) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadObj = {
    username: user.username,
    fullName: user.fullName || user.username,
    role: user.role || 'user',
    permissions: Array.isArray(user.permissions) ? user.permissions.slice() : [],
    userId: user.userId || user.id || user.username,
    companyId: companyId || DEFAULT_COMPANY_ID,
    rev: Number(user.rev) || 1,
    jti: crypto.randomBytes(12).toString('base64url'), // معرّف فريد لكل توكن
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60, // 7 أيام
  };
  const payload = base64url(JSON.stringify(payloadObj));
  const signature = crypto
    .createHmac('sha256', getJwtSecret())
    .update(header + '.' + payload)
    .digest('base64url');
  return header + '.' + payload + '.' + signature;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const header = parts[0];
  const payload = parts[1];
  const signature = parts[2];
  const expected = crypto
    .createHmac('sha256', getJwtSecret())
    .update(header + '.' + payload)
    .digest('base64url');
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
  if (!decoded || !decoded.username) return null;
  if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) return null;
  return decoded;
}

// ---------- أدوات HTTP المشتركة ----------

function setCors(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function sendJson(res, status, obj) {
  res.status(status).json(obj);
}

function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'string') {
    try {
      return JSON.parse(req.body);
    } catch (e) {
      return {};
    }
  }
  return req.body;
}

function getBearerToken(req) {
  const header = req.headers && (req.headers.authorization || req.headers.Authorization);
  if (!header || typeof header !== 'string') return null;
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

// يتحقق من التوكن ويعيد بياناته، أو يرسل 401 ويعيد null.
function requireAuth(req, res) {
  const token = getBearerToken(req);
  if (!token) {
    sendJson(res, 401, { error: 'يلزم تسجيل الدخول (لا يوجد توكن)' });
    return null;
  }
  const decoded = verifyToken(token);
  if (!decoded) {
    sendJson(res, 401, { error: 'التوكن غير صالح أو منتهي — سجّل الدخول مجدداً' });
    return null;
  }
  return decoded;
}

function isValidName(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_\-]{1,64}$/.test(value);
}

// ---------- طبقة التخزين ----------
// واجهة موحّدة يستخدمها auth.js و data.js.
// الخلفية الوحيدة في الإنتاج: Postgres. وفي الاختبار: مخزن ذاكرة.
// لا توجد أي خلفية ملفات. كل سجل: { company_id, collection, id, data, updated_at }

class NoDatabaseError extends Error {
  constructor() {
    super('NO_DATABASE_CONFIGURED');
    this.name = 'NoDatabaseError';
  }
}

function requireStore() {
  if (!isPostgresMode() && !isTestMode()) throw new NoDatabaseError();
}

// --- Postgres (يُستدعى فقط عند وجود DATABASE_URL؛ الاستدعاء كسول) ---
async function pgList(companyId, collection) {
  const { sql } = require('@vercel/postgres');
  const { rows } = await sql`
    SELECT id, data, updated_at FROM mshry_records
    WHERE company_id = ${companyId} AND collection = ${collection}
    ORDER BY updated_at DESC, id ASC`;
  return rows.map((r) => ({ id: r.id, data: r.data, updated_at: r.updated_at }));
}

async function pgGet(companyId, collection, id) {
  const { sql } = require('@vercel/postgres');
  const { rows } = await sql`
    SELECT id, data, updated_at FROM mshry_records
    WHERE company_id = ${companyId} AND collection = ${collection} AND id = ${id}`;
  if (!rows.length) return null;
  return { id: rows[0].id, data: rows[0].data, updated_at: rows[0].updated_at };
}

async function pgUpsert(companyId, collection, id, data) {
  const { sql } = require('@vercel/postgres');
  const { rows } = await sql`
    INSERT INTO mshry_records (company_id, collection, id, data, updated_at)
    VALUES (${companyId}, ${collection}, ${id}, ${JSON.stringify(data)}::jsonb, NOW())
    ON CONFLICT (company_id, collection, id)
    DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
    RETURNING id, data, updated_at`;
  return { id: rows[0].id, data: rows[0].data, updated_at: rows[0].updated_at };
}

async function pgDelete(companyId, collection, id) {
  const { sql } = require('@vercel/postgres');
  const { rowCount } = await sql`
    DELETE FROM mshry_records
    WHERE company_id = ${companyId} AND collection = ${collection} AND id = ${id}`;
  return rowCount > 0;
}

// --- مخزن الذاكرة للاختبار فقط ---
function memList(companyId, collection) {
  const store = getTestStore();
  if (typeof store.listRecords === 'function') return store.listRecords(companyId, collection);
  return store.records
    .filter((r) => r.company_id === companyId && r.collection === collection)
    .sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)))
    .map((r) => ({ id: r.id, data: r.data, updated_at: r.updated_at }));
}

function memGet(companyId, collection, id) {
  const store = getTestStore();
  if (typeof store.getRecord === 'function') return store.getRecord(companyId, collection, id);
  const found = store.records.find(
    (r) => r.company_id === companyId && r.collection === collection && r.id === id
  );
  return found ? { id: found.id, data: found.data, updated_at: found.updated_at } : null;
}

function memUpsert(companyId, collection, id, data) {
  const store = getTestStore();
  if (typeof store.upsertRecord === 'function') return store.upsertRecord(companyId, collection, id, data);
  const now = new Date().toISOString();
  const idx = store.records.findIndex(
    (r) => r.company_id === companyId && r.collection === collection && r.id === id
  );
  const row = { company_id: companyId, collection, id, data, updated_at: now };
  if (idx >= 0) store.records[idx] = row;
  else store.records.push(row);
  return { id, data, updated_at: now };
}

function memDelete(companyId, collection, id) {
  const store = getTestStore();
  if (typeof store.deleteRecord === 'function') return store.deleteRecord(companyId, collection, id);
  const before = store.records.length;
  store.records = store.records.filter(
    (r) => !(r.company_id === companyId && r.collection === collection && r.id === id)
  );
  return before !== store.records.length;
}

// --- واجهة موحّدة ---

async function listRecords(companyId, collection) {
  requireStore();
  if (isPostgresMode()) return pgList(companyId, collection);
  return memList(companyId, collection);
}

async function getRecord(companyId, collection, id) {
  requireStore();
  if (isPostgresMode()) return pgGet(companyId, collection, id);
  return memGet(companyId, collection, id);
}

async function upsertRecord(companyId, collection, id, data) {
  requireStore();
  if (isPostgresMode()) return pgUpsert(companyId, collection, id, data);
  return memUpsert(companyId, collection, id, data);
}

async function deleteRecord(companyId, collection, id) {
  requireStore();
  if (isPostgresMode()) return pgDelete(companyId, collection, id);
  return memDelete(companyId, collection, id);
}

// هل أُبطل هذا التوكن بتعديل على المستخدم بعد إصداره؟
// يُقارن rev في التوكن مع rev في سجل المستخدم الحالي؛ عند الاختلاف
// يكون التوكن مبطلاً (تغيّرت كلمة المرور أو الدور أو الصلاحيات).
// - لا سجل للمستخدم بعد → مبطل (فشل مغلق: مستخدم محذوف أو غير موجود
//   لا يجوز أن تبقى توكناته صالحة).
// - خطأ في قاعدة البيانات → مبطل (فشل مغلق) بدل الفتح عند الخطأ
//   في النسخة القديمة؛ فتعطّل القاعدة لا يفتح البيانات للجميع.
async function isTokenRevoked(decoded) {
  try {
    if (!decoded || !decoded.username) return true;
    const companyId = decoded.companyId || DEFAULT_COMPANY_ID;
    let row = await getRecord(companyId, 'users', decoded.username);
    if (!row) {
      const all = await listRecords(companyId, 'users');
      row = all.find((r) => r.data && r.data.username === decoded.username) || null;
    }
    if (!row || !row.data) return true;
    const storedRev = Number(row.data.rev) || 1;
    const tokenRev = Number(decoded.rev) || 1;
    return storedRev !== tokenRev;
  } catch (e) {
    return true;
  }
}

module.exports = {
  DEFAULT_COMPANY_ID,
  ADMIN_USERNAME,
  FULL_PERMS,
  ROLE_SCREENS,
  getMode,
  isPostgresMode,
  isTestMode,
  setTestStore,
  getJwtSecret,
  isJwtSecretConfigured,
  hashPassword,
  verifyPassword,
  createToken,
  verifyToken,
  isTokenRevoked,
  setCors,
  sendJson,
  parseBody,
  getBearerToken,
  requireAuth,
  isValidName,
  listRecords,
  getRecord,
  upsertRecord,
  deleteRecord,
  NoDatabaseError,
};
