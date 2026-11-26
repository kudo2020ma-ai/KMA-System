// مكتبة مشتركة لدوال KMA: التوكن (HMAC) + طبقة التخزين.
// وضعان:
//  1) الإنتاج (Vercel): عند وجود DATABASE_URL تُستخدم Vercel Postgres.
//  2) التطوير المحلي: عند غياب DATABASE_URL يُستخدم ملف JSON محلي.
//     ⚠️ المخزن المحلي للتطوير والاختبار فقط — ليس للإنتاج ولا يُزامَن
//     بين الأجهزة، وبياناته تبقى على جهاز واحد فقط.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DEV_SECRET_FALLBACK = 'dev-only-change-me-NOT-FOR-PRODUCTION';
const DEFAULT_COMPANY_ID = 'kma-default';

function isPostgresMode() {
  return Boolean(process.env.DATABASE_URL);
}

function getMode() {
  return isPostgresMode() ? 'postgres' : 'local-json';
}

function getJwtSecret() {
  return process.env.JWT_SECRET || DEV_SECRET_FALLBACK;
}

function isJwtSecretConfigured() {
  return Boolean(process.env.JWT_SECRET);
}

// ---------- التوكن: JWT مبسّط بتوقيع HMAC-SHA256، بلا اعتماديات ----------
// الصيغة: base64url(header).base64url(payload).base64url(signature)
// الـ payload: { username, fullName, role, companyId, exp }

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function createToken(user, companyId) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadObj = {
    username: user.username,
    fullName: user.fullName || user.username,
    role: user.role || 'user',
    companyId: companyId || DEFAULT_COMPANY_ID,
    jti: crypto.randomBytes(12).toString('base64url'), // معرّف فريد لكل توكن
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60, // 7 أيام
  };
  const payload = base64url(JSON.stringify(payloadObj));
  const signature = crypto
    .createHmac('sha256', getJwtSecret())
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${signature}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header, payload, signature] = parts;
  const expected = crypto
    .createHmac('sha256', getJwtSecret())
    .update(`${header}.${payload}`)
    .digest('base64url');
  const sigBuf = Buffer.from(signature);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length) return null;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  let decoded;
  try {
    decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!decoded || !decoded.username) return null;
  if (decoded.exp && decoded.exp < Math.floor(Date.now() / 1000)) return null;
  return decoded;
}

// ---------- أدوات HTTP المشتركة ----------

function setCors(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
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
    } catch {
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
// واجهة موحّدة يستخدمها auth.js و data.js، سواء كان الخلفية Postgres
// أو ملف JSON المحلي. كل سجل: { company_id, collection, id, data, updated_at }

function localDbPath() {
  if (process.env.KMA_LOCAL_DB_PATH) return process.env.KMA_LOCAL_DB_PATH;
  // بجانب مجلد api/ — أي في جذر المشروع: data/kma-local.json
  return path.join(__dirname, '..', 'data', 'kma-local.json');
}

function readLocalDb() {
  const file = localDbPath();
  try {
    const raw = fs.readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed && Array.isArray(parsed.records)) return parsed.records;
    return [];
  } catch {
    return [];
  }
}

function writeLocalDb(records) {
  const file = localDbPath();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ records }, null, 2), 'utf8');
}

// --- Postgres (يُستدعى فقط عند وجود DATABASE_URL) ---
async function pgList(companyId, collection) {
  const { sql } = require('@vercel/postgres');
  const { rows } = await sql`
    SELECT id, data, updated_at FROM kma_records
    WHERE company_id = ${companyId} AND collection = ${collection}
    ORDER BY updated_at DESC, id ASC`;
  return rows.map((r) => ({ id: r.id, data: r.data, updated_at: r.updated_at }));
}

async function pgGet(companyId, collection, id) {
  const { sql } = require('@vercel/postgres');
  const { rows } = await sql`
    SELECT id, data, updated_at FROM kma_records
    WHERE company_id = ${companyId} AND collection = ${collection} AND id = ${id}`;
  if (!rows.length) return null;
  return { id: rows[0].id, data: rows[0].data, updated_at: rows[0].updated_at };
}

async function pgUpsert(companyId, collection, id, data) {
  const { sql } = require('@vercel/postgres');
  const { rows } = await sql`
    INSERT INTO kma_records (company_id, collection, id, data, updated_at)
    VALUES (${companyId}, ${collection}, ${id}, ${JSON.stringify(data)}::jsonb, NOW())
    ON CONFLICT (company_id, collection, id)
    DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
    RETURNING id, data, updated_at`;
  return { id: rows[0].id, data: rows[0].data, updated_at: rows[0].updated_at };
}

async function pgDelete(companyId, collection, id) {
  const { sql } = require('@vercel/postgres');
  const { rowCount } = await sql`
    DELETE FROM kma_records
    WHERE company_id = ${companyId} AND collection = ${collection} AND id = ${id}`;
  return rowCount > 0;
}

// --- واجهة موحّدة ---

async function listRecords(companyId, collection) {
  if (isPostgresMode()) return pgList(companyId, collection);
  return readLocalDb()
    .filter((r) => r.company_id === companyId && r.collection === collection)
    .sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)))
    .map((r) => ({ id: r.id, data: r.data, updated_at: r.updated_at }));
}

async function getRecord(companyId, collection, id) {
  if (isPostgresMode()) return pgGet(companyId, collection, id);
  const found = readLocalDb().find(
    (r) => r.company_id === companyId && r.collection === collection && r.id === id
  );
  return found ? { id: found.id, data: found.data, updated_at: found.updated_at } : null;
}

async function upsertRecord(companyId, collection, id, data) {
  if (isPostgresMode()) return pgUpsert(companyId, collection, id, data);
  const records = readLocalDb();
  const now = new Date().toISOString();
  const idx = records.findIndex(
    (r) => r.company_id === companyId && r.collection === collection && r.id === id
  );
  const row = { company_id: companyId, collection, id, data, updated_at: now };
  if (idx >= 0) records[idx] = row;
  else records.push(row);
  writeLocalDb(records);
  return { id, data, updated_at: now };
}

async function deleteRecord(companyId, collection, id) {
  if (isPostgresMode()) return pgDelete(companyId, collection, id);
  const records = readLocalDb();
  const kept = records.filter(
    (r) => !(r.company_id === companyId && r.collection === collection && r.id === id)
  );
  const removed = kept.length !== records.length;
  if (removed) writeLocalDb(kept);
  return removed;
}

module.exports = {
  DEFAULT_COMPANY_ID,
  getMode,
  isPostgresMode,
  getJwtSecret,
  isJwtSecretConfigured,
  createToken,
  verifyToken,
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
  localDbPath,
};
