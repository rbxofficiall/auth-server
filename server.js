'use strict';
// ---------------------------------------------------------------------------
//  Auth server — Render (Node.js) + Turso (cloud SQLite via HTTP API).
//  Zero npm dependencies: uses only node:http, node:crypto, node:fs.
//
//  Environment variables (set in Render dashboard):
//    PORT            — provided automatically by Render
//    ADMIN_TOKEN     — secret token for /api/admin/* and /admin panel
//    TURSO_URL       — https://<db-name>.turso.io  (from Turso dashboard)
//    TURSO_TOKEN     — Turso database auth token
//    RSA_PRIV_B64    — base64 of PKCS#8 DER private key  (generated once)
//    RSA_PUB_N_HEX   — 256-byte RSA modulus hex           (embed in client)
//    RSA_PUB_E_HEX   — RSA exponent hex (always 010001)
// ---------------------------------------------------------------------------
const http   = require('node:http');
const https  = require('node:https');
const fs     = require('node:fs');
const path   = require('node:path');
const crypto = require('node:crypto');

// ---- tiny .env loader (local dev only; Render uses dashboard env vars) ---
try {
  const lines = fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/);
  for (const l of lines) {
    const m = l.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
} catch (_) {}

const PORT        = Number(process.env.PORT || 3000);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change-this-admin-token';
const TURSO_URL   = (process.env.TURSO_URL   || '').replace(/\/$/, '');
const TURSO_TOKEN = process.env.TURSO_TOKEN  || '';

// ---- RSA-2048 keypair ---------------------------------------------------
// On first local run: keys are generated and printed — copy them to Render
// env vars. On Render they are read from env, nothing is written to disk.
let privKey;
function initKeys() {
  const privB64  = process.env.RSA_PRIV_B64;
  const pubNHex  = process.env.RSA_PUB_N_HEX;
  const pubEHex  = process.env.RSA_PUB_E_HEX;

  if (privB64 && pubNHex && pubEHex) {
    privKey = crypto.createPrivateKey({
      key: Buffer.from(privB64, 'base64'), format: 'der', type: 'pkcs8'
    });
    console.log('[keys] loaded RSA key from environment.');
    return;
  }

  // Local first-run: generate and print for copy-paste into Render.
  console.log('[keys] RSA env vars not set — generating new keypair...');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'spki',  format: 'jwk' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' }
  });
  const jwk    = publicKey;
  const modHex = Buffer.from(jwk.n, 'base64url').toString('hex');
  const expHex = Buffer.from(jwk.e, 'base64url').toString('hex');
  const privB64New = privateKey.toString('base64');

  privKey = crypto.createPrivateKey({
    key: privateKey, format: 'der', type: 'pkcs8'
  });

  console.log('\n========== COPY THESE TO RENDER ENV VARS ==========');
  console.log('RSA_PRIV_B64  =', privB64New);
  console.log('RSA_PUB_N_HEX =', modHex);
  console.log('RSA_PUB_E_HEX =', expHex);
  console.log('====================================================\n');
  console.log('[client] Put this in src/core/auth_pubkey.h:');
  console.log('  modulus hex:', modHex);
  console.log('  exponent hex:', expHex, '\n');
}
initKeys();

function sign(payloadBuf) {
  return crypto.sign('SHA256', payloadBuf, privKey);
}

// ---- password hashing ---------------------------------------------------
const SCRYPT_N = 1 << 14, SCRYPT_R = 8, SCRYPT_P = 1, SCRYPT_LEN = 32;
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, SCRYPT_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  return salt.toString('base64') + ':' + hash.toString('base64');
}
function verifyPassword(pw, stored) {
  const [s, h] = stored.split(':');
  if (!s || !h) return false;
  const want = Buffer.from(h, 'base64');
  const got  = crypto.scryptSync(pw, Buffer.from(s, 'base64'), SCRYPT_LEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P });
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}

// ---- Turso HTTP client --------------------------------------------------
// Turso exposes a simple HTTP API: POST /v2/pipeline with JSON.
// We send SQL statements and get rows back — no driver needed.
async function turso(statements) {
  if (!TURSO_URL || !TURSO_TOKEN) throw new Error('TURSO_URL/TURSO_TOKEN not set');
  const body = JSON.stringify({ requests: statements.map(s =>
    typeof s === 'string'
      ? { type: 'execute', stmt: { sql: s } }
      : { type: 'execute', stmt: { sql: s.sql, args: s.args.map(toTursoArg) } }
  )});
  const url = new URL('/v2/pipeline', TURSO_URL);
  return new Promise((resolve, reject) => {
    const req = https.request(url, {
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + TURSO_TOKEN,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    }, res => {
      let d = '';
      res.on('data', c => d += c);
      res.on('end', () => {
        try {
          const r = JSON.parse(d);
          // Return array of result objects, one per statement
          resolve(r.results || r);
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function toTursoArg(v) {
  if (v === null || v === undefined) return { type: 'null' };
  if (typeof v === 'number') return { type: Number.isInteger(v) ? 'integer' : 'float', value: String(v) };
  return { type: 'text', value: String(v) };
}

// Extract rows from a Turso result (index into the pipeline results array).
function rows(results, idx) {
  const r = results[idx];
  if (!r || r.type === 'error') return [];
  const cols = (r.response?.result?.cols || []).map(c => c.name);
  return (r.response?.result?.rows || []).map(row => {
    const obj = {};
    row.forEach((cell, i) => { obj[cols[i]] = cell?.value ?? null; });
    return obj;
  });
}
function firstRow(results, idx) { return rows(results, idx)[0] || null; }
function affected(results, idx) {
  return results[idx]?.response?.result?.affected_row_count ?? 0;
}

// ---- DB init (runs once at startup) ------------------------------------
async function initDb() {
  await turso([`
    CREATE TABLE IF NOT EXISTS users (
      id        INTEGER PRIMARY KEY AUTOINCREMENT,
      login     TEXT NOT NULL UNIQUE,
      pass      TEXT NOT NULL,
      hwid      TEXT,
      sub_until INTEGER NOT NULL DEFAULT 0,
      banned    INTEGER NOT NULL DEFAULT 0,
      created   INTEGER NOT NULL
    )
  `]);
  console.log('[db] Turso ready.');
}

// ---- auth helpers -------------------------------------------------------
const DAY = 86400;
const now = () => Math.floor(Date.now() / 1000);
function validLogin(s) { return /^[A-Za-z0-9_.\-]{3,32}$/.test(s || ''); }

async function verifyAuth(b) {
  const { login, password, hwid } = b;
  if (!validLogin(login) || typeof password !== 'string' || typeof hwid !== 'string')
    return { error: 'bad_request' };

  const res = await turso([{ sql: 'SELECT * FROM users WHERE login = ?', args: [login] }]);
  const u = firstRow(res, 0);
  if (!u) return { error: 'invalid_credentials' };
  if (!verifyPassword(password, u.pass)) return { error: 'invalid_credentials' };
  if (Number(u.banned)) return { error: 'banned' };

  if (!u.hwid) {
    await turso([{ sql: 'UPDATE users SET hwid = ? WHERE login = ?', args: [hwid, login] }]);
    u.hwid = hwid;
  }
  if (u.hwid !== hwid) return { error: 'device_mismatch' };
  if (Number(u.sub_until) <= now()) return { error: 'expired' };
  return { u };
}

// ---- HTTP helpers -------------------------------------------------------
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function sendSigned(res, obj) {
  const buf = Buffer.from(JSON.stringify(obj));
  const sig = sign(buf);
  send(res, 200, { payload: buf.toString('base64'), sig: sig.toString('base64') });
}
function readBody(req) {
  return new Promise(resolve => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 1 << 16) req.destroy(); });
    req.on('end', () => resolve(d));
    req.on('error', () => resolve(''));
  });
}
function isAdmin(req) { return req.headers['x-admin-token'] === ADMIN_TOKEN; }

// ---- routes -------------------------------------------------------------
const srv = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p   = url.pathname;
  try {
    if (req.method === 'GET' && p === '/api/health') return send(res, 200, { ok: true });

    // Web admin panel
    if (req.method === 'GET' && (p === '/admin' || p === '/admin/')) {
      const html = fs.readFileSync(path.join(__dirname, 'admin.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(html);
    }

    // ---- /api/auth -------------------------------------------------------
    if (req.method === 'POST' && p === '/api/auth') {
      const b = JSON.parse(await readBody(req) || '{}');
      const nonce = typeof b.nonce === 'string' ? b.nonce : '';
      const v = await verifyAuth(b);
      if (v.error) return sendSigned(res, { ok: false, error: v.error, nonce });
      const daysLeft = Math.max(0, Math.ceil((Number(v.u.sub_until) - now()) / DAY));
      return sendSigned(res, { ok: true, login: b.login, hwid: b.hwid,
                               until: Number(v.u.sub_until), daysLeft, nonce });
    }

    // ---- /api/dll --------------------------------------------------------
    // DLL is stored in server/files/d3dx9_43.dll.
    // On Render: upload it once via admin panel or scp; it persists on disk
    // between deploys as long as you don't clear the service.
    if (req.method === 'POST' && p === '/api/dll') {
      const b = JSON.parse(await readBody(req) || '{}');
      const v = await verifyAuth(b);
      if (v.error) return send(res, 403, { error: v.error });
      const dllPath = path.join(__dirname, 'files', 'd3dx9_43.dll');
      let data;
      try { data = fs.readFileSync(dllPath); }
      catch (_) { return send(res, 404, { error: 'no_dll' }); }
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': data.length });
      return res.end(data);
    }

    // ---- admin -----------------------------------------------------------
    if (p.startsWith('/api/admin/') && !isAdmin(req)) return send(res, 403, { error: 'forbidden' });

    if (req.method === 'POST' && p === '/api/admin/user') {
      const b = JSON.parse(await readBody(req) || '{}');
      if (!validLogin(b.login) || typeof b.password !== 'string' || Number(b.days) <= 0)
        return send(res, 400, { error: 'bad_request' });
      const until = now() + Math.floor(Number(b.days)) * DAY;
      try {
        await turso([{ sql: 'INSERT INTO users (login, pass, hwid, sub_until, banned, created) VALUES (?, ?, NULL, ?, 0, ?)',
                        args: [b.login, hashPassword(b.password), until, now()] }]);
      } catch (e) {
        if (String(e).includes('UNIQUE')) return send(res, 409, { error: 'exists' });
        throw e;
      }
      return send(res, 200, { ok: true, login: b.login, until });
    }

    if (req.method === 'POST' && p === '/api/admin/extend') {
      const b = JSON.parse(await readBody(req) || '{}');
      const res2 = await turso([{ sql: 'SELECT sub_until FROM users WHERE login = ?', args: [b.login] }]);
      const u = firstRow(res2, 0);
      if (!u) return send(res, 404, { error: 'not_found' });
      const base  = Math.max(Number(u.sub_until), now());
      const until = base + Math.floor(Number(b.days)) * DAY;
      await turso([{ sql: 'UPDATE users SET sub_until = ? WHERE login = ?', args: [until, b.login] }]);
      return send(res, 200, { ok: true, login: b.login, until });
    }

    if (req.method === 'POST' && p === '/api/admin/ban') {
      const b = JSON.parse(await readBody(req) || '{}');
      const r2 = await turso([{ sql: 'SELECT id FROM users WHERE login = ?', args: [b.login] }]);
      if (!firstRow(r2, 0)) return send(res, 404, { error: 'not_found' });
      await turso([{ sql: 'UPDATE users SET banned = ? WHERE login = ?', args: [b.banned ? 1 : 0, b.login] }]);
      return send(res, 200, { ok: true, login: b.login, banned: !!b.banned });
    }

    if (req.method === 'POST' && p === '/api/admin/reset-hwid') {
      const b = JSON.parse(await readBody(req) || '{}');
      const r2 = await turso([{ sql: 'SELECT id FROM users WHERE login = ?', args: [b.login] }]);
      if (!firstRow(r2, 0)) return send(res, 404, { error: 'not_found' });
      await turso([{ sql: 'UPDATE users SET hwid = NULL WHERE login = ?', args: [b.login] }]);
      return send(res, 200, { ok: true, login: b.login });
    }

    if (req.method === 'POST' && p === '/api/admin/delete') {
      const b = JSON.parse(await readBody(req) || '{}');
      await turso([{ sql: 'DELETE FROM users WHERE login = ?', args: [b.login] }]);
      return send(res, 200, { ok: true });
    }

    if (req.method === 'GET' && p === '/api/admin/list') {
      const r2 = await turso(['SELECT id, login, hwid, sub_until, banned, created FROM users ORDER BY id']);
      return send(res, 200, rows(r2, 0).map(u => ({
        id: Number(u.id), login: u.login, hwid: u.hwid,
        sub_until: Number(u.sub_until), banned: !!Number(u.banned), created: Number(u.created)
      })));
    }

    return send(res, 404, { error: 'not_found' });
  } catch (e) {
    console.error(e);
    send(res, 500, { error: 'server_error' });
  }
});

initDb().then(() => {
  srv.listen(PORT, '0.0.0.0', () => {
    console.log(`[auth-server] listening on http://0.0.0.0:${PORT}`);
    console.log(`[auth-server] admin token: ${ADMIN_TOKEN}`);
  });
}).catch(e => { console.error('[db] init failed:', e); process.exit(1); });
