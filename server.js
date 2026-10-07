'use strict';
/**
 * LearnFlow backend - zero dependencies, Node 18+.
 *   node server.js   ->   http://localhost:3000
 *
 * - Passwords hashed with scrypt + per-user salt
 * - Sessions: HMAC-signed token in an HttpOnly, SameSite=Lax cookie
 * - Storage: data/db.json (atomic writes); one saved "state" blob per user
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const SECRET_FILE = path.join(DATA_DIR, 'secret.key');
const SESSION_DAYS = 14;
const MAX_BODY = 2 * 1024 * 1024; // 2 MB

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- secret ----------
let SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  if (fs.existsSync(SECRET_FILE)) SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
  else { SECRET = crypto.randomBytes(48).toString('hex'); fs.writeFileSync(SECRET_FILE, SECRET, { mode: 0o600 }); }
}

// ---------- tiny JSON database ----------
let db = { users: {}, nextId: 1 };
if (fs.existsSync(DB_FILE)) {
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (e) { console.error('db.json is corrupt, refusing to start:', e.message); process.exit(1); }
}
let writing = false, dirty = false;
function persist() {
  dirty = true;
  if (writing) return;
  writing = true; dirty = false;
  const tmp = DB_FILE + '.tmp';
  fs.writeFile(tmp, JSON.stringify(db), (err) => {
    if (!err) fs.rename(tmp, DB_FILE, () => done()); else { console.error('Save failed:', err); done(); }
  });
  function done() { writing = false; if (dirty) persist(); }
}
function findByEmail(email) {
  return Object.values(db.users).find((u) => u.email === email);
}

// ---------- crypto helpers ----------
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const a = Buffer.from(crypto.scryptSync(password, salt, 64).toString('hex'));
  const b = Buffer.from(hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return body + '.' + sig;
}
function unsign(token) {
  if (typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    return payload.exp > Date.now() ? payload : null;
  } catch (e) { return null; }
}

// ---------- http helpers ----------
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setSession(res, userId) {
  const token = sign({ uid: userId, exp: Date.now() + SESSION_DAYS * 86400000 });
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', 'lf_session=' + encodeURIComponent(token) + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + SESSION_DAYS * 86400 + secure);
}
function clearSession(res) {
  res.setHeader('Set-Cookie', 'lf_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}
function currentUser(req) {
  const payload = unsign(parseCookies(req).lf_session);
  return payload ? db.users[payload.uid] || null : null;
}
function send(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject({ status: 413, message: 'Request too large' }); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {}); }
      catch (e) { reject({ status: 400, message: 'Invalid JSON' }); }
    });
    req.on('error', () => reject({ status: 400, message: 'Bad request' }));
  });
}
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, createdAt: u.createdAt });

// simple in-memory rate limit for auth endpoints (per IP)
const attempts = new Map();
function limited(ip) {
  const now = Date.now(), rec = attempts.get(ip) || { n: 0, reset: now + 15 * 60000 };
  if (now > rec.reset) { rec.n = 0; rec.reset = now + 15 * 60000; }
  rec.n++; attempts.set(ip, rec);
  return rec.n > 20;
}
setInterval(() => { const now = Date.now(); attempts.forEach((v, k) => { if (now > v.reset) attempts.delete(k); }); }, 60000).unref();

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// ---------- API ----------
async function handleApi(req, res, pathname) {
  const ip = req.socket.remoteAddress || 'unknown';

  if (pathname === '/api/register' && req.method === 'POST') {
    if (limited(ip)) return send(res, 429, { error: 'Too many attempts. Try again in a few minutes.' });
    const b = await readJson(req);
    const name = String(b.name || '').trim().slice(0, 60);
    const email = String(b.email || '').trim().toLowerCase();
    const password = String(b.password || '');
    if (!name) return send(res, 400, { error: 'Please enter your name.' });
    if (!EMAIL_RE.test(email)) return send(res, 400, { error: 'Please enter a valid email address.' });
    if (password.length < 8) return send(res, 400, { error: 'Password must be at least 8 characters.' });
    if (password.length > 200) return send(res, 400, { error: 'Password is too long.' });
    if (findByEmail(email)) return send(res, 409, { error: 'An account with this email already exists.' });
    const { salt, hash } = hashPassword(password);
    const id = String(db.nextId++);
    db.users[id] = { id, name, email, salt, hash, createdAt: new Date().toISOString(), state: null, stateUpdatedAt: null };
    persist();
    setSession(res, id);
    return send(res, 201, { user: publicUser(db.users[id]) });
  }

  if (pathname === '/api/login' && req.method === 'POST') {
    if (limited(ip)) return send(res, 429, { error: 'Too many attempts. Try again in a few minutes.' });
    const b = await readJson(req);
    const email = String(b.email || '').trim().toLowerCase();
    const password = String(b.password || '');
    const user = findByEmail(email);
    // run a hash even when the user is missing to keep timing similar
    const ok = user ? verifyPassword(password, user.salt, user.hash) : (hashPassword(password), false);
    if (!ok) return send(res, 401, { error: 'Incorrect email or password.' });
    setSession(res, user.id);
    return send(res, 200, { user: publicUser(user) });
  }

  if (pathname === '/api/logout' && req.method === 'POST') {
    clearSession(res);
    return send(res, 200, { ok: true });
  }

  // everything below needs a session
  const user = currentUser(req);
  if (!user) return send(res, 401, { error: 'Not signed in.' });

  if (pathname === '/api/me' && req.method === 'GET') return send(res, 200, { user: publicUser(user) });

  if (pathname === '/api/state' && req.method === 'GET') {
    return send(res, 200, { state: user.state, updatedAt: user.stateUpdatedAt });
  }
  if (pathname === '/api/state' && req.method === 'PUT') {
    const b = await readJson(req);
    if (!b || typeof b.state !== 'object' || b.state === null || Array.isArray(b.state)) return send(res, 400, { error: 'Invalid state.' });
    user.state = b.state;
    user.stateUpdatedAt = new Date().toISOString();
    persist();
    return send(res, 200, { ok: true, updatedAt: user.stateUpdatedAt });
  }

  if (pathname === '/api/account' && req.method === 'DELETE') {
    const b = await readJson(req);
    if (!verifyPassword(String(b.password || ''), user.salt, user.hash)) return send(res, 401, { error: 'Incorrect password.' });
    delete db.users[user.id];
    persist(); clearSession(res);
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: 'Not found.' });
}

// ---------- static files ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
function serveStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  const user = currentUser(req);
  if (pathname === '/' || pathname === '/index.html') {
    if (!user) { res.writeHead(302, { Location: '/login' }); return res.end(); }
    pathname = '/index.html';
  } else if (pathname === '/login' || pathname === '/login.html') {
    if (user) { res.writeHead(302, { Location: '/' }); return res.end(); }
    pathname = '/login.html';
  }
  const file = path.normalize(path.join(PUBLIC_DIR, pathname));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' });
    res.end(req.method === 'HEAD' ? undefined : buf);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const pathname = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (pathname.startsWith('/api/')) {
      // CSRF defence: state-changing requests must be same-origin JSON
      if (req.method !== 'GET') {
        const origin = req.headers.origin;
        if (origin && new URL(origin).host !== req.headers.host) return send(res, 403, { error: 'Cross-origin request blocked.' });
      }
      return await handleApi(req, res, pathname);
    }
    serveStatic(req, res, pathname);
  } catch (e) {
    if (e && e.status) return send(res, e.status, { error: e.message });
    console.error(e);
    send(res, 500, { error: 'Server error.' });
  }
});
server.listen(PORT, () => console.log('LearnFlow running at http://localhost:' + PORT));
process.on('SIGINT', () => { if (!writing) fs.writeFileSync(DB_FILE, JSON.stringify(db)); process.exit(0); });
