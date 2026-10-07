'use strict';

const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');

const SESSION_DAYS = 14;
const MAX_BODY = 2 * 1024 * 1024;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const attempts = new Map();

let sql;
let schemaPromise;

function database() {
  if (!sql) {
    if (!process.env.DATABASE_URL) {
      throw new Error('DATABASE_URL is not configured.');
    }
    sql = neon(process.env.DATABASE_URL);
  }
  if (!schemaPromise) {
    schemaPromise = sql.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        state JSONB,
        state_updated_at TIMESTAMPTZ
      )
    `).catch((error) => {
      schemaPromise = undefined;
      throw error;
    });
  }
  return schemaPromise.then(() => sql);
}

function send(res, status, data) {
  const body = JSON.stringify(data);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(body);
}

function readBody(req) {
  if (req.body !== undefined) {
    try {
      const body = typeof req.body === 'string' || Buffer.isBuffer(req.body)
        ? JSON.parse(req.body.toString())
        : req.body;
      if (!body || typeof body !== 'object' || Array.isArray(body)) {
        return Promise.reject({ status: 400, message: 'Invalid JSON' });
      }
      if (Buffer.byteLength(JSON.stringify(body)) > MAX_BODY) {
        return Promise.reject({ status: 413, message: 'Request too large' });
      }
      return Promise.resolve(body);
    } catch (error) {
      return Promise.reject(error.status ? error : { status: 400, message: 'Invalid JSON' });
    }
  }

  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject({ status: 413, message: 'Request too large' });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
          reject({ status: 400, message: 'Invalid JSON' });
          return;
        }
        resolve(body);
      } catch {
        reject({ status: 400, message: 'Invalid JSON' });
      }
    });
    req.on('error', () => reject({ status: 400, message: 'Bad request' }));
  });
}

function parseCookies(header) {
  const cookies = {};
  for (const part of (header || '').split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    try {
      cookies[part.slice(0, index).trim()] = decodeURIComponent(part.slice(index + 1).trim());
    } catch {
      continue;
    }
  }
  return cookies;
}

function sessionSecret() {
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
    throw new Error('SESSION_SECRET must be configured with at least 32 characters.');
  }
  return process.env.SESSION_SECRET;
}

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', sessionSecret()).update(body).digest('base64url');
  return body + '.' + signature;
}

function unsign(token) {
  if (typeof token !== 'string') return null;
  const [body, signature] = token.split('.');
  if (!body || !signature) return null;
  const expected = crypto.createHmac('sha256', sessionSecret()).update(body).digest('base64url');
  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(actualBuffer, expectedBuffer)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    return payload.exp > Date.now() && typeof payload.uid === 'string' ? payload : null;
  } catch {
    return null;
  }
}

function setSession(res, userId) {
  const token = sign({ uid: userId, exp: Date.now() + SESSION_DAYS * 86400000 });
  res.setHeader('Set-Cookie', 'lf_session=' + encodeURIComponent(token) + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + SESSION_DAYS * 86400 + '; Secure');
}

function clearSession(res) {
  res.setHeader('Set-Cookie', 'lf_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0; Secure');
}

function limited(ip) {
  const now = Date.now();
  const record = attempts.get(ip) || { count: 0, reset: now + 15 * 60000 };
  if (now > record.reset) {
    record.count = 0;
    record.reset = now + 15 * 60000;
  }
  record.count++;
  attempts.set(ip, record);
  return record.count > 20;
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    createdAt: new Date(user.created_at).toISOString()
  };
}

function userFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    salt: row.password_salt,
    hash: row.password_hash,
    created_at: row.created_at,
    state: row.state,
    stateUpdatedAt: row.state_updated_at
  };
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return {
    salt,
    hash: crypto.scryptSync(password, salt, 64).toString('hex')
  };
}

function verifyPassword(password, salt, hash) {
  const actual = Buffer.from(crypto.scryptSync(password, salt, 64).toString('hex'));
  const expected = Buffer.from(hash);
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function getClientIp(req) {
  const forwardedFor = req.headers['x-forwarded-for'];
  return (typeof forwardedFor === 'string' && forwardedFor.split(',')[0].trim())
    || req.socket?.remoteAddress
    || 'unknown';
}

async function handleApi(req, res, pathname) {
  const ip = getClientIp(req);

  if (pathname === '/api/logout' && req.method === 'POST') {
    clearSession(res);
    return send(res, 200, { ok: true });
  }

  if (pathname === '/api/register' && req.method === 'POST') {
    if (limited(ip)) return send(res, 429, { error: 'Too many attempts. Try again in a few minutes.' });
    const body = await readBody(req);
    const name = String(body.name || '').trim().slice(0, 60);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!name) return send(res, 400, { error: 'Please enter your name.' });
    if (!EMAIL_RE.test(email)) return send(res, 400, { error: 'Please enter a valid email address.' });
    if (password.length < 8) return send(res, 400, { error: 'Password must be at least 8 characters.' });
    if (password.length > 200) return send(res, 400, { error: 'Password is too long.' });

    const { salt, hash } = hashPassword(password);
    const id = crypto.randomUUID();
    const sqlClient = await database();
    let rows;
    try {
      rows = await sqlClient.query(
        'INSERT INTO users (id, name, email, password_salt, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, created_at',
        [id, name, email, salt, hash]
      );
    } catch (error) {
      if (error.code === '23505') return send(res, 409, { error: 'An account with this email already exists.' });
      throw error;
    }
    setSession(res, id);
    return send(res, 201, { user: publicUser(rows[0]) });
  }

  if (pathname === '/api/login' && req.method === 'POST') {
    if (limited(ip)) return send(res, 429, { error: 'Too many attempts. Try again in a few minutes.' });
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const sqlClient = await database();
    const rows = await sqlClient.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email]);
    const user = userFromRow(rows[0]);
    const valid = user ? verifyPassword(password, user.salt, user.hash) : (hashPassword(password), false);
    if (!valid) return send(res, 401, { error: 'Incorrect email or password.' });
    setSession(res, user.id);
    return send(res, 200, { user: publicUser(user) });
  }

  const payload = unsign(parseCookies(req.headers.cookie).lf_session);
  if (!payload) return send(res, 401, { error: 'Not signed in.' });
  const sqlClient = await database();
  const rows = await sqlClient.query('SELECT * FROM users WHERE id = $1 LIMIT 1', [payload.uid]);
  const user = userFromRow(rows[0]);
  if (!user) return send(res, 401, { error: 'Not signed in.' });

  if (pathname === '/api/me' && req.method === 'GET') {
    return send(res, 200, { user: publicUser(user) });
  }

  if (pathname === '/api/state' && req.method === 'GET') {
    return send(res, 200, {
      state: user.state,
      updatedAt: user.state_updated_at ? new Date(user.state_updated_at).toISOString() : null
    });
  }

  if (pathname === '/api/state' && req.method === 'PUT') {
    const body = await readBody(req);
    if (!body.state || typeof body.state !== 'object' || Array.isArray(body.state)) {
      return send(res, 400, { error: 'Invalid state.' });
    }
    const updatedAt = new Date();
    await sqlClient.query(
      'UPDATE users SET state = $1::jsonb, state_updated_at = $2 WHERE id = $3',
      [JSON.stringify(body.state), updatedAt.toISOString(), user.id]
    );
    return send(res, 200, { ok: true, updatedAt: updatedAt.toISOString() });
  }

  if (pathname === '/api/account' && req.method === 'DELETE') {
    const body = await readBody(req);
    if (!verifyPassword(String(body.password || ''), user.salt, user.hash)) {
      return send(res, 401, { error: 'Incorrect password.' });
    }
    await sqlClient.query('DELETE FROM users WHERE id = $1', [user.id]);
    clearSession(res);
    return send(res, 200, { ok: true });
  }

  return send(res, 404, { error: 'Not found.' });
}

module.exports = async function handler(req, res) {
  try {
    const pathname = decodeURIComponent(new URL(req.url, 'https://' + (req.headers.host || 'localhost')).pathname);
    if (!pathname.startsWith('/api/')) return send(res, 404, { error: 'Not found.' });

    if (req.method !== 'GET') {
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== req.headers.host) {
        return send(res, 403, { error: 'Cross-origin request blocked.' });
      }
    }

    await handleApi(req, res, pathname);
  } catch (error) {
    if (error && error.status) return send(res, error.status, { error: error.message });
    console.error('LearnFlow API error:', error);
    send(res, 500, { error: 'Server error.' });
  }
};
