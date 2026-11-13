'use strict';
/** Password hashing, password policy, sessions, 2FA tickets and rate limiters. */
const crypto = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

/* ---------- password hashing (scrypt, per-user random salt) ---------- */
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const dk = await scrypt(pw.normalize('NFKC'), salt, 64, SCRYPT);
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), dk.toString('base64')].join('$');
}

async function verifyPassword(pw, stored) {
  try {
    const [alg, N, r, p, saltB64, hashB64] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hashB64, 'base64');
    const dk = await scrypt(pw.normalize('NFKC'), Buffer.from(saltB64, 'base64'), expected.length,
      { N: +N, r: +r, p: +p, maxmem: 64 * 1024 * 1024 });
    return crypto.timingSafeEqual(dk, expected);
  } catch { return false; }
}

// Used for unknown usernames so that response time does not reveal whether a user exists.
let DUMMY_HASH = null;
hashPassword(crypto.randomBytes(12).toString('hex')).then((h) => { DUMMY_HASH = h; });
const dummyHash = () => DUMMY_HASH || 'scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA==$' + 'A'.repeat(86) + '==';

/* ---------- password policy ---------- */
const COMMON = new Set(('password,passw0rd,123456789,1234567890,12345678910,qwertyuiop,qwertzuiop,iloveyou,letmein,' +
  'welcome,admin,administrator,dragon,monkey,football,baseball,master,sunshine,shadow,princess,abc123,' +
  'jelszo,jelszo123,szia,almafa,kismacska,macska,magyarorszag,budapest,trustno1,superman,batman,' +
  'changeme,whatever,starwars,freedom,computer,internet,asdfghjkl,zxcvbnm,mustang,michael,jessica').split(','));

function checkPassword(pw, username) {
  if (typeof pw !== 'string') return 'pw_invalid';
  if (pw.length < 10) return 'pw_short';
  if (pw.length > 128) return 'pw_long';
  const low = pw.toLowerCase();
  const stripped = low.replace(/[^a-z]+$/g, '').replace(/^[^a-z]+/g, '');
  if (COMMON.has(low) || COMMON.has(stripped)) return 'pw_common';
  if (username && username.length >= 3 && low.includes(username)) return 'pw_user';
  if (new Set(pw).size < 5) return 'pw_weak';
  return null;
}

/* ---------- sessions (in memory, only a SHA-256 of the id is kept) ---------- */
const IDLE_MS = 30 * 60 * 1000;
const ABS_MS = 8 * 60 * 60 * 1000;
const sessions = new Map();
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

function createSession(user) {
  const id = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(24).toString('base64url');
  const now = Date.now();
  sessions.set(sha(id), { user, csrf, created: now, last: now, pending2fa: null });
  return { id, csrf };
}

function getSession(id) {
  if (typeof id !== 'string' || id.length < 20 || id.length > 100) return null;
  const h = sha(id);
  const s = sessions.get(h);
  if (!s) return null;
  const now = Date.now();
  if (now - s.last > IDLE_MS || now - s.created > ABS_MS) { sessions.delete(h); return null; }
  s.last = now;
  s.hash = h;
  return s;
}

const destroySession = (id) => { if (id) sessions.delete(sha(id)); };

function destroyUserSessions(user, exceptHash) {
  for (const [h, s] of sessions) if (s.user === user && h !== exceptHash) sessions.delete(h);
}
const countUserSessions = (user) => { let n = 0; for (const s of sessions.values()) if (s.user === user) n++; return n; };

/* ---------- 2FA login tickets ---------- */
const tickets = new Map();
function createTicket(user) {
  const id = crypto.randomBytes(24).toString('base64url');
  tickets.set(id, { user, exp: Date.now() + 5 * 60 * 1000, tries: 0 });
  return id;
}
function getTicket(id) {
  const t = typeof id === 'string' ? tickets.get(id) : null;
  if (!t) return null;
  if (t.exp < Date.now()) { tickets.delete(id); return null; }
  return t;
}
const dropTicket = (id) => tickets.delete(id);

/* ---------- sliding-window rate limiter ---------- */
function limiter(max, windowMs) {
  const m = new Map();
  const prune = (a, now) => { while (a.length && a[0] <= now - windowMs) a.shift(); };
  return {
    /** seconds until allowed again, or 0 when not blocked */
    blocked(key) {
      const a = m.get(key);
      if (!a) return 0;
      const now = Date.now();
      prune(a, now);
      return a.length >= max ? Math.ceil((a[0] + windowMs - now) / 1000) : 0;
    },
    add(key) {
      const now = Date.now();
      const a = m.get(key) || [];
      prune(a, now);
      a.push(now);
      m.set(key, a);
    },
    reset(key) { m.delete(key); },
    sweep() {
      const now = Date.now();
      for (const [k, a] of m) { prune(a, now); if (!a.length) m.delete(k); }
    },
  };
}

const limits = {
  loginIp: limiter(30, 15 * 60 * 1000),    // failed logins per IP
  loginUser: limiter(5, 15 * 60 * 1000),   // failed logins per IP + username
  loginName: limiter(50, 15 * 60 * 1000),  // failed logins per username, any IP
  register: limiter(10, 60 * 60 * 1000),   // registrations per IP
  twofa: limiter(10, 15 * 60 * 1000),      // wrong 2FA codes per IP
  reauth: limiter(8, 15 * 60 * 1000),      // wrong re-auth attempts per user
  requests: limiter(600, 60 * 1000),       // all requests per IP
};

setInterval(() => {
  const now = Date.now();
  for (const [h, s] of sessions) if (now - s.last > IDLE_MS || now - s.created > ABS_MS) sessions.delete(h);
  for (const [id, t] of tickets) if (t.exp < now) tickets.delete(id);
  for (const l of Object.values(limits)) l.sweep();
}, 60 * 1000).unref();

const safeEqual = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

module.exports = {
  hashPassword, verifyPassword, dummyHash, checkPassword,
  createSession, getSession, destroySession, destroyUserSessions, countUserSessions,
  createTicket, getTicket, dropTicket, limits, safeEqual,
};
