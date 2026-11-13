'use strict';
/**
 * Bullshit Analysis - secure multi-page site. Zero dependencies (Node >= 18).
 *
 *   npm run cert    (optional) create a self-signed HTTPS certificate
 *   npm start       start the server
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const store = require('./store');
const auth = require('./auth');
const totp = require('./totp');

/* ------------------------------------------------------------------ config */
const ROOT = __dirname;
const CERT_DIR = process.env.CERT_DIR || path.join(ROOT, 'certs');
const KEY_FILE = path.join(CERT_DIR, 'key.pem');
const CERT_FILE = path.join(CERT_DIR, 'cert.pem');
const TLS = fs.existsSync(KEY_FILE) && fs.existsSync(CERT_FILE);
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT) || (TLS ? 8443 : 3000);
const SECURE_COOKIES = TLS || process.env.COOKIE_SECURE === '1';
const COOKIE = SECURE_COOKIES ? '__Host-sid' : 'sid';
const ALLOW_REGISTRATION = process.env.ALLOW_REGISTRATION !== 'false';
const MAX_USERS = Number(process.env.MAX_USERS) || 500;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const LOOPBACK = ['127.0.0.1', '::1', 'localhost'];

if (!LOOPBACK.includes(HOST) && !TLS && process.env.ALLOW_INSECURE !== '1' && process.env.COOKIE_SECURE !== '1') {
  console.error('Refusing to listen on a non-loopback address without HTTPS.\n' +
    'Run "npm run cert" first, or put the server behind a TLS reverse proxy (COOKIE_SECURE=1).');
  process.exit(1);
}

/* -------------------------------------------------------------- allowed hosts
   Blocks DNS-rebinding: only these Host headers are served. */
const ALLOWED_HOSTS = new Set();
for (const n of ['localhost', '127.0.0.1', '[::1]', ...(process.env.ALLOWED_HOSTS || '').split(',').map((s) => s.trim()).filter(Boolean)]) {
  ALLOWED_HOSTS.add(`${n}:${PORT}`.toLowerCase());
  ALLOWED_HOSTS.add(n.toLowerCase());
}
const isLocalHost = (h) => /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i.test(h || '');

/* ------------------------------------------------------------------- i18n */
const LANGS = ['hu', 'en'];
const DICT = {};
for (const l of LANGS) DICT[l] = JSON.parse(fs.readFileSync(path.join(ROOT, `${l}.json`), 'utf8'));

const PAGES = {
  '/': 'home', '/frankfurt': 'frankfurt', '/types': 'types', '/detector': 'detector',
  '/quiz': 'quiz', '/workplace': 'workplace', '/defense': 'defense', '/account': 'account',
};
const NAV = ['home', 'frankfurt', 'types', 'detector', 'quiz', 'workplace', 'defense'];

// Only these files are ever served as static assets (explicit allowlist).
const ASSETS = {
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/login.js': ['login.js', 'text/javascript; charset=utf-8'],
  '/theme.js': ['theme.js', 'text/javascript; charset=utf-8'],
  '/favicon.svg': ['favicon.svg', 'image/svg+xml'],
};

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const readFile = (f) => fs.readFileSync(path.join(ROOT, f), 'utf8');

function getLang(req, cookies) {
  if (LANGS.includes(cookies.lang)) return cookies.lang;
  const first = String(req.headers['accept-language'] || '').split(',')[0].trim().toLowerCase();
  return first.startsWith('hu') ? 'hu' : 'en';
}

function render(page, lang, sess) {
  const dict = DICT[lang];
  const isPublic = page === 'login';
  const nav = isPublic ? '' : NAV.map((k) =>
    `<a href="${k === 'home' ? '/' : '/' + k}"${k === page ? ' aria-current="page"' : ''}>${esc(dict['nav.' + k])}</a>`).join('');
  const account = isPublic || !sess ? '' :
    `<a class="avatar" href="/account" aria-label="${esc(dict['nav.account'])}"${page === 'account' ? ' aria-current="page"' : ''}>${esc(sess.user.charAt(0).toUpperCase())}</a>` +
    `<button class="icon-btn" id="logout-btn" type="button" aria-label="${esc(dict.logout)}" title="${esc(dict.logout)}"><svg class="ic" viewBox="0 0 24 24" aria-hidden="true"><use href="#i-logout"/></svg></button>`;
  const vars = {
    lang, page,
    title: esc(dict['title.' + page]),
    nav, account,
    csrf: sess ? sess.csrf : '',
    user: sess ? esc(sess.user) : '',
    bodyclass: isPublic ? 'auth' : 'app',
    extra: isPublic ? '<script src="/login.js" defer></script>' : '',
    dict: JSON.stringify(dict).replace(/</g, '\\u003c'),
  };
  const html = readFile('layout.html').replace('{{@content}}', () => readFile(page + '.html'));
  return html.replace(/\{\{(?:(t|h):([\w.-]+)|@(\w+))\}\}/g, (m, kind, key, varName) => {
    if (varName) return varName in vars ? vars[varName] : '';
    const v = dict[key];
    if (v === undefined) { console.warn(`missing i18n key "${key}" (${lang})`); return esc(key); }
    return kind === 'h' ? v : esc(v);
  });
}

/* ---------------------------------------------------------------- helpers */
function securityHeaders(host) {
  const h = {
    'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; " +
      "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'" +
      (SECURE_COOKIES ? '; upgrade-insecure-requests' : ''),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
    'X-DNS-Prefetch-Control': 'off',
  };
  // HSTS is skipped for localhost so it does not stick to other local dev servers.
  if (SECURE_COOKIES && !isLocalHost(host)) h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  return h;
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { ...securityHeaders(res.req.headers.host), ...headers });
  if (res.req.method === 'HEAD') res.end(); else res.end(body);
}
const json = (res, status, obj, headers = {}) =>
  send(res, status, JSON.stringify(obj), { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
const text = (res, status, msg) =>
  send(res, status, msg, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
const redirect = (res, to) => send(res, 302, '', { Location: to, 'Cache-Control': 'no-store' });
const rateLimited = (res, s) => json(res, 429, { error: 'rate_limited', retry: s }, { 'Retry-After': String(s) });

function parseCookies(header = '') {
  const o = Object.create(null);
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) o[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return o;
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (xff.length) return xff[xff.length - 1];
  }
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}

const sessionCookie = (id) => `${COOKIE}=${id}; Path=/; HttpOnly; SameSite=Strict${SECURE_COOKIES ? '; Secure' : ''}`;
const clearCookie = () => `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${SECURE_COOKIES ? '; Secure' : ''}`;

const httpErr = (status, code) => Object.assign(new Error(code), { status, code });

function readJson(req, limit = 8192) {
  return new Promise((resolve, reject) => {
    const ct = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/json') return reject(httpErr(415, 'unsupported_media_type'));
    let size = 0, over = false;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) over = true; else chunks.push(c);
    });
    req.on('end', () => {
      if (over) return reject(httpErr(413, 'too_large'));
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
        if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('shape');
        resolve(v);
      } catch { reject(httpErr(400, 'invalid_json')); }
    });
    req.on('error', reject);
  });
}

/** Cross-site request check for state-changing requests. */
function sameOrigin(req) {
  const site = req.headers['sec-fetch-site'];
  if (site && site !== 'same-origin' && site !== 'none') return false;
  const origin = req.headers.origin;
  if (origin) {
    try { return new URL(origin).host.toLowerCase() === String(req.headers.host).toLowerCase(); } catch { return false; }
  }
  return true;
}

const normName = (v) => {
  if (typeof v !== 'string') return null;
  const n = v.trim().toLowerCase();
  return /^[a-z0-9][a-z0-9_.-]{2,31}$/.test(n) ? n : null;
};

function logEvent(u, type, ip) {
  u.events = u.events || [];
  u.events.unshift({ t: Date.now(), e: type, ip });
  u.events.length = Math.min(u.events.length, 20);
  store.save();
}

/* ------------------------------------------------------------------- API */
async function startSession(req, res, u, ip, oldId) {
  if (oldId) auth.destroySession(oldId); // session fixation protection: always a fresh id
  const { id } = auth.createSession(u.name);
  u.lastLogin = Date.now();
  logEvent(u, 'login', ip);
  store.save(true);
  json(res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(id) });
}

async function reauth(u, b) {
  const wait = auth.limits.reauth.blocked(u.name);
  if (wait) return { err: 'rate_limited', wait };
  const pw = typeof b.password === 'string' ? b.password : (typeof b.current === 'string' ? b.current : '');
  if (!pw || pw.length > 128 || !(await auth.verifyPassword(pw, u.hash))) {
    auth.limits.reauth.add(u.name);
    return { err: 'invalid_credentials' };
  }
  if (u.twofa) {
    const step = totp.verify(u.twofa.secret, String(b.code || ''), u.twofa.last);
    if (step < 0) { auth.limits.reauth.add(u.name); return { err: 'invalid_code' }; }
    u.twofa.last = step;
  }
  return { ok: true };
}

async function api(req, res, pathname, cookies, ip) {
  const route = `${req.method} ${pathname}`;
  const sid = cookies[COOKIE];
  const sess = sid ? auth.getSession(sid) : null;

  const PUBLIC = ['POST /api/register', 'POST /api/login', 'POST /api/login/2fa'];
  const PRIVATE = ['GET /api/me', 'PUT /api/progress', 'POST /api/logout', 'POST /api/logout-all', 'POST /api/password',
    'POST /api/2fa/setup', 'POST /api/2fa/enable', 'POST /api/2fa/disable', 'POST /api/account/delete'];
  if (!PUBLIC.includes(route) && !PRIVATE.includes(route)) return json(res, 404, { error: 'not_found' });

  if (req.method !== 'GET' && !sameOrigin(req)) return json(res, 403, { error: 'forbidden' });

  const isPrivate = PRIVATE.includes(route);
  if (isPrivate && !sess) return json(res, 401, { error: 'unauthenticated' });
  if (isPrivate && req.method !== 'GET') {
    if (!auth.safeEqual(req.headers['x-csrf-token'] || '', sess.csrf)) return json(res, 403, { error: 'csrf' });
  }
  const u = isPrivate ? store.get(sess.user) : null;
  if (isPrivate && !u) { auth.destroySession(sid); return json(res, 401, { error: 'unauthenticated' }); }

  const b = req.method === 'GET' ? {} : await readJson(req);

  switch (route) {
    case 'POST /api/register': {
      if (!ALLOW_REGISTRATION) return json(res, 403, { error: 'registration_closed' });
      const wait = auth.limits.register.blocked(ip);
      if (wait) return rateLimited(res, wait);
      auth.limits.register.add(ip);
      const name = normName(b.username);
      if (!name) return json(res, 400, { error: 'username_invalid' });
      const bad = auth.checkPassword(b.password, name);
      if (bad) return json(res, 400, { error: bad });
      if (store.has(name)) return json(res, 409, { error: 'username_taken' });
      if (store.count() >= MAX_USERS) return json(res, 403, { error: 'registration_closed' });
      const hash = await auth.hashPassword(b.password);
      if (store.has(name)) return json(res, 409, { error: 'username_taken' });
      const nu = { name, hash, created: Date.now(), lastLogin: null, twofa: null, progress: { quizBest: 0, checklist: [] }, events: [] };
      store.put(nu);
      logEvent(nu, 'register', ip);
      return startSession(req, res, nu, ip, sid);
    }

    case 'POST /api/login': {
      const name = normName(b.username);
      const pw = typeof b.password === 'string' ? b.password : '';
      if (!name || !pw || pw.length > 128) return json(res, 400, { error: 'invalid_request' });
      const L = auth.limits;
      const wait = L.loginIp.blocked(ip) || L.loginUser.blocked(`${ip}|${name}`) || L.loginName.blocked(name);
      if (wait) return rateLimited(res, wait);
      const user = store.get(name);
      const ok = await auth.verifyPassword(pw, user ? user.hash : auth.dummyHash());
      if (!user || !ok) {
        L.loginIp.add(ip); L.loginUser.add(`${ip}|${name}`); L.loginName.add(name);
        if (user) logEvent(user, 'login_fail', ip);
        return json(res, 401, { error: 'invalid_credentials' });
      }
      L.loginUser.reset(`${ip}|${name}`);
      if (user.twofa) return json(res, 200, { step: '2fa', ticket: auth.createTicket(user.name) });
      return startSession(req, res, user, ip, sid);
    }

    case 'POST /api/login/2fa': {
      const wait = auth.limits.twofa.blocked(ip);
      if (wait) return rateLimited(res, wait);
      const ticket = auth.getTicket(b.ticket);
      const user = ticket && store.get(ticket.user);
      if (!user || !user.twofa) return json(res, 401, { error: 'ticket_expired' });
      const step = totp.verify(user.twofa.secret, String(b.code || ''), user.twofa.last);
      if (step < 0) {
        auth.limits.twofa.add(ip);
        ticket.tries++;
        if (ticket.tries >= 5) auth.dropTicket(b.ticket);
        logEvent(user, '2fa_fail', ip);
        return json(res, 401, { error: 'invalid_code' });
      }
      user.twofa.last = step; // a used code can never be replayed
      auth.dropTicket(b.ticket);
      return startSession(req, res, user, ip, sid);
    }

    case 'GET /api/me':
      return json(res, 200, {
        user: u.name, twofa: !!u.twofa, created: u.created, lastLogin: u.lastLogin,
        progress: u.progress, events: (u.events || []).slice(0, 10),
        sessions: auth.countUserSessions(u.name), csrf: sess.csrf,
      });

    case 'PUT /api/progress': {
      if (b.quizBest !== undefined) {
        if (!Number.isInteger(b.quizBest) || b.quizBest < 0 || b.quizBest > 8) return json(res, 400, { error: 'invalid_request' });
        u.progress.quizBest = Math.max(u.progress.quizBest || 0, b.quizBest);
      }
      if (b.checklist !== undefined) {
        if (!Array.isArray(b.checklist) || b.checklist.length > 6 || !b.checklist.every((x) => typeof x === 'boolean')) {
          return json(res, 400, { error: 'invalid_request' });
        }
        u.progress.checklist = b.checklist;
      }
      store.save();
      return json(res, 200, { ok: true, progress: u.progress });
    }

    case 'POST /api/logout':
      auth.destroySession(sid);
      return json(res, 200, { ok: true }, { 'Set-Cookie': clearCookie() });

    case 'POST /api/logout-all':
      auth.destroyUserSessions(u.name);
      logEvent(u, 'logout_all', ip);
      store.save(true);
      return json(res, 200, { ok: true }, { 'Set-Cookie': clearCookie() });

    case 'POST /api/password': {
      const r = await reauth(u, b);
      if (r.err) return r.err === 'rate_limited' ? rateLimited(res, r.wait) : json(res, 401, { error: r.err });
      const bad = auth.checkPassword(b.next, u.name);
      if (bad) return json(res, 400, { error: bad });
      if (b.next === b.current) return json(res, 400, { error: 'pw_same' });
      u.hash = await auth.hashPassword(b.next);
      auth.destroyUserSessions(u.name, sess.hash); // every other device is signed out
      logEvent(u, 'password_changed', ip);
      store.save(true);
      return json(res, 200, { ok: true });
    }

    case 'POST /api/2fa/setup': {
      if (u.twofa) return json(res, 409, { error: 'already_enabled' });
      const secret = totp.newSecret();
      sess.pending2fa = secret;
      return json(res, 200, { secret, uri: totp.uri(secret, u.name, DICT.en['app.name']) });
    }

    case 'POST /api/2fa/enable': {
      if (!sess.pending2fa) return json(res, 400, { error: 'no_pending' });
      const wait = auth.limits.reauth.blocked(u.name);
      if (wait) return rateLimited(res, wait);
      const step = totp.verify(sess.pending2fa, String(b.code || ''), -1);
      if (step < 0) { auth.limits.reauth.add(u.name); return json(res, 401, { error: 'invalid_code' }); }
      u.twofa = { secret: sess.pending2fa, last: step };
      sess.pending2fa = null;
      logEvent(u, '2fa_enabled', ip);
      store.save(true);
      return json(res, 200, { ok: true });
    }

    case 'POST /api/2fa/disable': {
      if (!u.twofa) return json(res, 400, { error: 'invalid_request' });
      const r = await reauth(u, b);
      if (r.err) return r.err === 'rate_limited' ? rateLimited(res, r.wait) : json(res, 401, { error: r.err });
      u.twofa = null;
      logEvent(u, '2fa_disabled', ip);
      store.save(true);
      return json(res, 200, { ok: true });
    }

    case 'POST /api/account/delete': {
      const r = await reauth(u, b);
      if (r.err) return r.err === 'rate_limited' ? rateLimited(res, r.wait) : json(res, 401, { error: r.err });
      auth.destroyUserSessions(u.name);
      store.remove(u.name);
      store.save(true);
      return json(res, 200, { ok: true }, { 'Set-Cookie': clearCookie() });
    }
  }
  return json(res, 404, { error: 'not_found' });
}

/* ---------------------------------------------------------------- handler */
async function handle(req, res) {
  try {
    const host = String(req.headers.host || '').toLowerCase();
    if (!ALLOWED_HOSTS.has(host)) return text(res, 421, 'Misdirected Request');

    const ip = clientIp(req);
    const wait = auth.limits.requests.blocked(ip);
    if (wait) return rateLimited(res, wait);
    auth.limits.requests.add(ip);

    let pathname;
    try { pathname = new URL(req.url, 'http://x').pathname; } catch { return text(res, 400, 'Bad Request'); }
    const cookies = parseCookies(req.headers.cookie);

    if (pathname.startsWith('/api/')) return await api(req, res, pathname, cookies, ip);

    if (req.method !== 'GET' && req.method !== 'HEAD') return text(res, 405, 'Method Not Allowed');

    const sess = cookies[COOKIE] ? auth.getSession(cookies[COOKIE]) : null;
    const lang = getLang(req, cookies);

    if (pathname === '/login') {
      if (sess && store.has(sess.user)) return redirect(res, '/');
      return send(res, 200, render('login', lang, null), { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    }
    if (Object.prototype.hasOwnProperty.call(PAGES, pathname)) {
      if (!sess || !store.has(sess.user)) return redirect(res, '/login');
      return send(res, 200, render(PAGES[pathname], lang, sess), { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    }
    if (Object.prototype.hasOwnProperty.call(ASSETS, pathname)) {
      const [file, type] = ASSETS[pathname];
      const body = fs.readFileSync(path.join(ROOT, file));
      const etag = '"' + crypto.createHash('sha1').update(body).digest('hex') + '"';
      if (req.headers['if-none-match'] === etag) return send(res, 304, '', { ETag: etag });
      return send(res, 200, body, { 'Content-Type': type, 'Cache-Control': 'no-cache', ETag: etag });
    }
    return text(res, 404, 'Not Found');
  } catch (err) {
    if (err && err.status) return json(res, err.status, { error: err.code }, err.status === 413 ? { Connection: 'close' } : {});
    console.error('Unhandled error:', err);
    if (!res.headersSent) return json(res, 500, { error: 'server_error' });
    res.end();
  }
}

/* ------------------------------------------------------------------ start */
store.init();
const server = TLS
  ? https.createServer({ key: fs.readFileSync(KEY_FILE), cert: fs.readFileSync(CERT_FILE), minVersion: 'TLSv1.2' }, handle)
  : http.createServer(handle);
server.requestTimeout = 15000;
server.headersTimeout = 10000;
server.keepAliveTimeout = 5000;
server.maxHeadersCount = 50;

server.listen(PORT, HOST, () => {
  const shown = HOST === '::1' ? '[::1]' : HOST;
  console.log(`Listening on ${TLS ? 'https' : 'http'}://${shown}:${PORT}  (users: ${store.count()})`);
  if (!TLS) console.log('Note: no certificate found, serving plain HTTP on loopback only. Run "npm run cert" for HTTPS.');
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => { try { store.flush(); } catch { /* ignore */ } server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 500).unref(); });
}
