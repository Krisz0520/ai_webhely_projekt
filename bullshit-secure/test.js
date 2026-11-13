'use strict';
/**
 * Self-contained test suite: starts the server on a temp data dir and checks
 * authentication, CSRF, rate limiting, 2FA, encryption at rest, TLS and i18n wiring.
 * Run: npm test
 */
const { spawn, spawnSync } = require('child_process');
const http = require('http');
const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');
const totp = require('./totp');

let passed = 0, failed = 0;
function ok(cond, name, extra) {
  if (cond) { passed++; console.log('  ok   ' + name); }
  else { failed++; console.log('  FAIL ' + name + (extra ? '  -> ' + extra : '')); }
}

function request(port, { method = 'GET', p = '/', headers = {}, body, tls = false, jar }) {
  return new Promise((resolve, reject) => {
    const h = { Host: `localhost:${port}`, ...headers };
    let payload;
    if (body !== undefined) {
      payload = typeof body === 'string' ? body : JSON.stringify(body);
      h['Content-Type'] = h['Content-Type'] || 'application/json';
      h['Content-Length'] = Buffer.byteLength(payload);
    }
    if (jar && Object.keys(jar).length) h.Cookie = Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
    const mod = tls ? https : http;
    const req = mod.request({ host: '127.0.0.1', port, method, path: p, headers: h, rejectUnauthorized: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        for (const c of res.headers['set-cookie'] || []) {
          const [kv] = c.split(';');
          const i = kv.indexOf('=');
          if (jar) { if (/Max-Age=0/i.test(c)) delete jar[kv.slice(0, i)]; else jar[kv.slice(0, i)] = kv.slice(i + 1); }
        }
        const text = Buffer.concat(chunks).toString('utf8');
        let data = null;
        try { data = JSON.parse(text); } catch { /* not json */ }
        resolve({ status: res.statusCode, headers: res.headers, text, data });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function startServer(env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['server.js'], { cwd: __dirname, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    const onData = (d) => { out += d; const m = out.match(/Listening on (https?):\/\/[^:]+:(\d+)/); if (m) resolve({ child, port: +m[2] }); };
    child.stdout.on('data', onData);
    child.stderr.on('data', (d) => { out += d; });
    child.on('exit', (code) => reject(new Error('server exited early: ' + code + '\n' + out)));
    setTimeout(() => reject(new Error('server start timeout\n' + out)), 8000);
  });
}

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'bs-test-'));
const PW = 'Correct-Horse-Battery-9';

async function mainSuite() {
  console.log('\n[HTTP mode]');
  const dataDir = tmp();
  const port = 30000 + Math.floor(Math.random() * 20000);
  const { child } = await startServer({ DATA_DIR: dataDir, CERT_DIR: path.join(dataDir, 'none'), PORT: String(port), HOST: '127.0.0.1' });
  const R = (o) => request(port, o);
  try {
    // --- public surface
    let r = await R({ p: '/' });
    ok(r.status === 302 && r.headers.location === '/login', 'protected page redirects to /login when signed out');
    r = await R({ p: '/login', headers: { 'Accept-Language': 'en-US,en;q=0.9' } });
    ok(r.status === 200 && /<html lang="en">/.test(r.text), 'login page renders, English by Accept-Language');
    ok(!/\{\{/.test(r.text), 'no unresolved template placeholders on login page');
    ok(/default-src 'none'/.test(r.headers['content-security-policy'] || ''), 'CSP header present');
    ok(r.headers['x-content-type-options'] === 'nosniff' && r.headers['x-frame-options'] === 'DENY', 'nosniff + X-Frame-Options');
    ok(/no-store/.test(r.headers['cache-control'] || ''), 'login page is no-store');
    ok(!('strict-transport-security' in r.headers), 'no HSTS on plain-HTTP localhost');
    r = await R({ p: '/login', headers: { Cookie: 'lang=hu', 'Accept-Language': 'en' } });
    ok(/<html lang="hu">/.test(r.text), 'lang cookie overrides Accept-Language');
    r = await R({ p: '/style.css' });
    ok(r.status === 200 && /text\/css/.test(r.headers['content-type']), 'static allowlist serves style.css');
    for (const bad of ['/server.js', '/store.js', '/hu.json', '/home.html', '/layout.html', '/package.json', '/data/users.enc', '/..%2fserver.js', '/%2e%2e/server.js', '/test.js']) {
      r = await R({ p: bad });
      ok(r.status === 404 || r.status === 400, 'not served: ' + bad, 'status ' + r.status);
    }
    r = await request(port, { p: '/login', headers: { Host: 'evil.example' } });
    ok(r.status === 421, 'unknown Host header is rejected (DNS-rebinding guard)');

    // --- registration validation
    const A = {};
    r = await R({ method: 'POST', p: '/api/register', body: { username: 'alice', password: 'short' }, jar: A });
    ok(r.status === 400 && r.data.error === 'pw_short', 'short password rejected');
    r = await R({ method: 'POST', p: '/api/register', body: { username: 'alice', password: 'password' + '1234' }, jar: A });
    ok(r.status === 400 && r.data.error === 'pw_common', 'common password rejected');
    r = await R({ method: 'POST', p: '/api/register', body: { username: '__proto__x!', password: PW }, jar: A });
    ok(r.status === 400 && r.data.error === 'username_invalid', 'invalid username rejected');
    r = await R({ method: 'POST', p: '/api/register', body: { username: 'alice', password: PW }, headers: { Origin: 'https://evil.example' }, jar: A });
    ok(r.status === 403, 'cross-origin POST rejected');
    r = await R({ method: 'POST', p: '/api/register', body: 'username=alice', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, jar: A });
    ok(r.status === 415, 'non-JSON content type rejected');
    r = await R({ method: 'POST', p: '/api/register', body: { username: 'alice', password: PW, pad: 'x'.repeat(20000) }, jar: A });
    ok(r.status === 413, 'oversized body rejected');
    r = await R({ method: 'POST', p: '/api/register', body: { username: 'alice', password: PW }, jar: A });
    ok(r.status === 200 && r.data.ok, 'register alice');
    const setCookie = (await R({ method: 'POST', p: '/api/login', body: { username: 'alice', password: PW } })).headers['set-cookie'] || [];
    ok(setCookie.some((c) => /^sid=/.test(c) && /HttpOnly/i.test(c) && /SameSite=Strict/i.test(c)), 'session cookie is HttpOnly + SameSite=Strict');
    r = await R({ method: 'POST', p: '/api/register', body: { username: 'ALICE', password: PW } });
    ok(r.status === 409 && r.data.error === 'username_taken', 'usernames are case-insensitive and unique');

    // --- authenticated area
    r = await R({ p: '/', jar: A });
    ok(r.status === 200 && /alice/.test(r.text) && /name="csrf-token" content="[\w-]{20,}"/.test(r.text), 'home renders for alice with csrf meta');
    ok(!/\{\{/.test(r.text), 'no unresolved placeholders on home');
    for (const pg of ['/frankfurt', '/types', '/detector', '/quiz', '/workplace', '/defense', '/account']) {
      const rr = await R({ p: pg, jar: A });
      ok(rr.status === 200 && !/\{\{/.test(rr.text), 'page renders: ' + pg);
    }
    r = await R({ p: '/login', jar: A });
    ok(r.status === 302 && r.headers.location === '/', 'signed-in user is redirected away from /login');
    r = await R({ p: '/api/me', jar: A });
    ok(r.status === 200 && r.data.user === 'alice' && r.data.twofa === false, 'GET /api/me');
    const csrf = r.data.csrf;
    r = await R({ p: '/api/me' });
    ok(r.status === 401, '/api/me requires a session');

    r = await R({ method: 'PUT', p: '/api/progress', body: { quizBest: 5 }, jar: A });
    ok(r.status === 403 && r.data.error === 'csrf', 'state change without CSRF token rejected');
    r = await R({ method: 'PUT', p: '/api/progress', body: { quizBest: 6, checklist: [true, false, true, false, false, false] }, headers: { 'X-CSRF-Token': csrf }, jar: A });
    ok(r.status === 200 && r.data.progress.quizBest === 6, 'progress saved with CSRF token');
    r = await R({ method: 'PUT', p: '/api/progress', body: { quizBest: 99 }, headers: { 'X-CSRF-Token': csrf }, jar: A });
    ok(r.status === 400, 'invalid progress value rejected');
    r = await R({ method: 'PUT', p: '/api/progress', body: { quizBest: 3 }, headers: { 'X-CSRF-Token': csrf }, jar: A });
    ok(r.data.progress.quizBest === 6, 'quizBest keeps the maximum');

    // --- password change (before 2FA, so no TOTP step is needed)
    const hdr = { 'X-CSRF-Token': csrf };
    r = await R({ method: 'POST', p: '/api/password', body: { current: 'wrong-password-1', next: 'Another-Long-Pass-77' }, headers: hdr, jar: A });
    ok(r.status === 401, 'password change needs the current password');
    r = await R({ method: 'POST', p: '/api/password', body: { current: PW, next: 'short' }, headers: hdr, jar: A });
    ok(r.status === 400 && r.data.error === 'pw_short', 'password policy applies on change');
    const A2 = {}; // a second device
    await R({ method: 'POST', p: '/api/login', body: { username: 'alice', password: PW }, jar: A2 });
    r = await R({ method: 'POST', p: '/api/password', body: { current: PW, next: 'Another-Long-Pass-77' }, headers: hdr, jar: A });
    ok(r.status === 200, 'password changed');
    r = await R({ p: '/api/me', jar: A2 });
    ok(r.status === 401, 'other sessions are signed out after a password change');
    r = await R({ p: '/api/me', jar: A });
    ok(r.status === 200, 'current session stays valid');
    r = await R({ method: 'POST', p: '/api/login', body: { username: 'alice', password: PW } });
    ok(r.status === 401, 'old password no longer works');
    const PW2 = 'Another-Long-Pass-77';

    // --- 2FA
    r = await R({ method: 'POST', p: '/api/2fa/setup', body: {}, headers: hdr, jar: A });
    ok(r.status === 200 && /^[A-Z2-7]{32}$/.test(r.data.secret) && r.data.uri.startsWith('otpauth://totp/'), '2FA setup returns secret + otpauth uri');
    const secret = r.data.secret;
    const codeAt = (step) => totp.hotp(totp.b32decode(secret), step);
    r = await R({ method: 'POST', p: '/api/2fa/enable', body: { code: '000000' }, headers: hdr, jar: A });
    ok(r.status === 401 && r.data.error === 'invalid_code', '2FA enable rejects a wrong code');
    r = await R({ method: 'POST', p: '/api/2fa/enable', body: { code: codeAt(totp.stepOf() - 1) }, headers: hdr, jar: A });
    ok(r.status === 200, '2FA enabled with a valid code');
    r = await R({ p: '/api/me', jar: A });
    ok(r.data.twofa === true, 'account reports 2FA on');

    await R({ method: 'POST', p: '/api/logout', body: {}, headers: hdr, jar: A });
    r = await R({ p: '/', jar: A });
    ok(r.status === 302, 'logout destroys the session');

    const L = {};
    r = await R({ method: 'POST', p: '/api/login', body: { username: 'alice', password: PW2 }, jar: L });
    ok(r.status === 200 && r.data.step === '2fa' && r.data.ticket && !L.sid, 'login with 2FA returns a ticket, no session yet');
    const ticket = r.data.ticket;
    r = await R({ method: 'POST', p: '/api/login/2fa', body: { ticket, code: '123456' }, jar: L });
    ok(r.status === 401, 'wrong 2FA code rejected');
    const good = codeAt(totp.stepOf());
    r = await R({ method: 'POST', p: '/api/login/2fa', body: { ticket, code: good }, jar: L });
    ok(r.status === 200 && L.sid, '2FA login succeeds with a valid code');
    r = await R({ method: 'POST', p: '/api/login', body: { username: 'alice', password: PW2 }, jar: {} });
    const t2 = r.data.ticket;
    r = await R({ method: 'POST', p: '/api/login/2fa', body: { ticket: t2, code: good }, jar: {} });
    ok(r.status === 401, 'a used 2FA code cannot be replayed');

    const me = await R({ p: '/api/me', jar: L });
    const hdrL = { 'X-CSRF-Token': me.data.csrf };
    r = await R({ method: 'POST', p: '/api/2fa/disable', body: { password: PW2, code: codeAt(totp.stepOf() + 1) }, headers: hdrL, jar: L });
    ok(r.status === 200, '2FA disabled (password + fresh code)');

    // --- rate limiting
    let last;
    for (let i = 0; i < 6; i++) last = await R({ method: 'POST', p: '/api/login', body: { username: 'ghost', password: 'wrong-password-' + i } });
    ok(last.status === 429 && last.headers['retry-after'], 'login attempts are rate limited (429 + Retry-After)');
    r = await R({ method: 'POST', p: '/api/login', body: { username: 'ghost', password: 'x' } });
    ok(r.status === 429, 'limiter keeps blocking');

    // --- account deletion
    const C = {};
    r = await R({ method: 'POST', p: '/api/register', body: { username: 'carol', password: PW }, jar: C });
    ok(r.status === 200, 'register carol');
    const cm = await R({ p: '/api/me', jar: C });
    const hdrC = { 'X-CSRF-Token': cm.data.csrf };
    r = await R({ method: 'POST', p: '/api/account/delete', body: { password: 'nope-nope-nope' }, headers: hdrC, jar: C });
    ok(r.status === 401, 'delete requires the right password');
    r = await R({ method: 'POST', p: '/api/account/delete', body: { password: PW }, headers: hdrC, jar: C });
    ok(r.status === 200, 'account deleted');
    r = await R({ method: 'POST', p: '/api/login', body: { username: 'carol', password: PW } });
    ok(r.status === 401, 'deleted account cannot sign in');

    // --- encryption at rest
    await new Promise((res) => setTimeout(res, 400));
    const enc = fs.readFileSync(path.join(dataDir, 'users.enc'));
    ok(enc.subarray(0, 4).toString() === 'BSE1', 'store has the encrypted-format header');
    ok(!enc.includes('alice') && !enc.includes('scrypt$') && !enc.includes(secret), 'store contains no readable usernames, hashes or secrets');
    if (process.platform !== 'win32') {
      ok((fs.statSync(path.join(dataDir, 'users.enc')).mode & 0o077) === 0, 'store file is private (0600)');
      ok((fs.statSync(path.join(dataDir, 'secret.key')).mode & 0o077) === 0, 'key file is private (0600)');
    }
  } finally {
    child.kill();
  }

  // tampering must be detected on the next start
  const enc = path.join(dataDir, 'users.enc');
  const buf = fs.readFileSync(enc);
  buf[buf.length - 3] ^= 0xff;
  fs.writeFileSync(enc, buf);
  const bad = spawnSync(process.execPath, ['server.js'], { cwd: __dirname, env: { ...process.env, DATA_DIR: dataDir, PORT: '0', CERT_DIR: path.join(dataDir, 'none') }, timeout: 5000 });
  ok(bad.status !== 0, 'a tampered store file makes the server refuse to start');
}

async function tlsSuite() {
  console.log('\n[HTTPS mode]');
  const probe = spawnSync('openssl', ['version']);
  if (probe.status !== 0) { console.log('  skip (openssl not available)'); return; }
  const dir = tmp();
  const certs = path.join(dir, 'certs');
  fs.mkdirSync(certs);
  const gen = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
    '-keyout', path.join(certs, 'key.pem'), '-out', path.join(certs, 'cert.pem'), '-days', '2', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1']);
  ok(gen.status === 0, 'self-signed certificate generated');
  const port = 30000 + Math.floor(Math.random() * 20000);
  const { child } = await startServer({ DATA_DIR: path.join(dir, 'data'), CERT_DIR: certs, PORT: String(port) });
  try {
    const jar = {};
    let r = await request(port, { p: '/login', tls: true });
    ok(r.status === 200, 'login page served over HTTPS');
    ok(/upgrade-insecure-requests/.test(r.headers['content-security-policy']), 'CSP upgrades insecure requests under TLS');
    r = await request(port, { method: 'POST', p: '/api/register', body: { username: 'tlsuser', password: PW }, tls: true, jar });
    ok(r.status === 200 && (r.headers['set-cookie'] || []).some((c) => /^__Host-sid=/.test(c) && /; Secure/.test(c) && /Path=\//.test(c) && !/Domain=/i.test(c)), 'session cookie is __Host- prefixed and Secure over HTTPS');
  } finally { child.kill(); }
}

async function bindSuite() {
  console.log('\n[Safety checks]');
  const dir = tmp();
  const r = spawnSync(process.execPath, ['server.js'], { cwd: __dirname, env: { ...process.env, DATA_DIR: dir, HOST: '0.0.0.0', PORT: '0', CERT_DIR: path.join(dir, 'none') }, timeout: 5000 });
  ok(r.status === 1 && /non-loopback/.test(String(r.stderr)), 'refuses to listen on a public address without HTTPS');
}

function staticChecks() {
  console.log('\n[TOTP]');
  // RFC 6238 appendix B test vector (SHA-1): T=59s -> counter 1 -> 8-digit 94287082, i.e. 6-digit 287082
  ok(totp.hotp(Buffer.from('12345678901234567890'), 1) === '287082', 'TOTP matches the RFC 6238 test vector');
  ok(totp.hotp(Buffer.from('12345678901234567890'), 37037036) === '081804', 'TOTP matches the RFC 6238 vector for T=1111111109');
  console.log('\n[Static consistency]');
  const hu = JSON.parse(fs.readFileSync('hu.json', 'utf8'));
  const en = JSON.parse(fs.readFileSync('en.json', 'utf8'));
  const hk = Object.keys(hu), ek = Object.keys(en);
  ok(hk.length === ek.length && hk.every((k) => k in en), 'hu.json and en.json have identical keys', hk.filter((k) => !(k in en)).concat(ek.filter((k) => !(k in hu))).join(','));
  ok(Object.values(hu).concat(Object.values(en)).every((v) => v.trim().length > 0), 'no empty translations');

  const htmlFiles = fs.readdirSync('.').filter((f) => f.endsWith('.html'));
  const used = new Set();
  const ids = new Set();
  for (const f of htmlFiles) {
    const s = fs.readFileSync(f, 'utf8');
    for (const m of s.matchAll(/\{\{[th]:([\w.-]+)\}\}/g)) used.add(m[1]);
    for (const m of s.matchAll(/\sid="([\w-]+)"/g)) ids.add(m[1]);
    ok(!/\sstyle=|<style|<script(?![^>]*\ssrc=)(?![^>]*type="application\/json")/.test(s), `no inline style/script in ${f}`);
  }
  const missing = [...used].filter((k) => !(k in hu) || !(k in en));
  ok(missing.length === 0, 'every template key exists in both languages', missing.join(','));

  const js = fs.readFileSync('app.js', 'utf8') + fs.readFileSync('login.js', 'utf8');
  const jsKeys = new Set();
  // keys followed by "+" are dynamic prefixes ('det.l' + level); their full sets are added explicitly below
  for (const m of js.matchAll(/\b(?:t|list)\('([\w.-]+)'(?!\s*\+)/g)) jsKeys.add(m[1]);
  for (let i = 1; i <= 8; i++) { jsKeys.add(`quiz.q${i}.t`); jsKeys.add(`quiz.q${i}.w`); }
  for (const k of ['honest', 'liar', 'bs']) { jsKeys.add(`ff.role.${k}.t`); jsKeys.add(`ff.role.${k}.d`); }
  for (let i = 0; i <= 3; i++) jsKeys.add('det.l' + i);
  for (let i = 0; i <= 4; i++) jsKeys.add('login.s' + i);
  for (const k of ['auto', 'light', 'dark']) jsKeys.add('theme.' + k);
  const jsMissing = [...jsKeys].filter((k) => !(k in hu) || !(k in en));
  ok(jsMissing.length === 0, 'every key used by the client scripts exists in both languages', jsMissing.join(','));

  const srv = fs.readFileSync('server.js', 'utf8') + fs.readFileSync('auth.js', 'utf8');
  const codes = new Set();
  for (const m of srv.matchAll(/error:\s*'([a-z0-9_]+)'/g)) codes.add(m[1]);
  for (const m of srv.matchAll(/httpErr\(\d+,\s*'([a-z0-9_]+)'/g)) codes.add(m[1]);
  for (const m of srv.matchAll(/return '(pw_[a-z]+)'/g)) codes.add(m[1]);
  for (const m of srv.matchAll(/err: '([a-z_]+)'/g)) codes.add(m[1]);
  const codeMissing = [...codes].filter((c) => !(`err.${c}` in hu) || !(`err.${c}` in en));
  ok(codeMissing.length === 0, 'every server error code has a translation', codeMissing.join(','));
  const evs = new Set([...srv.matchAll(/logEvent\([^,]+,\s*'([\w]+)'/g)].map((m) => m[1]));
  const evMissing = [...evs].filter((e) => !(`ev.${e}` in hu));
  ok(evMissing.length === 0, 'every logged event has a translation', evMissing.join(','));

  const dynamicIds = new Set(['dict']);
  const wanted = [...js.matchAll(/\$\('#([\w-]+)'\)/g)].map((m) => m[1]);
  const noId = [...new Set(wanted)].filter((i) => !ids.has(i) && !dynamicIds.has(i) && !['theme-btn', 'lang-btn', 'menu-btn', 'nav', 'logout-btn'].includes(i));
  ok(noId.length === 0, 'every #id used by the scripts exists in some page', noId.join(','));
  const layout = fs.readFileSync('layout.html', 'utf8');
  ok(['theme-btn', 'lang-btn', 'menu-btn', 'nav', 'dict'].every((i) => layout.includes(`id="${i}"`)), 'layout contains the shared control ids');
}

(async () => {
  try {
    staticChecks();
    await mainSuite();
    await tlsSuite();
    await bindSuite();
  } catch (e) {
    failed++;
    console.log('  FAIL suite crashed: ' + e.stack);
  }
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
