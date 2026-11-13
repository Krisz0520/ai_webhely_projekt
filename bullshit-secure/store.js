'use strict';
/**
 * Encrypted user store.
 * - All user records live in ONE file (data/users.enc), sealed with AES-256-GCM.
 * - The key comes from APP_SECRET (stretched with scrypt) or from a random
 *   key file (data/secret.key, mode 0600) that is generated on first start.
 * - Writes are atomic (temp file + rename) and the file mode is 0600.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILE = path.join(DATA_DIR, 'users.enc');
const MAGIC = Buffer.from('BSE1'); // format marker, also used as AAD

const users = new Map(); // name -> record (Map: no prototype-pollution via names)
let key = null;
let timer = null;
let dirty = false;

function loadKey() {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  if (process.env.APP_SECRET) {
    const saltFile = path.join(DATA_DIR, 'kdf.salt');
    let salt;
    if (fs.existsSync(saltFile)) salt = fs.readFileSync(saltFile);
    else {
      salt = crypto.randomBytes(16);
      fs.writeFileSync(saltFile, salt, { mode: 0o600 });
    }
    return crypto.scryptSync(process.env.APP_SECRET, salt, 32, {
      N: 1 << 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024,
    });
  }
  const keyFile = path.join(DATA_DIR, 'secret.key');
  if (fs.existsSync(keyFile)) {
    const k = Buffer.from(fs.readFileSync(keyFile, 'utf8').trim(), 'hex');
    if (k.length !== 32) throw new Error('secret.key is corrupt (expected 32 bytes)');
    return k;
  }
  const k = crypto.randomBytes(32);
  fs.writeFileSync(keyFile, k.toString('hex'), { mode: 0o600 });
  return k;
}

function seal(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(MAGIC);
  const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  return Buffer.concat([MAGIC, iv, c.getAuthTag(), ct]);
}

function open(buf) {
  if (buf.length < 32 || !buf.subarray(0, 4).equals(MAGIC)) throw new Error('unknown store format');
  const d = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(4, 16));
  d.setAAD(MAGIC);
  d.setAuthTag(buf.subarray(16, 32));
  const plain = Buffer.concat([d.update(buf.subarray(32)), d.final()]); // throws if tampered / wrong key
  return JSON.parse(plain.toString('utf8'));
}

function init() {
  key = loadKey();
  users.clear();
  if (fs.existsSync(FILE)) {
    const data = open(fs.readFileSync(FILE));
    for (const u of data.users || []) users.set(u.name, u);
  }
}

function persist() {
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, seal({ v: 1, users: [...users.values()] }), { mode: 0o600 });
  fs.renameSync(tmp, FILE);
  dirty = false;
}

/** save(true) writes immediately; save() coalesces writes (200 ms). */
function save(now = false) {
  dirty = true;
  if (now) {
    if (timer) { clearTimeout(timer); timer = null; }
    persist();
    return;
  }
  if (!timer) {
    timer = setTimeout(() => { timer = null; if (dirty) persist(); }, 200);
  }
}

function flush() { if (timer) { clearTimeout(timer); timer = null; } if (dirty) persist(); }
process.on('exit', () => { try { flush(); } catch { /* ignore */ } });

module.exports = {
  init, save, flush,
  get: (n) => users.get(n),
  has: (n) => users.has(n),
  put: (u) => { users.set(u.name, u); },
  remove: (n) => users.delete(n),
  all: () => [...users.values()],
  count: () => users.size,
  DATA_DIR,
};
