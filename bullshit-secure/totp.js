'use strict';
/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s) with RFC 4648 base32. No dependencies. */
const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function b32encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function b32decode(str) {
  const s = String(str).replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error('invalid base32');
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

function hotp(secret, counter, digits = 6) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', secret).update(msg).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 10 ** digits).padStart(digits, '0');
}

const stepOf = (ms = Date.now()) => Math.floor(ms / 30000);

/**
 * Returns the accepted time step (> lastStep) or -1.
 * A window of +-1 step tolerates clock drift; a used step can never be replayed.
 */
function verify(secretB32, code, lastStep = -1, now = Date.now()) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return -1;
  const secret = b32decode(secretB32);
  const cur = stepOf(now);
  let accepted = -1;
  for (let d = -1; d <= 1; d++) {
    const s = cur + d;
    if (s <= lastStep) continue;
    const ok = crypto.timingSafeEqual(Buffer.from(hotp(secret, s)), Buffer.from(code));
    if (ok && accepted < 0) accepted = s;
  }
  return accepted;
}

const newSecret = () => b32encode(crypto.randomBytes(20));

const uri = (secret, account, issuer) =>
  `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}` +
  `?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

module.exports = { b32encode, b32decode, hotp, stepOf, verify, newSecret, uri };
