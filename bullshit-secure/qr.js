/* Minimal QR Code generator: byte mode, error-correction level M, versions 1-10 (up to 213 bytes).
   No dependencies. Works in the browser (window.QR) and in Node (module.exports) for the tests.
   The text never leaves the browser: the 2FA secret is encoded locally, not by an online service. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.QR = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const MAX_VERSION = 10;
  const ECC_PER_BLOCK = [10, 16, 26, 18, 24, 16, 18, 22, 22, 26]; // level M, index = version - 1
  const NUM_BLOCKS = [1, 1, 1, 2, 2, 4, 4, 4, 5, 5];
  const ALIGN = [[], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];

  const rawModules = (v) => {
    let r = (16 * v + 128) * v + 64;
    if (v >= 2) {
      const a = Math.floor(v / 7) + 2;
      r -= (25 * a - 10) * a - 55;
      if (v >= 7) r -= 36;
    }
    return r;
  };
  const rawCodewords = (v) => Math.floor(rawModules(v) / 8);
  const dataCodewords = (v) => rawCodewords(v) - ECC_PER_BLOCK[v - 1] * NUM_BLOCKS[v - 1];

  /* ---------------------------------------------- Reed-Solomon over GF(2^8), polynomial 0x11D */
  function gfMul(x, y) {
    let z = 0;
    for (let i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11d);
      z ^= ((y >>> i) & 1) * x;
    }
    return z;
  }
  function rsDivisor(degree) {
    const result = new Array(degree).fill(0);
    result[degree - 1] = 1;
    let root = 1;
    for (let i = 0; i < degree; i++) {
      for (let j = 0; j < degree; j++) {
        result[j] = gfMul(result[j], root);
        if (j + 1 < degree) result[j] ^= result[j + 1];
      }
      root = gfMul(root, 0x02);
    }
    return result;
  }
  function rsRemainder(data, divisor) {
    const result = divisor.map(() => 0);
    for (const b of data) {
      const factor = b ^ result.shift();
      result.push(0);
      divisor.forEach((coef, i) => { result[i] ^= gfMul(coef, factor); });
    }
    return result;
  }

  /* ----------------------------------------------------------------------- data encoding */
  function utf8(str) {
    if (typeof TextEncoder !== 'undefined') return Array.from(new TextEncoder().encode(str));
    return Array.from(Buffer.from(str, 'utf8'));
  }

  function buildData(bytes, v) {
    const bits = [];
    const put = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
    put(4, 4); // byte mode
    put(bytes.length, v < 10 ? 8 : 16);
    bytes.forEach((b) => put(b, 8));
    const cap = dataCodewords(v) * 8;
    put(0, Math.min(4, cap - bits.length)); // terminator
    put(0, (8 - (bits.length % 8)) % 8);
    for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) put(pad, 8);
    const out = [];
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0;
      for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
      out.push(b);
    }
    return out;
  }

  function addEccAndInterleave(data, v) {
    const nb = NUM_BLOCKS[v - 1];
    const eccLen = ECC_PER_BLOCK[v - 1];
    const raw = rawCodewords(v);
    const numShort = nb - (raw % nb);
    const shortLen = Math.floor(raw / nb);
    const div = rsDivisor(eccLen);
    const blocks = [];
    let k = 0;
    for (let i = 0; i < nb; i++) {
      const dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1));
      k += dat.length;
      const ecc = rsRemainder(dat, div);
      if (i < numShort) dat.push(0);
      blocks.push(dat.concat(ecc));
    }
    const result = [];
    for (let i = 0; i < blocks[0].length; i++) {
      blocks.forEach((block, j) => {
        if (i !== shortLen - eccLen || j >= numShort) result.push(block[i]);
      });
    }
    return result;
  }

  /* ------------------------------------------------------------------------ masks, penalty */
  const MASKS = [
    (x, y) => (x + y) % 2 === 0,
    (x, y) => y % 2 === 0,
    (x, y) => x % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
    (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
    (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
  ];

  function penalty(m, size) {
    let result = 0;
    for (let dir = 0; dir < 2; dir++) {
      for (let a = 0; a < size; a++) {
        const line = [];
        for (let b = 0; b < size; b++) line.push(dir === 0 ? m[a][b] : m[b][a]);
        let run = 1;
        for (let i = 1; i < size; i++) {
          if (line[i] === line[i - 1]) {
            run++;
            if (run === 5) result += 3; else if (run > 5) result += 1;
          } else run = 1;
        }
        for (let i = 0; i + 11 <= size; i++) {
          const w = line.slice(i, i + 11).map(Number).join('');
          if (w === '10111010000' || w === '00001011101') result += 40;
        }
      }
    }
    for (let y = 0; y < size - 1; y++) {
      for (let x = 0; x < size - 1; x++) {
        const c = m[y][x];
        if (c === m[y][x + 1] && c === m[y + 1][x] && c === m[y + 1][x + 1]) result += 3;
      }
    }
    let dark = 0;
    for (const row of m) for (const c of row) if (c) dark++;
    const total = size * size;
    result += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10;
    return result;
  }

  /* --------------------------------------------------------------------------- the encoder */
  /** opts.mask (0-7) forces a mask pattern; used by the tests, the default picks the best one. */
  function encode(text, opts) {
    const bytes = utf8(String(text));
    let v = 1;
    for (; v <= MAX_VERSION; v++) {
      if (4 + (v < 10 ? 8 : 16) + bytes.length * 8 <= dataCodewords(v) * 8) break;
    }
    if (v > MAX_VERSION) throw new Error('QR: text too long (max 213 bytes)');

    const codewords = addEccAndInterleave(buildData(bytes, v), v);
    const size = 17 + 4 * v;
    const modules = Array.from({ length: size }, () => new Array(size).fill(false));
    const isFn = Array.from({ length: size }, () => new Array(size).fill(false));
    const setFn = (x, y, dark) => { modules[y][x] = dark; isFn[y][x] = true; };

    // timing patterns
    for (let i = 0; i < size; i++) { setFn(6, i, i % 2 === 0); setFn(i, 6, i % 2 === 0); }
    // finder patterns with separators
    const finder = (cx, cy) => {
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const x = cx + dx, y = cy + dy, d = Math.max(Math.abs(dx), Math.abs(dy));
          if (x >= 0 && x < size && y >= 0 && y < size) setFn(x, y, d !== 2 && d !== 4);
        }
      }
    };
    finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
    // alignment patterns
    const pos = ALIGN[v - 1];
    const n = pos.length;
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue;
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) setFn(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }

    // format information (level M = 00) and, from version 7, version information
    const drawFormat = (mask) => {
      const data = mask; // (M = 00) << 3 | mask
      let rem = data;
      for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
      const bits = ((data << 10) | rem) ^ 0x5412;
      const bit = (i) => ((bits >>> i) & 1) !== 0;
      for (let i = 0; i <= 5; i++) setFn(8, i, bit(i));
      setFn(8, 7, bit(6)); setFn(8, 8, bit(7)); setFn(7, 8, bit(8));
      for (let i = 9; i < 15; i++) setFn(14 - i, 8, bit(i));
      for (let i = 0; i < 8; i++) setFn(size - 1 - i, 8, bit(i));
      for (let i = 8; i < 15; i++) setFn(8, size - 15 + i, bit(i));
      setFn(8, size - 8, true);
    };
    drawFormat(0);
    if (v >= 7) {
      let rem = v;
      for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
      const bits = (v << 12) | rem;
      for (let i = 0; i < 18; i++) {
        const dark = ((bits >>> i) & 1) !== 0;
        const a = size - 11 + (i % 3), b = Math.floor(i / 3);
        setFn(a, b, dark); setFn(b, a, dark);
      }
    }

    // place the data bits in the zigzag order
    let bitIdx = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? size - 1 - vert : vert;
          if (!isFn[y][x] && bitIdx < codewords.length * 8) {
            modules[y][x] = ((codewords[bitIdx >>> 3] >>> (7 - (bitIdx & 7))) & 1) !== 0;
            bitIdx++;
          }
        }
      }
    }

    // pick the mask with the lowest penalty
    const applyMask = (m) => {
      for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!isFn[y][x] && MASKS[m](x, y)) modules[y][x] = !modules[y][x];
    };
    let best = 0, bestScore = Infinity;
    const forced = opts && Number.isInteger(opts.mask) ? opts.mask : -1;
    for (let m = forced >= 0 ? forced : 0; m < (forced >= 0 ? forced + 1 : 8); m++) {
      applyMask(m);
      drawFormat(m);
      const s = penalty(modules, size);
      if (s < bestScore) { best = m; bestScore = s; }
      applyMask(m); // undo
    }
    applyMask(best);
    drawFormat(best);

    return { version: v, size, mask: best, modules };
  }

  /** SVG path for the dark modules (horizontal runs), with a quiet zone of `border` modules. */
  function pathData(qr, border) {
    const b = border === undefined ? 4 : border;
    const parts = [];
    for (let y = 0; y < qr.size; y++) {
      let x = 0;
      while (x < qr.size) {
        if (!qr.modules[y][x]) { x++; continue; }
        const start = x;
        while (x < qr.size && qr.modules[y][x]) x++;
        parts.push(`M${start + b},${y + b}h${x - start}v1h-${x - start}z`);
      }
    }
    return parts.join('');
  }

  return { encode, pathData, MAX_BYTES: 213, _rsDivisor: rsDivisor, _rsRemainder: rsRemainder };
});
