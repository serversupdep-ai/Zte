/* Dell BIOS master-password keygen — faithful JS port of dell_keygen48.py
 * (48-family corpus keygen; legacy constructions validated against
 * pwgen-for-bios vectors, CF1B firmware path validated by module execution).
 * Tables are auto-extracted from the Python original (zero transcription).
 */
"use strict";
const TABLES = {"md5magic": [3614090360, 3905402710, 606105819, 3250441966, 4118548399, 1200080426, 2821735955, 4249261313, 1770035416, 2336552879, 4294925233, 2304563134, 1804603682, 4254626195, 2792965006, 1236535329, 4129170786, 3225465664, 643717713, 3921069994, 3593408605, 38016083, 3634488961, 3889429448, 568446438, 3275163606, 4107603335, 1163531501, 2850285829, 4243563512, 1735328473, 2368359562, 4294588738, 2272392833, 1839030562, 4259657740, 2763975236, 1272893353, 4139469664, 3200236656, 681279174, 3936430074, 3572445317, 76029189, 3654602809, 3873151461, 530742520, 3299628645, 4096336452, 1126891415, 2878612391, 4237533241, 1700485571, 2399980690, 4293915773, 2240044497, 1873313359, 4264355552, 2734768916, 1309151649, 4149444226, 3174756917, 718787259, 3951481745], "md5magic2": [3614090360, 3905402710, 606105819, 3250441966, 4118548399, 1200080426, 2821735955, 4249261313, 1770035416, 2336552879, 4294925233, 2304563134, 1804603682, 4254626195, 2792965006, 1236535329, 4129170786, 3225465664, 643717713, 3921069994, 3593408605, 38016083, 3634488961, 3889429448, 568446438, 3275163606, 4107603335, 1163531501, 2850285829, 4243563512, 1735328473, 2368359562, 3654602809, 3873151461, 530742520, 3299628645, 681279174, 3936430074, 3572445317, 76029189, 2763975236, 1272893353, 4139469664, 3200236656, 4294588738, 2272392833, 1839030562, 4259657740, 4149444226, 3174756917, 718787259, 3951481745, 1873313359, 4264355552, 2734768916, 1309151649, 1700485571, 2399980690, 4293915773, 2240044497, 4096336452, 1126891415, 2878612391, 4237533241], "rotationTable": [[7, 12, 17, 22], [5, 9, 14, 20], [4, 11, 16, 23], [6, 10, 15, 21]], "initialData": [1732584193, 4023233417, 2562383102, 271733878], "T72": ["0", "Q", "2", "d", "r", "G", "k", "9", "9", "r", "k", "Q", "F", "M", "x", "N", "[", "Z", "5", "y", "3", "D", "G", "r", "1", "6", "h", "6", "3", "8", "m", "y", "I", "L", "2", "r", "z", "z", "2", "p", "z", "c", "U", "7", "J", "W", "L", "J", "1", "E", "G", "n", "q", "R", "N", "4", "s", "e", "Z", "P", "R", "M", "2", "a", "B", "X", "I", "j", "b", "k", "G", "Z"], "E7A8_TABLE": ["Q", "9", "2", "G", "0", "d", "r", "k", "9", "y", "6", "3", "r", "5", "D", "G", "1", "h", "L", "q", "J", "G", "W", "1", "E", "n", "R", "k", "[", "Q", "x", "r", "F", "M", "N", "Z", "3", "2", "8", "I", "6", "m", "y", "L", "r", "4", "M", "s", "P", "N", "e", "Z", "R", "2", "z", "7", "2", "c", "z", "p", "z", "U", "J", "B", "G", "X", "b", "a", "I", "j", "k", "Z"], "ENCSCANS": [5, 16, 19, 9, 50, 3, 37, 17, 31, 23, 6, 21, 48, 25, 38, 34, 10, 2, 44, 47, 22, 20, 7, 24, 36, 35, 49, 32, 30, 8, 45, 33, 4, 11, 18, 46], "SCAN_CODES": [0, 27, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 45, 61, 8, 9, 113, 119, 101, 114, 116, 121, 117, 105, 111, 112, 91, 93, 13, 255, 97, 115, 100, 102, 103, 104, 106, 107, 108, 59, 39, 96, 255, 92, 122, 120, 99, 118, 98, 110, 109, 44, 46, 47], "EXTRA_CHARACTERS": {"2A7B": ["0", "1", "2", "3", "4", "5", "6", "7", "9", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0"], "1F5A": ["0", "1", "2", "3", "4", "5", "6", "7", "9", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0"], "1D3B": ["0", "B", "f", "I", "U", "G", "1", "k", "u", "P", "v", "c", "8", "A", "9", "N", "l", "5", "D", "L", "Z", "Y", "S", "n", "o", "7", "K", "a", "6", "H", "M", "g", "q", "s", "J", "W", "m", "6", "5", "y", "C", "Q", "R", "9", "4", "b", "2", "1", "O", "T", "p", "7", "V", "F", "X", "2", "z", "0", "j", "i", "h", "E", "3", "3", "d", "4", "x", "t", "r", "e", "w", "0"], "1F66": ["0", "e", "w", "r", "3", "d", "4", "x", "t", "U", "G", "1", "k", "u", "0", "B", "f", "I", "p", "7", "V", "F", "b", "2", "1", "O", "T", "S", "n", "o", "7", "K", "D", "L", "Z", "Y", "q", "s", "J", "W", "a", "6", "H", "M", "g", "C", "Q", "R", "9", "4", "m", "6", "5", "y", "9", "N", "l", "5", "P", "v", "c", "8", "A", "j", "i", "h", "E", "3", "X", "2", "z", "0"], "6FF1": ["0", "8", "r", "p", "t", "B", "x", "f", "b", "G", "V", "M", "z", "3", "8", "I", "i", "S", "o", "e", "b", "3", "6", "0", "M", "K", "c", "L", "f", "4", "Q", "t", "B", "C", "b", "W", "V", "z", "m", "H", "5", "w", "m", "Z", "U", "c", "R", "R", "5", "D", "Z", "G", "2", "x", "N", "C", "E", "v", "1", "n", "F", "t", "z", "s", "Z", "B", "2", "b", "w", "1", "X", "0"], "BF97": ["0", "Q", "2", "d", "r", "G", "k", "9", "9", "r", "k", "Q", "F", "M", "x", "N", "[", "Z", "5", "y", "3", "D", "G", "r", "1", "6", "h", "6", "3", "8", "m", "y", "I", "L", "2", "r", "z", "z", "2", "p", "z", "c", "U", "7", "J", "W", "L", "J", "1", "E", "G", "n", "q", "R", "N", "4", "s", "e", "Z", "P", "R", "M", "2", "a", "B", "X", "I", "j", "b", "k", "G", "Z"]}, "ALT72": ["0", "1", "2", "3", "4", "5", "6", "7", "9", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0"]};

const M = 0xFFFFFFFF;
const mask32 = (x) => x >>> 0;
const rol = (x, b) => { x >>>= 0; b &= 31; return ((x << b) | (x >>> (32 - b))) >>> 0; };
const ror = (x, b) => { x >>>= 0; b &= 31; return ((x >>> b) | (x << (32 - b))) >>> 0; };
const rol8 = (x, b) => { x &= 0xff; b &= 7; return ((x << b) | (x >> (8 - b))) & 0xff; };

const encF1 = (a, b) => (a + b) >>> 0;
const encF1N = (a, b) => (a - b) >>> 0;
const encF2 = (a, b, c) => (((c ^ b) & a) ^ c) >>> 0;
const encF2N = (a, b, c) => encF2(a, b, ~c >>> 0);
const encF3 = (a, b, c) => (((a ^ b) & c) ^ b) >>> 0;
const encF4 = (a, b, c) => ((b ^ a) ^ c) >>> 0;
const encF4N = (a, b, c) => encF4(a, ~b >>> 0, c);
const encF5 = (a, b, c) => ((a | (~c >>> 0)) ^ b) >>> 0;
const encF5N = (a, b, c) => encF5(~a >>> 0, b, c);

function intArrayToByte(arr) {
  const out = [];
  for (const num of arr) {
    out.push(num & 0xff, (num >>> 8) & 0xff, (num >>> 16) & 0xff, (num >>> 24) & 0xff);
  }
  return out;
}
function byteArrayToInt(arr) {
  const out = [];
  for (let i = 0; i < Math.ceil(arr.length / 4); i++) {
    let v = 0;
    for (let k = 0; k < 4; k++) if (i * 4 + k < arr.length) v |= arr[i * 4 + k] << (8 * k);
    out.push(v >>> 0);
  }
  return out;
}

/* base encoder: MD5-variant rounds with per-family F-set + table */
function Enc(encBlock, opts) {
  this.f1 = opts.f1; this.f2 = opts.f2; this.f3 = opts.f3;
  this.f4 = opts.f4; this.f5 = opts.f5;
  this.md5table = opts.md5table;
  this.init = opts.init || TABLES.initialData;
  this.encBlock = encBlock;
  this.encData = this.init.slice();
  this.A = this.encData[0]; this.B = this.encData[1];
  this.C = this.encData[2]; this.D = this.encData[3];
}
Enc.prototype.calc = function (func, key1, key2) {
  const tmp = func(this.B, this.C, this.D);
  const combined = (this.md5table[key2] + this.encBlock[key1]) >>> 0;
  return (this.A + this.f1(tmp, combined)) >>> 0;
};
Enc.prototype.shuffle = function (t, shift) {   // A,D,C = D,C,B ; B += rol(t,shift)
  const nA = this.D, nD = this.C, nC = this.B;
  this.A = nA; this.D = nD; this.C = nC;
  this.B = (this.B + rol(t, shift)) >>> 0;
};
Enc.prototype.incrementData = function () {
  this.encData[0] = (this.encData[0] + this.A) >>> 0;
  this.encData[1] = (this.encData[1] + this.B) >>> 0;
  this.encData[2] = (this.encData[2] + this.C) >>> 0;
  this.encData[3] = (this.encData[3] + this.D) >>> 0;
};
Enc.prototype.result = function () { return this.encData.map(mask32); };

const ROT = TABLES.rotationTable;
const F_N = { f1: encF1N, f2: encF2N, f3: encF3, f4: encF4N, f5: encF5N };   // 595B set
const F_P = { f1: encF1, f2: encF2, f3: encF3, f4: encF4, f5: encF5 };       // D35B set

/* --- 595B: 64 rounds, key2 = i --- */
function make595B(o) {
  for (let i = 0; i < 64; i++) {
    const w = i >> 4;
    let t;
    if (w === 0) t = o.calc(o.f2, i & 15, i);
    else if (w === 1) t = o.calc(o.f3, (i * 5 + 1) & 15, i);
    else if (w === 2) t = o.calc(o.f4, (i * 3 + 5) & 15, i);
    else t = o.calc(o.f5, (i * 7) & 15, i);
    o.shuffle(t, ROT[w][i & 3]);
  }
  o.incrementData();
}
const enc595B = { ...F_N, md5table: TABLES.md5magic, make: make595B };
const enc595BSorted = { ...F_N, md5table: TABLES.md5magic2, make: make595B }; // fnA alt
const encD35B = { ...F_P, md5table: TABLES.md5magic, make: make595B };

/* --- 1D3B: 21 x (595B rounds) with pre-op constants --- */
function make1D3B(o) {
  for (let j = 0; j < 21; j++) {
    o.A |= 0x97; o.B ^= 0x8;
    o.C |= mask32(0x60606161 - j); o.D ^= mask32(0x50501010 + j);
    make595B(o);
  }
}
const enc1D3B = { ...F_N, md5table: TABLES.md5magic, make: make1D3B };

/* --- 6FF1 / BF97: counter1 x 64 + 17 x 64 --- */
function make6FF1(counter1) {
  return (o) => {
    for (let j = 0; j < counter1; j++) {
      o.A |= 0xA08097; o.B ^= 0xA010908;
      o.C |= (0x60606161 - j) >>> 0; o.D ^= (0x50501010 + j) >>> 0;
      for (let i = 0; i < 64; i++) {
        const w = i >> 4;
        const k = (i & 15) - ((i & 12) << 1) + 12;
        let t;
        if (w === 0) t = o.calc(o.f2, i & 15, (i + 32) >>> 0);
        else if (w === 1) t = o.calc(o.f3, (i * 5 + 1) & 15, i & 15);
        else if (w === 2) t = o.calc(o.f4, (i * 3 + 5) & 15, (k + 16) >>> 0);
        else t = o.calc(o.f5, (i * 7) & 15, (k + 48) >>> 0);
        o.shuffle(t, ROT[w][i & 3]);
      }
      o.incrementData();
    }
    for (let j = 0; j < 17; j++) {
      o.A |= 0x100097; o.B ^= 0xA0008;
      o.C |= (0x50501010 - j) >>> 0; o.D ^= (0x60606161 + j) >>> 0;
      for (let i = 0; i < 64; i++) {
        const w = i >> 4;
        const k = (i & 15) - ((i & 12) << 1) + 12;
        let t;
        if (w === 0) t = o.calc(o.f4, ((i & 15) * 3 + 5) & 15, k + 16);
        else if (w === 1) t = o.calc(o.f5, ((i & 3) * 7 + (i & 12) + 4) & 15, (i & 15) + 32);
        else if (w === 2) t = o.calc(o.f2, k & 15, k);
        else t = o.calc(o.f3, ((i & 15) * 5 + 1) & 15, (i & 15) + 48);
        const g = ((i >> 4) + 2) & 3;
        o.shuffle(t, ROT[g][i & 3]);
      }
      o.incrementData();
    }
  };
}
const enc6FF1 = { ...F_N, md5table: TABLES.md5magic2, make: make6FF1(23) };
const encBF97 = { ...F_N, md5table: TABLES.md5magic2, make: make6FF1(31) };

/* --- 1F66: 17x64 + 21x64, md5magic2 --- */
function make1F66(o) {
  for (let j = 0; j < 17; j++) {
    o.A |= 0x100097; o.B ^= 0xA0008;
    o.C |= mask32(0x60606161 - j); o.D ^= mask32(0x50501010 + j);
    for (let i = 0; i < 64; i++) {
      const w = i >> 4;
      let t;
      if (w === 0) t = o.calc(o.f2, i & 15, mask32(i + 16));
      else if (w === 1) t = o.calc(o.f3, (i * 5 + 1) & 15, mask32(i + 32));
      else if (w === 2) t = o.calc(o.f4, (i * 3 + 5) & 15, mask32(i - 2 * (i & 12) + 12));
      else t = o.calc(o.f5, (i * 7) & 15, mask32(2 * (i & 3) - (i & 15) + 12));
      o.shuffle(t, ROT[w][i & 3]);
    }
    o.incrementData();
  }
  for (let j = 0; j < 21; j++) {
    o.A |= 0x97; o.B ^= 0x8;
    o.C |= mask32(0x50501010 - j); o.D ^= mask32(0x60606161 + j);
    for (let i = 0; i < 64; i++) {
      const w = i >> 4;
      let t;
      if (w === 0) t = o.calc(o.f4, (i * 3 + 5) & 15, mask32(2 * (i & 3) - i + 44));
      else if (w === 1) t = o.calc(o.f5, (i * 7) & 15, mask32(2 * (i & 3) - i + 76));
      else if (w === 2) t = o.calc(o.f2, i & 15, i & 15);
      else t = o.calc(o.f3, (i * 5 + 1) & 15, mask32(i - 32));
      const g = w + 2;
      o.shuffle(t, ROT[g & 3][i & 3]);
    }
    o.incrementData();
  }
}
const enc1F66 = { ...F_N, md5table: TABLES.md5magic2, make: make1F66 };

/* --- 1F5A: 5 x 64, custom register order + custom calc/increment --- */
const enc1F5A = {
  ...F_N, md5table: TABLES.md5magic2,
  make: function (o) {
    for (let r = 0; r < 5; r++) {
      for (let j = 0; j < 64; j++) {
        const w = j >> 4;
        const k = 12 + (j & 3) - (j & 12);
        let t;
        if (w === 0) t = o.calc1F5A(o.f2, j & 15, j);
        else if (w === 1) t = o.calc1F5A(o.f3, (j * 5 + 1) & 15, j);
        else if (w === 2) t = o.calc1F5A(o.f4, (j * 3 + 5) & 15, mask32(k + 0x20));
        else t = o.calc1F5A(o.f5, (j * 7) & 15, mask32(k + 0x30));
        // B,D,A,C = D,A,C, mask32(C + rol(t, rot))
        const nB = o.D, nD = o.A, nA = o.C;
        const nC = (o.C + rol(t, ROT[w][j & 3])) >>> 0;
        o.B = nB; o.D = nD; o.A = nA; o.C = nC;
      }
      // swapped accumulation
      o.encData[0] = (o.encData[0] + o.B) >>> 0;
      o.encData[1] = (o.encData[1] + o.C) >>> 0;
      o.encData[2] = (o.encData[2] + o.A) >>> 0;
      o.encData[3] = (o.encData[3] + o.D) >>> 0;
    }
  },
};
/* 1F5A's calculate uses (C,A,D) and B: patched onto the object in encode() */

/* --- E7A8 (+ second): shortcut loops, init [0,0,0,0] --- */
function makeE7A8(loopParams) {
  return (o) => {
    const ep = [0x50501010, 0xA010908, 0xA08097, 0x60606161,
                0x60606161, 0xA0008, 0x100097, 0x50501010];
    const lp = loopParams;
    const sc = (fun, j, md5i, rotIdx, idxs) => {
      for (let i = 0; i < 4; i++) {
        const t = o.calc(fun, (j + idxs[i]) & 7, md5i + i);
        o.shuffle(t, ROT[rotIdx][i]);
      }
    };
    for (let p = 0; p < lp[0]; p++) {
      o.A |= ep[0]; o.B ^= ep[1];
      o.C |= (ep[2] - p) >>> 0; o.D ^= (ep[3] + p) >>> 0;
      for (let j = 0; j < lp[2]; j += 4) sc(o.f2, j, j + 32, 0, [0, 1, 2, 3]);
      for (let j = 0; j < lp[2]; j += 4) sc(o.f3, j, j, 1, [1, -2, -1, 0]);
      for (let j = lp[3]; j > 3; j -= 4) sc(o.f4, j, j + 16, 2, [-3, -4, -1, 2]);
      for (let j = lp[3]; j > 3; j -= 4) sc(o.f5, j, j + 48, 3, [2, 3, 2, -3]);
      o.incrementData();
    }
    for (let p = 0; p < lp[1]; p++) {
      o.A |= ep[4]; o.B ^= ep[5];
      o.C |= (ep[6] - p) >>> 0; o.D ^= (ep[7] + p) >>> 0;
      for (let j = lp[3]; j > 3; j -= 4) sc(o.f4, j, j + 16, 2, [-3, -4, -1, 2]);
      for (let j = 0; j < lp[2]; j += 4) sc(o.f5, j, j + 32, 3, [2, 3, 2, -3]);
      for (let j = lp[3]; j > 0; j -= 4) sc(o.f2, j, j, 0, [0, 1, 2, 3]);
      for (let j = 0; j < lp[2]; j += 4) sc(o.f3, j, j + 48, 1, [1, -2, 3, 0]);
      o.incrementData();
    }
  };
}
const encE7A8 = { ...F_N, md5table: TABLES.md5magic2, init: [0, 0, 0, 0], make: makeE7A8([17, 13, 12, 8]) };
const encE7A8Second = {
  ...F_N, init: [0, 0, 0, 0], make: makeE7A8([17, 13, 12, 16]),
  md5table: null, // set at encode time: md5magic2 + 4 overfill entries
};

function encodeWith(opts, encBlock) {
  const o = Object.create(Enc.prototype);
  const table = opts.md5table || TABLES.md5magic2;
  Enc.call(o, encBlock, { ...opts, md5table: table });
  o.calc1F5A = function (func, key1, key2) {   // 1F5A variant
    const tmp = func(this.C, this.A, this.D);
    const combined = (this.md5table[key2 % this.md5table.length] + this.encBlock[key1]) >>> 0;
    return (this.B + this.f1(tmp, combined)) >>> 0;
  };
  opts.make(o);
  return o.result();
}

const LEGACY_ENCODERS = {
  "595B": enc595B, "2A7B": enc595B, "A95B": enc595B,
  "1D3B": enc1D3B, "D35B": encD35B, "1F66": enc1F66,
  "6FF1": enc6FF1, "1F5A": enc1F5A, "BF97": encBF97,
};

/* ---------------- suffix calculation (firmware 0x7d84) ---------------- */
function calculateSuffixFW(tag, table, mod, arr) {
  if (arr === undefined || arr === null) {
    const b = Array.from(tag, (c) => c.charCodeAt(0));
    arr = [b[4], b[3], b[2], b[1], b[0]];
  }
  const sfx = new Array(8).fill(0);
  sfx[0] = arr[0] & 0x1f;
  sfx[1] = ((rol8(arr[1], 3) & 0xf1) | (arr[0] >> 5)) & 0x1f;
  sfx[2] = (arr[1] >> 2) & 0x1f;
  sfx[3] = (((arr[2] & 0xf) << 1) | (arr[1] >> 7)) & 0xff;
  sfx[4] = (((arr[3] & 1) << 4) | (arr[2] >> 4)) & 0xff;
  sfx[5] = (arr[3] >> 1) & 0x1f;
  sfx[6] = (((arr[4] & 7) << 2) | (arr[3] >> 6)) & 0xff;
  sfx[7] = (arr[4] >> 3) & 0xff;
  const out = [];
  for (let i = 0; i < 8; i++) {
    let r = 0xaa;
    if (sfx[i] & 1) r ^= arr[0];
    if (sfx[i] & 2) r ^= arr[1];
    if (sfx[i] & 4) r ^= arr[2];
    if (sfx[i] & 8) r ^= arr[3];
    if (sfx[i] & 16) r ^= arr[4];
    out.push(table[(r & 0xff) % mod]);
  }
  return out;   // array of chars (Python returned a string)
}

function md5PadBlock(msg23) {   // 23-byte message -> 16 u32 block
  const block = Array.from(msg23, (c) => typeof c === "number" ? c : c.charCodeAt(0));
  while (block.length < 23) block.push(0);
  block.length = 23;
  while (block.length < 24) block.push(0);
  block[23] = 0x80;
  while (block.length < 64) block.push(0);
  const encBlock = byteArrayToInt(block);
  encBlock[14] = 23 << 3;
  return encBlock;
}

function legacyPad(arr) {
  const a = arr.slice();
  while (a.length <= 23) a.push(0);
  a[23] = 0x80;
  const enc = [];
  for (let i = 0; i < a.length / 4; i++) {
    enc.push((a[i * 4] | (a[i * 4 + 1] << 8) | (a[i * 4 + 2] << 16) | (a[i * 4 + 3] << 24)) >>> 0);
  }
  while (enc.length < 16) enc.push(0);
  enc[14] = 23 << 3;
  enc[15] = 0;
  return enc;
}

function resultToString(arr16, tag) {
  const r = arr16[0] % 9;
  let out = "";
  const table = TABLES.EXTRA_CHARACTERS[tag];
  for (let i = 0; i < 16; i++) {
    if (table !== undefined) {
      out += table[arr16[i] % table.length];
    } else if (r <= i && out.length < 8) {
      out += String.fromCharCode(TABLES.SCAN_CODES[TABLES.ENCSCANS[arr16[i] % TABLES.ENCSCANS.length]]);
    }
  }
  return out;
}

/* ---------------- keygens ---------------- */
function keygenDellLegacy(serial, tag) {
  tag = tag.toUpperCase();
  serial = serial.toUpperCase();
  let full;
  if (tag === "A95B") full = serial + "595B";
  else full = serial + tag;
  if (tag === "E7A8") return keygenE7A8(serial);
  const opts = LEGACY_ENCODERS[tag];
  if (!opts) throw new Error("unsupported suffix " + tag);
  const fullArr = Array.from(full, (c) => c.charCodeAt(0));
  const arr = [fullArr[4], fullArr[3], fullArr[2], fullArr[1], fullArr[0]]; // service mode
  let sfx;
  if (TABLES.EXTRA_CHARACTERS[tag] !== undefined) {
    sfx = calculateSuffixFW(full, TABLES.EXTRA_CHARACTERS[tag], 72, arr);
  } else {
    const encTab = TABLES.ENCSCANS.map((x) => String.fromCharCode(x));
    sfx = calculateSuffixFW(full, encTab, 36, arr);
  }
  const encBlock = legacyPad(fullArr.concat(sfx.map((c) => typeof c === "string" ? c.charCodeAt(0) : c)));
  const enc16 = intArrayToByte(encodeWith(opts, encBlock));
  const pw = resultToString(enc16, tag);
  return pw ? [pw] : [];
}

function keygenCf1b(tag) {
  tag = tag.toUpperCase();
  tag = Array.from(tag, (c) => (c.charCodeAt(0) > 0x20 && c.charCodeAt(0) <= 0x7e) ? c : "*").join("");
  const sfx = calculateSuffixFW(tag, TABLES.T72, 72).join("");
  const data = (tag + "BF97" + sfx);
  const encBlock = md5PadBlock(data);
  const enc = encodeWith(encBF97, encBlock);
  const enc16 = intArrayToByte(enc);
  return TABLES.T72.map((ch, i) => i < 16 ? TABLES.T72[enc16[i] % 72] : null).slice(0, 16).join("");
}

function keygenCf1bAltFnA(tag) {
  tag = tag.toUpperCase();
  const fs = tag + "2A7B";
  const arr = [fs.charCodeAt(8), fs.charCodeAt(9), fs.charCodeAt(10), fs.charCodeAt(1), fs.charCodeAt(0)];
  const ascii72 = TABLES.ALT72;  // inline firmware alphabet (differs from T72!)
  const sfx = calculateSuffixFW(tag, ascii72, 72, arr).join("");
  const data = fs + sfx;
  const encBlock = md5PadBlock(data);
  const enc16 = intArrayToByte(encodeWith(enc595BSorted, encBlock));
  let out = "";
  for (let i = 0; i < 16; i++) out += ascii72[enc16[i] % 72];
  return out;
}

/* --- SHA-256 (sync, standalone) --- */
const SHA_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
function sha256Bytes(bytes) {
  const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const msg = bytes.slice();
  const bitLen = bytes.length * 8;
  msg.push(0x80);
  while (msg.length % 64 !== 56) msg.push(0);
  for (let i = 7; i >= 0; i--) msg.push((bitLen / Math.pow(2, i * 8)) & 0xff);
  const w = new Array(64);
  for (let off = 0; off < msg.length; off += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = ((msg[off + i * 4] << 24) | (msg[off + i * 4 + 1] << 16) |
              (msg[off + i * 4 + 2] << 8) | msg[off + i * 4 + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i++) {
      const s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + SHA_K[i] + w[i]) >>> 0;
      const S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  const out = [];
  for (const x of h) out.push((x >>> 24) & 0xff, (x >>> 16) & 0xff, (x >>> 8) & 0xff, x & 0xff);
  return out;
}

function keygenE7A8(serial) {
  const fullSerial = serial.toUpperCase() + "E7A8";
  const arr = Array.from(fullSerial, (c) => c.charCodeAt(0));
  let encBlock = byteArrayToInt(arr);
  while (encBlock.length < 16) encBlock.push(0);
  const outs = [];
  const tables = [TABLES.md5magic2,
                  TABLES.md5magic2.concat([
                    (0xa0008 ^ 0x6d2f93a5) >>> 0, (0xa08097 ^ 0x6d2f93a5) >>> 0,
                    (0xa010908 ^ 0x6d2f93a5) >>> 0, (0x60606161 ^ 0x6d2f93a5) >>> 0])];
  const makes = [makeE7A8([17, 13, 12, 8]), makeE7A8([17, 13, 12, 16])];
  for (let k = 0; k < 2; k++) {
    const opts = { ...F_N, md5table: tables[k], init: [0, 0, 0, 0], make: makes[k] };
    const encoded = encodeWith(opts, encBlock);
    const res = intArrayToByte(encoded);
    const digest = sha256Bytes(res);
    let out = "";
    for (let i = 0; i < 16; i++) {
      out += TABLES.E7A8_TABLE[(digest[i + 16] + digest[i]) % TABLES.E7A8_TABLE.length];
    }
    outs.push(out);
  }
  return outs;
}

/* ---------------- public API ---------------- */
function keygen(tag, suffix) {
  suffix = suffix.toUpperCase();
  if (suffix === "CF1B" || suffix === "FC1B") {
    return [
      { label: "PRIMARY — CF1B firmware path (BF97 construction; pre-gate firmware era)", pw: keygenCf1b(tag) },
      { label: "ALTERNATE — fnA-2A7B-legacy", pw: keygenCf1bAltFnA(tag) },
      { label: "ALTERNATE — E7A8 #1", pw: keygenE7A8(tag)[0] },
      { label: "ALTERNATE — E7A8 #2", pw: keygenE7A8(tag)[1] },
    ];
  }
  const pws = keygenDellLegacy(tag, suffix);
  return pws.map((pw, i) => ({
    label: pws.length > 1 ? `candidate ${i + 1}` : `legacy ${suffix} master`,
    pw,
  }));
}

if (typeof module !== "undefined") {
  module.exports = { keygen, keygenDellLegacy, keygenCf1b, keygenCf1bAltFnA, keygenE7A8, sha256Bytes };
}
