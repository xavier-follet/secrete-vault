'use strict';
/**
 * Generates build/icon.png (512x512 RGBA): the vault's combination dial on a
 * green-black enamel tile, with the gold index mark. Pure Node (zlib), no
 * dependencies, 4x4 supersampled for smooth edges. electron-builder converts the
 * PNG to .ico for the Windows exe automatically.
 * Run: node scripts/make-icon.js            (writes build/icon.png)
 *      node scripts/make-icon.js 48 out.png (any size, for previews)
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const S = Number(process.argv[2]) || 512;
const OUT = process.argv[3] || path.join(__dirname, '..', 'build', 'icon.png');
const N = 4; // subsamples per axis

const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const TILE = hex('#0f1613'), RIM = hex('#2b3a33'), DISC = hex('#1b2822');
const IVORY = hex('#e6e9e2'), IVORY_DIM = hex('#b9c2b7');
const KNOB = hex('#1f2d26'), KNURL = hex('#34463c'), CAP = hex('#0b110e'), GOLD = hex('#d8b45f');

const C = 256; // everything is designed on a 512 grid and scaled by S/512

// rounded-rect signed distance (negative = inside)
function rr(x, y, w, h, rad) {
  const dx = Math.max(Math.abs(x - C) - (w / 2 - rad), 0);
  const dy = Math.max(Math.abs(y - C) - (h / 2 - rad), 0);
  return Math.hypot(dx, dy) - rad;
}

// point inside the upward-pointing index triangle (apex top)
function inIndex(x, y) {
  const top = 116, bottom = 166, half = 25;
  if (y < top || y > bottom) return false;
  return Math.abs(x - C) <= (half * (y - top)) / (bottom - top);
}

/** Colour of one sample point on the 512 grid, or null if transparent. */
function shade(x, y) {
  const tile = rr(x, y, 512, 512, 112);
  if (tile > 0) return null;
  let col = tile > -4 ? RIM : TILE;

  const dx = x - C, dy = y - C;
  const d = Math.hypot(dx, dy);
  const ang = (Math.atan2(dx, -dy) + Math.PI * 2) % (Math.PI * 2); // 0 = 12 o'clock, clockwise

  if (d <= 212) col = DISC;

  // 60 ticks, every 5th a long ivory one
  if (d >= 150 && d <= 204) {
    const step = (Math.PI * 2) / 60;
    const k = Math.round(ang / step);
    const off = Math.abs(ang - k * step) * d; // arc distance to the nearest tick
    const major = k % 5 === 0;
    if (major ? d >= 152 && off <= 4.5 : d >= 178 && off <= 2.2) col = major ? IVORY : IVORY_DIM;
  }
  if (Math.abs(d - 144) <= 1.5) col = RIM;

  // knob with a knurled edge
  if (d <= 134) {
    col = KNOB;
    if (d >= 112) col = Math.floor(ang / ((Math.PI * 2) / 56)) % 2 === 0 ? KNURL : KNOB;
  }
  if (d <= 96) col = d >= 93.5 ? RIM : CAP;

  // keyhole: round head plus a widening stem
  if (Math.hypot(x - C, y - 240) <= 24 || (y >= 250 && y <= 306 && Math.abs(x - C) <= 9 + (y - 250) * 0.14)) {
    if (d <= 92) col = IVORY;
  }

  if (inIndex(x, y)) col = GOLD;
  return col;
}

const px = Buffer.alloc(S * S * 4);
const scale = 512 / S;
for (let py = 0; py < S; py++) {
  for (let pxl = 0; pxl < S; pxl++) {
    let r = 0, g = 0, b = 0, a = 0;
    for (let sy = 0; sy < N; sy++) {
      for (let sx = 0; sx < N; sx++) {
        const c = shade((pxl + (sx + 0.5) / N) * scale, (py + (sy + 0.5) / N) * scale);
        if (c) { r += c[0]; g += c[1]; b += c[2]; a += 1; }
      }
    }
    const i = (py * S + pxl) * 4;
    if (a) { px[i] = r / a; px[i + 1] = g / a; px[i + 2] = b / a; px[i + 3] = Math.round((a / (N * N)) * 255); }
  }
}

/* ---------- minimal PNG encoder ---------- */
const crcTable = [];
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  crcTable[n] = c >>> 0;
}
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const out = Buffer.alloc(8 + data.length + 4);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.slice(4, 8 + data.length)), 8 + data.length);
  return out;
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(S, 0);
ihdr.writeUInt32BE(S, 4);
ihdr[8] = 8;  // bit depth
ihdr[9] = 6;  // color type RGBA

const raw = Buffer.alloc(S * (1 + S * 4));
for (let y = 0; y < S; y++) {
  raw[y * (1 + S * 4)] = 0; // filter: none
  px.copy(raw, y * (1 + S * 4) + 1, y * S * 4, (y + 1) * S * 4);
}

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, png);
console.log('wrote', OUT, png.length, 'bytes');
