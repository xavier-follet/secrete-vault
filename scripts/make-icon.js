'use strict';
/**
 * Generates build/icon.png (512x512 RGBA) — a simple lock glyph on a rounded
 * dark tile. Pure Node (zlib), no dependencies. electron-builder converts the
 * PNG to .ico for the Windows exe automatically.
 * Run: node scripts/make-icon.js
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const S = 512;
const px = new Uint8Array(S * S * 4); // RGBA, starts transparent

function set(x, y, r, g, b, a) {
  if (x < 0 || y < 0 || x >= S || y >= S) return;
  const i = (y * S + x) * 4;
  px[i] = r; px[i + 1] = g; px[i + 2] = b; px[i + 3] = a;
}

// rounded-rect SDF (negative = inside)
function rr(x, y, cx, cy, w, h, rad) {
  const dx = Math.max(Math.abs(x - cx) - (w / 2 - rad), 0);
  const dy = Math.max(Math.abs(y - cy) - (h / 2 - rad), 0);
  return Math.hypot(dx, dy) - rad;
}

const BG = [23, 26, 35];        // #171a23 tile
const ACCENT = [108, 140, 255]; // #6c8cff lock

for (let y = 0; y < S; y++) {
  for (let x = 0; x < S; x++) {
    // tile: rounded square with 96px corner radius
    if (rr(x, y, S / 2, S / 2, S, S, 96) <= 0) set(x, y, ...BG, 255);

    // shackle: ring (outer r=110, inner r=64) centered at (256, 218), upper half
    const dShackle = Math.hypot(x - 256, y - 218);
    if (y <= 218 && dShackle <= 110 && dShackle >= 64) set(x, y, ...ACCENT, 255);

    // body: rounded rect 250x190 centered at (256, 330)
    if (rr(x, y, 256, 330, 250, 190, 34) <= 0) set(x, y, ...ACCENT, 255);

    // keyhole: circle at (256, 310) r=30 + stem rect below, punched in tile color
    const dKey = Math.hypot(x - 256, y - 310);
    if (dKey <= 30 || (Math.abs(x - 256) <= 16 && y > 310 && y < 372)) {
      set(x, y, ...BG, 255);
    }
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
ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;

const raw = Buffer.alloc(S * (1 + S * 4));
for (let y = 0; y < S; y++) {
  raw[y * (1 + S * 4)] = 0; // filter: none
  Buffer.from(px.buffer, y * S * 4, S * 4).copy(raw, y * (1 + S * 4) + 1);
}

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);

const outDir = path.join(__dirname, '..', 'build');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'icon.png'), png);
console.log('wrote build/icon.png', png.length, 'bytes');
