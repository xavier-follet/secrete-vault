'use strict';
/**
 * TOTP (RFC 6238) / HOTP (RFC 4226) + base32 (RFC 4648) helpers.
 * Pure Node crypto — no dependencies.
 */
const crypto = require('crypto');

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = str.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Invalid base32 character: ' + ch);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Generate a random TOTP secret, base32 encoded (160 bits). */
function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

/** HOTP: 6-digit code for a given counter. */
function hotp(secretBase32, counter, digits = 6) {
  const key = base32Decode(secretBase32);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(bin % 10 ** digits).padStart(digits, '0');
}

/** TOTP code at a given time (ms since epoch), default 30s step. */
function totp(secretBase32, timeMs = Date.now(), step = 30, digits = 6) {
  return hotp(secretBase32, Math.floor(timeMs / 1000 / step), digits);
}

/** Verify a user-entered code, allowing +/- window steps of clock drift. */
function verifyTotp(secretBase32, code, window = 1, timeMs = Date.now(), step = 30, digits = 6) {
  const clean = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6,8}$/.test(clean)) return false;
  const counter = Math.floor(timeMs / 1000 / step);
  for (let w = -window; w <= window; w++) {
    if (hotp(secretBase32, counter + w, digits) === clean) return true;
  }
  return false;
}

/** otpauth:// URL understood by Google Authenticator, Authy, 1Password, etc. */
function otpauthUrl(secretBase32, issuer, account) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = `secret=${secretBase32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  return `otpauth://totp/${label}?${params}`;
}

module.exports = {
  base32Encode,
  base32Decode,
  generateTotpSecret,
  hotp,
  totp,
  verifyTotp,
  otpauthUrl,
};
