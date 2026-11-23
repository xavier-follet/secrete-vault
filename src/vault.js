'use strict';
/**
 * Secrete Vault — encrypted-at-rest storage core.
 *
 * File format (single JSON document, written atomically, mode 0600):
 * {
 *   version, createdAt,
 *   kdf:     { name:'scrypt', N, r, p, salt },            // password KDF params
 *   keyWrap: AES-256-GCM( scrypt(password, salt), masterKey ),
 *   check:   AES-256-GCM( masterKey, CHECK_CONSTANT ),     // verifies the master key
 *   payload: AES-256-GCM( masterKey, JSON.stringify(data) ),
 *   recovery: [ { id, salt, hash, wrap: AES-256-GCM(scrypt(code,salt), masterKey) } ]
 * }
 *
 * The random 32-byte masterKey encrypts the payload directly, so changing the
 * master password or consuming recovery codes never requires re-encrypting
 * the secrets — only the wraps change. Each recovery code is single-use.
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {
  generateTotpSecret, verifyTotp, otpauthUrl,
} = require('./totp');
const { parseAttestation, verifyAssertion } = require('./webauthn');

const VERSION = 1;
const CHECK = Buffer.from('secrete-vault:v1:master-key-check');
const KDF = { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 }; // scrypt
const RECOVERY_CODE_COUNT = 10;
const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I/L

const b64 = (b) => Buffer.from(b).toString('base64');
const ub64 = (s) => Buffer.from(s, 'base64');

function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([c.update(plaintext), c.final()]);
  return { iv: b64(iv), tag: b64(c.getAuthTag()), data: b64(data) };
}

function decrypt(key, box) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, ub64(box.iv));
  d.setAuthTag(ub64(box.tag));
  return Buffer.concat([d.update(ub64(box.data)), d.final()]); // throws on tamper
}

function scryptKey(secret, salt, params = {}) {
  // Always merge in maxmem so KDF params loaded from the file header are valid.
  return Buffer.from(crypto.scryptSync(String(secret), salt, 32, { maxmem: KDF.maxmem, ...params }));
}

function safeEqual(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function genRecoveryCode() {
  const bytes = crypto.randomBytes(15);
  let s = '';
  for (let i = 0; i < 15; i++) s += RECOVERY_ALPHABET[bytes[i] % 32];
  return `${s.slice(0, 5)}-${s.slice(5, 10)}-${s.slice(10, 15)}`;
}

function normRecoveryCode(code) {
  return String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

function hashRecoveryCode(code, salt) {
  return crypto.createHash('sha256').update(salt).update(normRecoveryCode(code)).digest();
}

class Vault {
  constructor(filePath) {
    this.filePath = filePath;
    this.header = null;
    this.masterKey = null;
    this.data = null;
    this.pendingTotpSecret = null; // set during 2FA setup
    this.onWrite = null;           // optional hook: called after every successful file write
  }

  exists() { return fs.existsSync(this.filePath); }
  isUnlocked() { return this.masterKey !== null; }

  /* ---------- low-level file I/O ---------- */

  _write() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = this.filePath + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.header), { mode: 0o600 });
    fs.renameSync(tmp, this.filePath); // atomic replace
    if (this.onWrite) this.onWrite();
  }

  _readHeader() {
    let header;
    try {
      header = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
    } catch {
      throw new Error('Vault file is missing or corrupted.');
    }
    if (!header || header.version !== VERSION) throw new Error('Unsupported vault file version.');
    return header;
  }

  _persistPayload() {
    this.header.payload = encrypt(this.masterKey, Buffer.from(JSON.stringify(this.data), 'utf8'));
    this._write();
  }

  /* ---------- lifecycle ---------- */

  /**
   * Create a brand-new vault. Returns the plaintext recovery codes (shown once).
   */
  create(password, { issuer = 'Secrete Vault', account = 'vault' } = {}) {
    if (typeof password !== 'string' || password.length < 8) {
      throw new Error('Password must be at least 8 characters.');
    }
    const salt = crypto.randomBytes(16);
    const kdf = { name: 'scrypt', N: KDF.N, r: KDF.r, p: KDF.p, salt: b64(salt) };
    const masterKey = crypto.randomBytes(32);

    this.header = {
      version: VERSION,
      createdAt: new Date().toISOString(),
      kdf,
      keyWrap: encrypt(scryptKey(password, salt, kdf), masterKey),
      check: encrypt(masterKey, CHECK),
      payload: encrypt(masterKey, Buffer.from(JSON.stringify({
        secrets: [],
        twoFA: { totp: null, passkeys: [] },
        meta: { issuer, account, createdAt: new Date().toISOString() },
      }), 'utf8')),
      recovery: [],
    };
    this.masterKey = masterKey;
    this.data = JSON.parse(decrypt(masterKey, this.header.payload).toString('utf8'));

    const codes = [];
    for (let i = 0; i < RECOVERY_CODE_COUNT; i++) codes.push(this._addRecoveryCode());
    this._write();
    return codes;
  }

  _addRecoveryCode() {
    const code = genRecoveryCode();
    const salt = crypto.randomBytes(16);
    this.header.recovery.push({
      id: crypto.randomUUID(),
      salt: b64(salt),
      hash: b64(hashRecoveryCode(code, salt)),
      wrap: encrypt(scryptKey(normRecoveryCode(code), salt), this.masterKey),
    });
    return code;
  }

  /** Regenerate all recovery codes (invalidates the old ones). Returns new codes. */
  rotateRecoveryCodes() {
    this._assertUnlocked();
    this.header.recovery = [];
    const codes = [];
    for (let i = 0; i < RECOVERY_CODE_COUNT; i++) codes.push(this._addRecoveryCode());
    this._write();
    return codes;
  }

  /**
   * Unlock with the master password.
   * @returns {{ ok: boolean, needTotp?: boolean, needPasskey?: boolean, error?: string }}
   */
  unlock(password) {
    const header = this._readHeader();
    const salt = ub64(header.kdf.salt);
    const pwKey = scryptKey(password, salt, header.kdf);
    let masterKey;
    try {
      masterKey = decrypt(pwKey, header.keyWrap);
    } catch {
      return { ok: false, error: 'Incorrect password.' };
    }
    try {
      decrypt(masterKey, header.check); // verifies master key
      this.data = JSON.parse(decrypt(masterKey, header.payload).toString('utf8'));
    } catch {
      return { ok: false, error: 'Vault file is corrupted (check failed).' };
    }
    this.header = header;
    this.masterKey = masterKey;

    const t = this.data.twoFA || { totp: null, passkeys: [] };
    const needTotp = !!t.totp;
    const needPasskey = (t.passkeys || []).length > 0;
    if (needTotp || needPasskey) {
      return { ok: true, locked2FA: true, needTotp, needPasskey };
    }
    return { ok: true, locked2FA: false, needTotp: false, needPasskey: false };
  }

  /** Complete unlock with a TOTP code. */
  completeTotp(code) {
    if (!this.masterKey || !this.data?.twoFA?.totp) return { ok: false, error: 'No TOTP configured.' };
    if (verifyTotp(this.data.twoFA.totp.secret, code)) return { ok: true };
    return { ok: false, error: 'Incorrect code.' };
  }

  /** Complete unlock with a passkey assertion. */
  completePasskey(assertion, expectedChallengeB64u) {
    if (!this.masterKey || !this.data?.twoFA?.passkeys?.length) {
      return { ok: false, error: 'No passkey configured.' };
    }
    for (const pk of this.data.twoFA.passkeys) {
      const res = verifyAssertion({
        assertion,
        expectedChallengeB64u,
        expectedRpId: RP_ID,
        publicKeyJwk: pk.publicKey,
        expectedCredIdB64u: pk.credId,
        prevSignCount: pk.signCount || 0,
      });
      if (res.ok) {
        pk.signCount = res.signCount;
        this._persistPayload();
        return { ok: true };
      }
    }
    return { ok: false, error: 'Passkey verification failed.' };
  }

  /**
   * Unlock with a recovery code (e.g. password forgotten).
   * Consumes the code (single use) and bypasses 2FA.
   */
  unlockWithRecoveryCode(code) {
    const header = this._readHeader();
    const norm = normRecoveryCode(code);
    if (!norm) return { ok: false, error: 'Enter a recovery code.' };
    for (const r of header.recovery) {
      const salt = ub64(r.salt);
      if (!safeEqual(hashRecoveryCode(code, salt), ub64(r.hash))) continue;
      let masterKey;
      try {
        masterKey = decrypt(scryptKey(norm, salt), r.wrap);
        decrypt(masterKey, header.check);
        this.data = JSON.parse(decrypt(masterKey, header.payload).toString('utf8'));
      } catch {
        continue;
      }
      this.header = header;
      this.masterKey = masterKey;
      header.recovery = header.recovery.filter((x) => x.id !== r.id); // single use
      this._write();
      return { ok: true };
    }
    return { ok: false, error: 'Invalid or already-used recovery code.' };
  }

  /** Change the master password (vault must be unlocked). */
  changePassword(newPassword) {
    this._assertUnlocked();
    if (typeof newPassword !== 'string' || newPassword.length < 8) {
      throw new Error('Password must be at least 8 characters.');
    }
    const salt = crypto.randomBytes(16);
    this.header.kdf = { name: 'scrypt', N: KDF.N, r: KDF.r, p: KDF.p, salt: b64(salt) };
    this.header.keyWrap = encrypt(scryptKey(newPassword, salt, this.header.kdf), this.masterKey);
    this._write();
    return { ok: true };
  }

  lock() {
    if (this.masterKey) this.masterKey.fill(0);
    this.masterKey = null;
    this.data = null;
    this.header = null;
    this.pendingTotpSecret = null;
  }

  /* ---------- 2FA management ---------- */

  startTotpSetup() {
    this._assertUnlocked();
    const secret = generateTotpSecret();
    this.pendingTotpSecret = secret;
    const { issuer, account } = this.data.meta || { issuer: 'Secrete Vault', account: 'vault' };
    return { secret, url: otpauthUrl(secret, issuer, account) };
  }

  /** Confirm a code from the authenticator app to enable TOTP. */
  confirmTotpSetup(code) {
    this._assertUnlocked();
    if (!this.pendingTotpSecret) return { ok: false, error: 'Start TOTP setup first.' };
    if (!verifyTotp(this.pendingTotpSecret, code)) return { ok: false, error: 'Incorrect code.' };
    this.data.twoFA.totp = { secret: this.pendingTotpSecret, enabledAt: new Date().toISOString() };
    this.pendingTotpSecret = null;
    this._persistPayload();
    return { ok: true };
  }

  disableTotp() {
    this._assertUnlocked();
    this.data.twoFA.totp = null;
    this._persistPayload();
    return { ok: true };
  }

  /** Register a passkey from a WebAuthn create() response. */
  addPasskey(attestation, clientDataJSON, expectedChallengeB64u, name) {
    this._assertUnlocked();
    const parsed = parseAttestation(attestation, clientDataJSON, expectedChallengeB64u, RP_ID);
    this.data.twoFA.passkeys.push({
      credId: parsed.credId,
      name: name || 'Passkey',
      publicKey: parsed.publicKeyJwk,
      signCount: parsed.signCount,
      createdAt: new Date().toISOString(),
    });
    this._persistPayload();
    return { ok: true, credId: parsed.credId };
  }

  removePasskey(credId) {
    this._assertUnlocked();
    this.data.twoFA.passkeys = this.data.twoFA.passkeys.filter((p) => p.credId !== credId);
    this._persistPayload();
    return { ok: true };
  }

  listPasskeys() {
    this._assertUnlocked();
    return this.data.twoFA.passkeys.map((p) => ({ credId: p.credId, name: p.name, createdAt: p.createdAt }));
  }

  hasTwoFA() {
    if (!this.data) return { totp: false, passkeys: 0 };
    return {
      totp: !!this.data.twoFA?.totp,
      passkeys: this.data.twoFA?.passkeys?.length || 0,
    };
  }

  /* ---------- secrets CRUD ---------- */

  _assertUnlocked() {
    if (!this.isUnlocked()) throw new Error('Vault is locked.');
  }

  listSecrets() {
    this._assertUnlocked();
    return this.data.secrets
      .map((s) => ({ id: s.id, title: s.title, type: s.type, username: s.username || '', updatedAt: s.updatedAt }))
      .sort((a, b) => (a.title || '').localeCompare(b.title || ''));
  }

  getSecret(id) {
    this._assertUnlocked();
    return this.data.secrets.find((s) => s.id === id) || null;
  }

  /** Add or update a secret. secret: { id?, title, type: 'login'|'note', username?, password?, text? } */
  saveSecret(secret) {
    this._assertUnlocked();
    if (!secret || typeof secret.title !== 'string' || !secret.title.trim()) {
      throw new Error('Title is required.');
    }
    const type = secret.type === 'note' ? 'note' : 'login';
    const now = new Date().toISOString();
    const clean = {
      title: secret.title.trim(),
      type,
      username: type === 'login' ? String(secret.username || '') : '',
      password: type === 'login' ? String(secret.password || '') : '',
      text: String(secret.text || ''),
    };
    if (type === 'login' && !clean.username && !clean.password) {
      throw new Error('A login needs a username or a password.');
    }
    const existing = secret.id ? this.data.secrets.find((s) => s.id === secret.id) : null;
    if (existing) {
      Object.assign(existing, clean, { updatedAt: now });
      this._persistPayload();
      return existing;
    }
    const created = { id: crypto.randomUUID(), ...clean, createdAt: now, updatedAt: now };
    this.data.secrets.push(created);
    this._persistPayload();
    return created;
  }

  deleteSecret(id) {
    this._assertUnlocked();
    const before = this.data.secrets.length;
    this.data.secrets = this.data.secrets.filter((s) => s.id !== id);
    if (this.data.secrets.length === before) return { ok: false };
    this._persistPayload();
    return { ok: true };
  }

  /* ---------- password generator ---------- */

  static generatePassword({ length = 20, upper = true, lower = true, digits = true, symbols = true } = {}) {
    const sets = [
      ['ABCDEFGHIJKLMNOPQRSTUVWXYZ', upper],
      ['abcdefghijklmnopqrstuvwxyz', lower],
      ['0123456789', digits],
      ['!@#$%^&*()-_=+[]{};:,.<>?', symbols],
    ].filter(([, on]) => on);
    if (!sets.length) throw new Error('Select at least one character set.');
    const all = sets.map(([s]) => s).join('');
    const pick = (s) => s[crypto.randomInt(s.length)];
    const chars = sets.map(([s, on]) => (on ? pick(s) : null)).filter(Boolean);
    while (chars.length < length) chars.push(pick(all));
    // Fisher-Yates with crypto randomness
    for (let i = chars.length - 1; i > 0; i--) {
      const j = crypto.randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
  }
}

const RP_ID = 'localhost'; // matches the app://localhost origin used by the renderer

module.exports = { Vault, RP_ID, genRecoveryCode, derivePasswordKey: scryptKey, VERSION };
