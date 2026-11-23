'use strict';
/**
 * Minimal WebAuthn (passkey) support for a local Electron app.
 *
 * - parseAttestation(): extracts the credential id + EC P-256 public key
 *   from a navigator.credentials.create() response (attestation "none").
 * - verifyAssertion(): verifies a navigator.credentials.get() response
 *   against the stored public key, challenge and rpId.
 *
 * Only what we need is implemented: CBOR decoding, COSE EC2 keys,
 * ES256 signature verification.
 */
const crypto = require('crypto');

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const ub64u = (s) => Buffer.from(s, 'base64url');

/* ---------------- minimal CBOR decoder ---------------- */

function cborDecode(buf, offset = 0) {
  const first = buf[offset];
  const major = first >> 5;
  const info = first & 0x1f;
  let pos = offset + 1;

  function readLength(info) {
    if (info < 24) return info;
    if (info === 24) return buf[pos++];
    if (info === 25) { const v = buf.readUInt16BE(pos); pos += 2; return v; }
    if (info === 26) { const v = buf.readUInt32BE(pos); pos += 4; return v; }
    if (info === 27) { const v = buf.readBigUInt64BE(pos); pos += 8; return Number(v); }
    throw new Error('Unsupported CBOR additional info: ' + info);
  }

  switch (major) {
    case 0: return [readLength(info), pos];
    case 1: return [-1 - readLength(info), pos];
    case 2: { const len = readLength(info); const v = buf.slice(pos, pos + len); return [v, pos + len]; }
    case 3: { const len = readLength(info); const v = buf.slice(pos, pos + len).toString('utf8'); return [v, pos + len]; }
    case 4: {
      const len = readLength(info);
      const arr = [];
      for (let i = 0; i < len; i++) { const [v, p] = cborDecode(buf, pos); arr.push(v); pos = p; }
      return [arr, pos];
    }
    case 5: {
      const len = readLength(info);
      const map = new Map();
      for (let i = 0; i < len; i++) {
        const [k, p1] = cborDecode(buf, pos); pos = p1;
        const [v, p2] = cborDecode(buf, pos); pos = p2;
        map.set(k, v);
      }
      return [map, pos];
    }
    case 6: { const tag = readLength(info); const [v, p] = cborDecode(buf, pos); return [v, p]; } // ignore tag
    case 7: {
      if (info === 20) return [false, pos];
      if (info === 21) return [true, pos];
      if (info === 22) return [null, pos];
      if (info === 23) return [undefined, pos];
      if (info === 25) { const v = buf.readUInt16BE(pos) / 256; pos += 2; return [v, pos]; }
      if (info === 26) { const v = buf.readFloatBE(pos); pos += 4; return [v, pos]; }
      if (info === 27) { const v = buf.readDoubleBE(pos); pos += 8; return [v, pos]; }
      throw new Error('Unsupported CBOR simple value: ' + info);
    }
  }
  throw new Error('Unsupported CBOR major type: ' + major);
}

/* ---------------- COSE key -> JWK ---------------- */

function coseToJwk(cose) {
  // Map with integer keys. EC2 / P-256 / ES256 only.
  const kty = cose.get(1);
  const alg = cose.get(3);
  const crv = cose.get(-1);
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (kty !== 2) throw new Error('Unsupported COSE key type: ' + kty);
  if (alg !== -7) throw new Error('Unsupported COSE algorithm (need ES256/-7): ' + alg);
  if (crv !== 1) throw new Error('Unsupported curve (need P-256/1): ' + crv);
  if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y) || x.length !== 32 || y.length !== 32) {
    throw new Error('Invalid EC coordinates');
  }
  return { kty: 'EC', crv: 'P-256', x: b64u(x), y: b64u(y) };
}

/* ---------------- attestation (create) ---------------- */

function parseClientData(clientDataJSONBuf) {
  const data = JSON.parse(clientDataJSONBuf.toString('utf8'));
  return data; // { type, challenge, origin, crossOrigin? }
}

/**
 * Parse a makeCredential response.
 * @param {string} attestationObjectB64u
 * @param {string} clientDataJSONB64u
 * @param {string} expectedChallengeB64u
 * @param {string} expectedRpId
 * @returns {{ credId: string, credIdRaw: Buffer, publicKeyJwk: object, signCount: number }}
 */
function parseAttestation(attestationObjectB64u, clientDataJSONB64u, expectedChallengeB64u, expectedRpId) {
  const clientDataBuf = ub64u(clientDataJSONB64u);
  const clientData = parseClientData(clientDataBuf);
  if (clientData.type !== 'webauthn.create') throw new Error('clientData.type must be webauthn.create');
  if (clientData.challenge !== expectedChallengeB64u) throw new Error('Challenge mismatch');

  const att = cborDecode(ub64u(attestationObjectB64u))[0];
  // attestation object is a CBOR map with text keys: "fmt", "attStmt", "authData"
  const authData = att.get('authData') || att.get(3);
  if (!Buffer.isBuffer(authData) || authData.length < 37) throw new Error('Bad authenticator data');

  const rpIdHash = authData.slice(0, 32);
  const expectedRpIdHash = crypto.createHash('sha256').update(expectedRpId).digest();
  if (!rpIdHash.equals(expectedRpIdHash)) throw new Error('rpId hash mismatch');

  const flags = authData[32];
  const signCount = authData.readUInt32BE(33);
  if (!(flags & 0x40)) throw new Error('Attested credential data flag not set');

  let off = 37 + 16; // skip aaguid
  const credIdLen = authData.readUInt16BE(off);
  off += 2;
  const credIdRaw = authData.slice(off, off + credIdLen);
  off += credIdLen;
  const [coseKey] = cborDecode(authData.slice(off));
  const publicKeyJwk = coseToJwk(coseKey);

  return { credId: b64u(credIdRaw), credIdRaw, publicKeyJwk, signCount };
}

/* ---------------- assertion (get) ---------------- */

/**
 * Verify an assertion (getCredential response).
 * @returns {{ ok: boolean, signCount?: number, error?: string }}
 */
function verifyAssertion(opts) {
  const {
    assertion,           // { id, response: { clientDataJSON, authenticatorData, signature } } all base64url strings
    expectedChallengeB64u,
    expectedRpId,
    publicKeyJwk,
    expectedCredIdB64u,
    prevSignCount = 0,
  } = opts;

  try {
    if (assertion.id !== expectedCredIdB64u) return { ok: false, error: 'Unknown credential' };
    const clientDataBuf = ub64u(assertion.response.clientDataJSON);
    const clientData = parseClientData(clientDataBuf);
    if (clientData.type !== 'webauthn.get') return { ok: false, error: 'clientData.type must be webauthn.get' };
    if (clientData.challenge !== expectedChallengeB64u) return { ok: false, error: 'Challenge mismatch' };

    const authData = ub64u(assertion.response.authenticatorData);
    if (authData.length < 37) return { ok: false, error: 'Bad authenticator data' };
    const rpIdHash = authData.slice(0, 32);
    if (!rpIdHash.equals(crypto.createHash('sha256').update(expectedRpId).digest())) {
      return { ok: false, error: 'rpId mismatch' };
    }
    const flags = authData[32];
    if (!(flags & 0x01)) return { ok: false, error: 'User presence flag not set' };
    if (!(flags & 0x04)) return { ok: false, error: 'User verification was not performed' };
    const signCount = authData.readUInt32BE(33);
    if (signCount !== 0 && signCount <= prevSignCount) return { ok: false, error: 'Clone detected (signCount)' };

    const clientHash = crypto.createHash('sha256').update(clientDataBuf).digest();
    const signed = Buffer.concat([authData, clientHash]);
    const key = crypto.createPublicKey({ key: publicKeyJwk, format: 'jwk' });
    const ok = crypto.verify('sha256', signed, key, ub64u(assertion.response.signature));
    return ok ? { ok: true, signCount } : { ok: false, error: 'Bad signature' };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = { cborDecode, coseToJwk, parseAttestation, verifyAssertion, b64u, ub64u };
