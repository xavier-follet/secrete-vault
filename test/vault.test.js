'use strict';
/**
 * Node test suite for the vault crypto core (no Electron needed).
 * Run: npm test
 */
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { Vault, RP_ID } = require('../src/vault');
const { generateTotpSecret, totp, verifyTotp, base32Encode, base32Decode, otpauthUrl } = require('../src/totp');
const { cborDecode, parseAttestation, verifyAssertion } = require('../src/webauthn');

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed++;
    console.log('  ✔ ' + name);
  } catch (err) {
    console.error('  ✘ ' + name);
    console.error(err);
    process.exitCode = 1;
  }
}

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secrete-vault-test-'));
const file = path.join(tmp, 'vault.dat');

console.log('TOTP / base32');
test('base32 roundtrip', () => {
  const raw = crypto.randomBytes(20);
  assert.deepStrictEqual(base32Decode(base32Encode(raw)), raw);
});
test('TOTP is deterministic and verifiable', () => {
  const secret = generateTotpSecret();
  const t = 1_700_000_000_000;
  const code = totp(secret, t);
  assert.match(code, /^\d{6}$/);
  assert.strictEqual(totp(secret, t), code); // deterministic
  assert.strictEqual(verifyTotp(secret, code, 1, t), true);
  const wrong = code === '000000' ? '111111' : '000000';
  assert.strictEqual(verifyTotp(secret, wrong, 0, t), false);
});
test('TOTP rejects wrong codes', () => {
  const secret = generateTotpSecret();
  const code = totp(secret, 1_700_000_000_000);
  const wrong = code === '123456' ? '654321' : '123456';
  assert.strictEqual(verifyTotp(secret, wrong, 0, 1_700_000_000_000), false);
  assert.strictEqual(verifyTotp(secret, 'abc', 1, 1_700_000_000_000), false);
});
test('otpauth URL format', () => {
  const url = otpauthUrl('JBSWY3DPEHPK3PXP', 'Secrete Vault', 'me@example.com');
  assert.ok(url.startsWith('otpauth://totp/Secrete%20Vault:me%40example.com?'));
  assert.ok(url.includes('secret=JBSWY3DPEHPK3PXP'));
});

console.log('Vault lifecycle');
const PASSWORD = 'correct horse battery staple';
let codes;
const v = new Vault(file);

test('vault does not exist yet', () => assert.strictEqual(v.exists(), false));
test('create() writes the file and returns 10 recovery codes', () => {
  codes = v.create(PASSWORD);
  assert.strictEqual(codes.length, 10);
  assert.ok(v.exists());
  assert.ok(v.isUnlocked());
  for (const c of codes) assert.match(c, /^[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}$/);
});
test('file on disk contains no plaintext secrets', () => {
  const raw = fs.readFileSync(file, 'utf8');
  assert.ok(!raw.includes('my secret'));
  assert.ok(raw.includes('"payload"'));
});
test('file permissions are owner-only (0600)', () => {
  if (process.platform !== 'win32') {
    const mode = fs.statSync(file).mode & 0o777;
    assert.strictEqual(mode, 0o600);
  }
});

test('secrets CRUD + persistence across instances', () => {
  const s = v.saveSecret({ title: 'Email', type: 'login', username: 'me@example.com', password: 's3cret!', text: 'note' });
  assert.ok(s.id);
  v.saveSecret({ title: 'WiFi', type: 'note', text: 'passphrase is hunter2' });
  v.lock();
  assert.strictEqual(v.isUnlocked(), false);

  const v2 = new Vault(file);
  const r = v2.unlock(PASSWORD);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.locked2FA, false);
  const list = v2.listSecrets();
  assert.strictEqual(list.length, 2);
  const got = v2.getSecret(s.id);
  assert.strictEqual(got.password, 's3cret!');
  assert.strictEqual(got.username, 'me@example.com');

  const upd = v2.saveSecret({ id: s.id, title: 'Email 2', type: 'login', username: 'me@example.com', password: 'new-pass', text: '' });
  assert.strictEqual(upd.title, 'Email 2');
  assert.strictEqual(v2.deleteSecret(upd.id).ok, true);
  assert.strictEqual(v2.listSecrets().length, 1);
  v2.lock();
});

test('wrong password is rejected', () => {
  const v2 = new Vault(file);
  const r = v2.unlock('wrong password');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(v2.isUnlocked(), false);
});

test('tampered payload fails GCM authentication', () => {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const data = Buffer.from(raw.payload.data, 'base64');
  data[0] ^= 0xff;
  raw.payload.data = data.toString('base64');
  fs.writeFileSync(file + '.tampered', JSON.stringify(raw));
  const v2 = new Vault(file + '.tampered');
  const r = v2.unlock(PASSWORD); // keyWrap still ok, but check/payload must fail
  assert.strictEqual(r.ok, false);
});

console.log('2FA (TOTP)');
test('TOTP setup, confirm, and unlock gating', () => {
  const v2 = new Vault(file);
  assert.strictEqual(v2.unlock(PASSWORD).ok, true);
  const { secret, url } = v2.startTotpSetup();
  assert.ok(url.includes(secret));
  const wrong1 = totp(secret) === '000000' ? '000001' : '000000';
  assert.strictEqual(v2.confirmTotpSetup(wrong1).ok, false); // wrong code rejected
  assert.strictEqual(v2.confirmTotpSetup(totp(secret)).ok, true);
  v2.lock();

  const v3 = new Vault(file);
  const r = v3.unlock(PASSWORD);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.locked2FA, true);
  assert.strictEqual(r.needTotp, true);
  const wrong2 = totp(secret) === '111111' ? '111112' : '111111';
  assert.strictEqual(v3.completeTotp(wrong2).ok, false);
  assert.strictEqual(v3.completeTotp(totp(secret)).ok, true);
  assert.strictEqual(v3.hasTwoFA().totp, true);
  v3.disableTotp();
  assert.strictEqual(v3.hasTwoFA().totp, false);
  v3.lock();
});

console.log('Recovery codes');
test('recovery code unlocks, is single-use, and password change works', () => {
  const code = codes[0];
  const v2 = new Vault(file);
  const r = v2.unlockWithRecoveryCode(code);
  assert.strictEqual(r.ok, true);
  assert.strictEqual(v2.isUnlocked(), true);
  assert.strictEqual(v2.listSecrets().length, 1);

  // same code again -> rejected
  const v3 = new Vault(file);
  assert.strictEqual(v3.unlockWithRecoveryCode(code).ok, false);

  // invalid code rejected
  assert.strictEqual(v3.unlockWithRecoveryCode('AAAAA-BBBBB-CCCCC').ok, false);

  // change password, old password must fail, new must work
  assert.strictEqual(v2.changePassword('new-master-password-1').ok, true);
  v2.lock();
  const v4 = new Vault(file);
  assert.strictEqual(v4.unlock(PASSWORD).ok, false);
  assert.strictEqual(v4.unlock('new-master-password-1').ok, true);

  // remaining recovery codes still work after password change
  v4.lock();
  const v5 = new Vault(file);
  assert.strictEqual(v5.unlockWithRecoveryCode(codes[1]).ok, true);
  v5.lock();
});

test('rotateRecoveryCodes invalidates old codes', () => {
  const v2 = new Vault(file);
  assert.strictEqual(v2.unlock('new-master-password-1').ok, true);
  const fresh = v2.rotateRecoveryCodes();
  assert.strictEqual(fresh.length, 10);
  v2.lock();
  const v3 = new Vault(file);
  assert.strictEqual(v3.unlockWithRecoveryCode(codes[2]).ok, false); // old code dead
  assert.strictEqual(v3.unlockWithRecoveryCode(fresh[0]).ok, true);   // new code works
  v3.lock();
});

console.log('Password generator');
test('generator respects length and charsets', () => {
  const pw = Vault.generatePassword({ length: 32, upper: true, lower: true, digits: true, symbols: false });
  assert.strictEqual(pw.length, 32);
  assert.match(pw, /^[A-Za-z0-9]+$/);
  const sym = Vault.generatePassword({ length: 24, upper: false, lower: false, digits: false, symbols: true });
  assert.strictEqual(sym.length, 24);
  assert.match(sym, /^[!@#$%^&*()\-_=+\[\]{};:,.<>?]+$/);
});

console.log('WebAuthn (passkey) crypto');
test('CBOR decoder handles maps/arrays/ints/bytes', () => {
  // {1: 2, 3: -7, -1: 1, -2: h'0102', -3: h'0304'}
  const buf = Buffer.from('a501020326200121582001024022582003 04'.replace(/\s/g, ''), 'hex');
  const [m] = cborDecode(buf);
  assert.strictEqual(m.get(1), 2);
  assert.strictEqual(m.get(3), -7);
  assert.strictEqual(m.get(-1), 1);
  assert.ok(Buffer.isBuffer(m.get(-2)));
});
test('passkey register + assert roundtrip with a synthetic ES256 authenticator', () => {
  // synthetic authenticator: generate an ES256 keypair, build attestation + assertion
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');

  // minimal CBOR encoder for the COSE key map {1:2, 3:-7, -1:1, -2:x, -3:y}
  function cborHead(major, len) {
    if (len < 24) return Buffer.from([(major << 5) | len]);
    if (len < 256) return Buffer.from([(major << 5) | 24, len]);
    return Buffer.from([(major << 5) | 25, len >> 8, len & 0xff]);
  }
  const cose = Buffer.concat([
    cborHead(5, 5),
    Buffer.from([0x01, 0x02]),                 // 1: 2
    Buffer.from([0x03, 0x26]),                 // 3: -7
    Buffer.from([0x20, 0x01]),                 // -1: 1
    Buffer.from([0x21]), cborHead(2, 32), x,   // -2: bytes(32)
    Buffer.from([0x22]), cborHead(2, 32), y,   // -3: bytes(32)
  ]);
  const credId = crypto.randomBytes(16);
  const rpIdHash = crypto.createHash('sha256').update(RP_ID).digest();
  const authData = Buffer.concat([
    rpIdHash, Buffer.from([0x45]), Buffer.from([0, 0, 0, 1]), // flags UP|UV|AT, signCount 1
    crypto.randomBytes(16),                                    // aaguid
    Buffer.from([0, credId.length]), credId,                   // credential id
    cose,
  ]);
  const challenge = crypto.randomBytes(32).toString('base64url');
  const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin: 'app://localhost' }));
  // attestationObject = map(3): {1: "none", 2: {}, 3: authData}
  const attObj = Buffer.concat([
    cborHead(5, 3),
    Buffer.from([0x01]), Buffer.from('none', 'utf8').length < 24 ? Buffer.concat([Buffer.from([0x64]), Buffer.from('none')]) : Buffer.alloc(0),
    Buffer.from([0x02, 0xa0]),                 // 2: {}
    Buffer.from([0x03]), cborHead(2, authData.length), authData,
  ]);

  const parsed = parseAttestation(attObj.toString('base64url'), clientDataJSON.toString('base64url'), challenge, RP_ID);
  assert.strictEqual(parsed.credId, credId.toString('base64url'));
  assert.deepStrictEqual(parsed.publicKeyJwk.x, jwk.x);
  assert.deepStrictEqual(parsed.publicKeyJwk.y, jwk.y);

  // now an assertion
  const authData2 = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 2])]);
  const clientData2 = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'app://localhost' }));
  const signed = Buffer.concat([authData2, crypto.createHash('sha256').update(clientData2).digest()]);
  const signature = crypto.sign('sha256', signed, privateKey);
  const assertion = {
    id: credId.toString('base64url'),
    response: {
      clientDataJSON: clientData2.toString('base64url'),
      authenticatorData: authData2.toString('base64url'),
      signature: signature.toString('base64url'),
    },
  };
  const res = verifyAssertion({
    assertion, expectedChallengeB64u: challenge, expectedRpId: RP_ID,
    publicKeyJwk: parsed.publicKeyJwk, expectedCredIdB64u: parsed.credId, prevSignCount: 1,
  });
  assert.strictEqual(res.ok, true, res.error);
  assert.strictEqual(res.signCount, 2);

  // bad signature must fail
  const badSig = Buffer.from(signature); badSig[10] ^= 0xff;
  const res2 = verifyAssertion({
    assertion: { ...assertion, response: { ...assertion.response, signature: badSig.toString('base64url') } },
    expectedChallengeB64u: challenge, expectedRpId: RP_ID,
    publicKeyJwk: parsed.publicKeyJwk, expectedCredIdB64u: parsed.credId, prevSignCount: 1,
  });
  assert.strictEqual(res2.ok, false);

  // wrong rpId must fail
  const res3 = verifyAssertion({
    assertion, expectedChallengeB64u: challenge, expectedRpId: 'evil.example',
    publicKeyJwk: parsed.publicKeyJwk, expectedCredIdB64u: parsed.credId, prevSignCount: 1,
  });
  assert.strictEqual(res3.ok, false);
});

test('passkey stored in vault gates unlock', () => {
  const v2 = new Vault(file);
  assert.strictEqual(v2.unlock('new-master-password-1').ok, true);
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = crypto.randomBytes(16).toString('base64url');
  v2.data.twoFA.passkeys.push({ credId, name: 'test', publicKey: jwk, signCount: 0, createdAt: new Date().toISOString() });

  const challenge = crypto.randomBytes(32).toString('base64url');
  const rpIdHash = crypto.createHash('sha256').update(RP_ID).digest();
  const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 5])]);
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: 'app://localhost' }));
  const signed = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const signature = crypto.sign('sha256', signed, privateKey);
  const r = v2.completePasskey({
    id: credId,
    response: {
      clientDataJSON: clientData.toString('base64url'),
      authenticatorData: authData.toString('base64url'),
      signature: signature.toString('base64url'),
    },
  }, challenge);
  assert.strictEqual(r.ok, true);
  v2.lock();
});

console.log(`\n${passed} tests passed${process.exitCode ? ' (with failures)' : ''}.`);
fs.rmSync(tmp, { recursive: true, force: true });
