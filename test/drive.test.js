'use strict';
/** Google Drive backup logic with a fake Google. Run: node test/drive.test.js */
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { DriveBackup } = require('../src/drive');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secrete-drive-'));
const vaultPath = path.join(dir, 'vault.dat');
const cfgPath = path.join(dir, 'drive-backup.json');
fs.writeFileSync(vaultPath, 'CIPHERTEXT-v1');

// reversible stand-in for DPAPI that is NOT plaintext on disk
const safeStorage = {
  isEncryptionAvailable: () => true,
  encryptString: (s) => Buffer.from(s).reverse(),
  decryptString: (b) => Buffer.from(b).reverse().toString(),
};

/** Fake Google: records calls, answers token + upload endpoints. */
function fakeGoogle() {
  const g = { calls: [], files: new Set(), patch404: false, grant: 'ok', challenge: null, verifier: null };
  g.fetch = async (url, opt = {}) => {
    const u = String(url);
    const json = (status, obj) => ({ ok: status < 300, status, json: async () => obj });
    g.calls.push({ url: u, opt });
    if (u.endsWith('/token')) {
      const f = opt.body;
      if (f.get('grant_type') === 'authorization_code') {
        g.verifier = f.get('code_verifier');
        return json(200, { refresh_token: 'REFRESH-1', access_token: 'AT' });
      }
      return g.grant === 'ok' ? json(200, { access_token: 'AT' }) : json(400, { error: 'invalid_grant' });
    }
    if (u.includes('/revoke')) return json(200, {});
    if (opt.method === 'PATCH') {
      if (g.patch404) return json(404, { error: { message: 'not found' } });
      return json(200, { id: u.split('/files/')[1].split('?')[0] });
    }
    g.files.add('F' + (g.files.size + 1));
    return json(200, { id: 'F' + g.files.size });
  };
  return g;
}

/** Plays the browser: follows the auth URL back to the loopback redirect. */
const browser = (g, { tamperState = false } = {}) => (authUrl) => {
  const q = new URL(authUrl).searchParams;
  g.challenge = q.get('code_challenge');
  g.scope = q.get('scope');
  const back = new URL(q.get('redirect_uri'));
  back.searchParams.set('state', tamperState ? 'evil' : q.get('state'));
  back.searchParams.set('code', 'AUTHCODE');
  setTimeout(() => fetch(back).catch(() => {}), 10);
};

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; console.log('  ✔ ' + name); }
  catch (err) { console.error('  ✘ ' + name); console.error(err); process.exitCode = 1; }
}
const make = (g, extra = {}) => new DriveBackup({ file: cfgPath, vaultPath, safeStorage, fetchFn: g.fetch, openUrl: browser(g), debounceMs: 20, ...extra });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  console.log('Google Drive backup tests');
  const g = fakeGoogle();
  const d = make(g);

  await test('configure rejects empty client details', () => {
    assert.throws(() => d.configure({ clientId: 'x', clientSecret: '' }), /both/);
  });

  await test('connect: PKCE + drive.file scope, then first backup creates the file', async () => {
    d.configure({ clientId: 'cid', clientSecret: 'client-secret-xyz' });
    const st = await d.connect();
    assert.strictEqual(st.connected, true);
    assert.strictEqual(g.scope, 'https://www.googleapis.com/auth/drive.file');
    const expect = crypto.createHash('sha256').update(g.verifier).digest('base64url');
    assert.strictEqual(g.challenge, expect); // verifier matches the challenge sent to Google
    const post = g.calls.find((c) => c.opt.method === 'POST' && c.url.includes('uploadType=multipart'));
    assert.ok(post, 'multipart create call made');
    assert.ok(Buffer.from(post.opt.body).includes('CIPHERTEXT-v1'), 'uploads the vault bytes');
    assert.ok(st.lastOk && !st.lastError);
  });

  await test('client secret and refresh token are not stored in plaintext', () => {
    const raw = fs.readFileSync(cfgPath, 'utf8');
    assert.ok(!raw.includes('client-secret-xyz') && !raw.includes('REFRESH-1'));
  });

  await test('a burst of saves becomes one update of the same file', async () => {
    fs.writeFileSync(vaultPath, 'CIPHERTEXT-v2');
    g.calls.length = 0;
    d.schedule(); d.schedule(); d.schedule();
    await wait(150);
    const patches = g.calls.filter((c) => c.opt.method === 'PATCH');
    assert.strictEqual(patches.length, 1);
    assert.strictEqual(Buffer.from(patches[0].opt.body).toString(), 'CIPHERTEXT-v2');
  });

  await test('file deleted in Drive (404) is created again', async () => {
    g.patch404 = true;
    const st = await d.backupNow();
    assert.ok(!st.lastError, st.lastError);
    assert.ok(g.calls.some((c) => c.opt.method === 'POST' && c.url.includes('uploadType=multipart')));
    g.patch404 = false;
  });

  await test('flush uploads a pending change immediately', async () => {
    g.calls.length = 0;
    d.schedule();
    await d.flush();
    assert.ok(g.calls.some((c) => c.opt.method === 'PATCH'));
  });

  await test('expired Google grant asks the user to reconnect', async () => {
    g.grant = 'revoked';
    const st = await d.backupNow();
    assert.strictEqual(st.connected, false);
    assert.match(st.lastError, /Connect Google Drive again/);
    g.grant = 'ok';
  });

  await test('sign-in with a wrong state value is rejected', async () => {
    const g2 = fakeGoogle();
    const d2 = make(g2, { openUrl: browser(g2, { tamperState: true }) });
    await assert.rejects(d2.connect(), /failed/);
  });

  await test('disconnect revokes the grant and keeps the client details', async () => {
    const g3 = fakeGoogle();
    const d3 = make(g3);
    await d3.connect();
    const st = await d3.disconnect();
    assert.strictEqual(st.connected, false);
    assert.strictEqual(st.hasClient, true);
    assert.ok(g3.calls.some((c) => c.url.includes('/revoke')));
  });

  fs.rmSync(dir, { recursive: true, force: true });
  console.log(`\n${passed} drive tests passed.`);
})();
