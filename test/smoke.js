'use strict';
/**
 * End-to-end smoke test: boots the real Electron app (main + preload + renderer)
 * with a throwaway userData dir, then drives the UI logic via executeJavaScript.
 *
 * Run: npx electron test/smoke.js --no-sandbox
 */
const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { totp } = require('../src/totp');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secrete-smoke-'));
app.setPath('userData', tmp);

require('../src/main.js'); // registers scheme, IPC handlers, creates the window

let failures = 0;
function check(label, cond, extra) {
  if (cond) console.log('  ✔ ' + label);
  else { failures++; console.error('  ✘ ' + label + (extra !== undefined ? ' -> ' + JSON.stringify(extra) : '')); }
}

app.whenReady().then(async () => {
  try {
    let win = null;
    for (let i = 0; i < 50 && !win; i++) {
      win = BrowserWindow.getAllWindows()[0] || null;
      if (!win) await new Promise((r) => setTimeout(r, 200));
    }
    if (!win) throw new Error('No window created');
    // wait until the renderer is loaded and the preload API is exposed
    let ready = false;
    for (let i = 0; i < 50 && !ready; i++) {
      try { ready = await win.webContents.executeJavaScript('!!window.api'); } catch { /* not loaded yet */ }
      if (!ready) await new Promise((r) => setTimeout(r, 200));
    }
    if (!ready) throw new Error('Renderer did not load');

    // ---- part 1: setup flow through the real UI, including the TOTP QR ----
    const r1 = await win.webContents.executeJavaScript(`(async () => {
      const out = {};
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      const $ = (s) => document.querySelector(s);
      const waitFor = async (fn, ms = 8000) => {
        const t0 = Date.now();
        while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(100); }
        return false;
      };
      out.hasApi = !!window.api;
      out.status = await api.status();
      out.setupViewVisible = $('#view-setup').classList.contains('active');

      // step 1: master password -> vault file must be created now
      $('#setup-password').value = 'smoke-test-password-1';
      $('#setup-password2').value = 'smoke-test-password-1';
      $('#setup-pw-next').click();
      out.step2fa = await waitFor(() => !$('#setup-step-2fa').classList.contains('hidden'));
      out.vaultCreatedAtPasswordStep = (await api.status()).exists === true;

      // step 2: choose authenticator -> QR image must actually render
      $('#choose-totp').click();
      out.qrImgLoads = await waitFor(() => {
        const im = $('#totp-qr');
        return im.complete && im.naturalWidth > 0 && im.naturalHeight > 0;
      });
      out.totpErrorText = $('#totp-error').textContent;
      out.qrSrcIsDataUrl = String($('#totp-qr').src).startsWith('data:image/png;base64,');
      out.totpSecret = $('#totp-secret').textContent;
      return out;
    })()`);

    console.log('Electron end-to-end smoke test');
    check('preload exposes window.api', r1.hasApi === true);
    check('first run shows setup view', r1.status.exists === false && r1.setupViewVisible === true, r1.status);
    check('password step advances to 2FA step', r1.step2fa === true);
    check('vault file created at password step', r1.vaultCreatedAtPasswordStep === true);
    check('TOTP QR image renders (not broken)', r1.qrImgLoads === true, { qrLoads: r1.qrImgLoads });
    check('QR is a data: URL', r1.qrSrcIsDataUrl === true, r1.qrSrcIsDataUrl);
    check('no error shown in TOTP step', r1.totpErrorText === '', r1.totpErrorText);

    // ---- part 2: confirm TOTP with a real code, then recovery -> vault ----
    const code = totp(r1.totpSecret);
    const r2 = await win.webContents.executeJavaScript(`(async () => {
      const out = {};
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      const $ = (s) => document.querySelector(s);
      const waitFor = async (fn, ms = 8000) => {
        const t0 = Date.now();
        while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(100); }
        return false;
      };
      // wrong code first
      $('#totp-code').value = '${code === '000000' ? '000001' : '000000'}';
      $('#totp-verify').click();
      await waitFor(() => $('#totp-error').textContent.length > 0);
      out.wrongCodeRejected = $('#totp-error').textContent.length > 0;
      // right code
      $('#totp-code').value = '${code}';
      $('#totp-verify').click();
      out.recoveryStepVisible = await waitFor(() => !$('#setup-step-recovery').classList.contains('hidden'));
      await waitFor(() => document.querySelectorAll('#recovery-codes span').length === 10);
      out.codes = [...document.querySelectorAll('#recovery-codes span')].map((s) => s.textContent);
      out.codeCount = out.codes.length;
      const t = await api.hasTwoFA();
      out.totpEnabled = t.ok && t.totp === true;
      $('#recovery-open').click();
      out.vaultViewVisible = await waitFor(() => $('#view-vault').classList.contains('active'));

      // CRUD over IPC while unlocked
      const saved = await api.saveSecret({ secret: { title: 'Test login', type: 'login', username: 'u1', password: 'Xq7!secret-pw-9931', text: 'hello' } });
      out.savedOk = saved.ok && !!saved.secret.id;
      out.savedId = saved.secret && saved.secret.id;
      await api.saveSecret({ secret: { title: 'Test note', type: 'note', text: 'uniq-note-7741 free text' } });
      const list = await api.listSecrets();
      out.listCount = list.secrets.length;
      await refreshSecrets();
      out.listRendered = document.querySelectorAll('#secret-list li').length;
      // the two add buttons must open the matching form type
      $('#btn-new-note').click();
      await sleep(150);
      out.noteBtnShowsNoteForm = !$('#detail-form').classList.contains('hidden')
        && $('#f-login-fields').classList.contains('hidden')
        && state.currentType === 'note';
      $('#btn-new-login').click();
      await sleep(150);
      out.loginBtnShowsLoginForm = !$('#detail-form').classList.contains('hidden')
        && !$('#f-login-fields').classList.contains('hidden')
        && state.currentType === 'login';
      // the explicit Generate button must fill the password field
      out.genOptionsVisible = !$('#gen-options').classList.contains('hidden');
      $('#gen-length').value = '28';
      $('#f-gen').click();
      await waitFor(() => $('#f-password').value.length > 0);
      out.genBtnFillsPassword = $('#f-password').value.length === 28;
      const got = await api.getSecret({ id: out.savedId });
      out.gotPassword = got.secret.password; // expect Xq7!secret-pw-9931
      const gen = await api.generatePassword({ length: 24 });
      out.genLen = gen && gen.password ? gen.password.length : 0;
      const t2 = await api.totpStart(); // second TOTP start while unlocked must work
      out.totpStartOk = t2.ok && !!t2.qr && !!t2.secret;
      return out;
    })()`);

    check('wrong TOTP code rejected', r2.wrongCodeRejected === true);
    check('TOTP confirm reaches recovery step', r2.recoveryStepVisible === true);
    check('10 recovery codes rendered in DOM', r2.codeCount === 10, r2.codeCount);
    check('TOTP enabled in vault', r2.totpEnabled === true);
    check('open vault shows vault view', r2.vaultViewVisible === true);
    check('secret saved via IPC', r2.savedOk === true);
    check('list returns 2 secrets and renders them', r2.listCount === 2 && r2.listRendered === 2, r2.listRendered);
    check('＋ Note button opens a note form', r2.noteBtnShowsNoteForm === true);
    check('＋ Password button opens a login form', r2.loginBtnShowsLoginForm === true);
    check('generator options visible in login form', r2.genOptionsVisible === true);
    check('🔄 Generate button fills password (28 chars)', r2.genBtnFillsPassword === true, r2.genBtnFillsPassword);
    check('get returns decrypted password', r2.gotPassword === 'Xq7!secret-pw-9931', r2.gotPassword);
    check('password generator works', r2.genLen === 24);
    check('TOTP start works while unlocked', r2.totpStartOk === true);

    // ---- part 3: lock -> unlock UI (password + TOTP gate) ----
    const r3 = await win.webContents.executeJavaScript(`(async () => {
      const out = {};
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      const $ = (s) => document.querySelector(s);
      const waitFor = async (fn, ms = 8000) => {
        const t0 = Date.now();
        while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(100); }
        return false;
      };
      await api.lock();
      out.unlockViewVisible = await waitFor(() => $('#view-unlock').classList.contains('active'));
      $('#unlock-password').value = 'nope-nope-nope';
      $('#unlock-btn').click();
      await waitFor(() => $('#unlock-error').textContent.length > 0);
      out.wrongPwError = $('#unlock-error').textContent;
      out.stillLocked = (await api.status()).unlocked === false;
      $('#unlock-password').value = 'smoke-test-password-1';
      $('#unlock-btn').click();
      out.totpGateShown = await waitFor(() => !$('#unlock-2fa-wrap').classList.contains('hidden') && !$('#unlock-totp-wrap').classList.contains('hidden'));
      // wrong totp
      $('#unlock-totp').value = '999999';
      $('#unlock-totp-btn').click();
      await waitFor(() => $('#unlock-totp-error').textContent.length > 0);
      out.wrongTotpRejected = $('#unlock-totp-error').textContent.length > 0;
      return out;
    })()`);

    check('unlock view shown after lock', r3.unlockViewVisible === true);
    check('wrong password shows error, stays locked', r3.wrongPwError.length > 0 && r3.stillLocked === true, r3.wrongPwError);
    check('password unlocks to TOTP gate (2FA enforced)', r3.totpGateShown === true);
    check('wrong TOTP at unlock rejected', r3.wrongTotpRejected === true);

    // ---- part 4: unlock via the recovery-code UI, then change password ----
    const r5 = await win.webContents.executeJavaScript(`(async () => {
      const out = {};
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      const $ = (s) => document.querySelector(s);
      const waitFor = async (fn, ms = 8000) => {
        const t0 = Date.now();
        while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(100); }
        return false;
      };
      // drive the real recovery UI on the unlock screen
      $('#show-recovery').click();
      await waitFor(() => !$('#unlock-recovery-wrap').classList.contains('hidden'));
      $('#unlock-recovery').value = ${JSON.stringify(r2.codes[0])};
      $('#unlock-recovery-btn').click();
      out.recoveryStepOk = await waitFor(() => $('#unlock-recovery-error').textContent.length > 0) === false;
      out.vaultViewAfterRecovery = await waitFor(() => $('#view-vault').classList.contains('active'));
      out.unlockedAfterRecovery = (await api.status()).unlocked === true;

      const cp = await api.changePassword({ current: 'smoke-test-password-1', next: 'smoke-test-password-2' });
      out.changePw = cp;
      await api.lock();
      for (let i = 0; i < 50 && (await api.status()).unlocked; i++) await sleep(100);
      out.lockedStatus = await api.status();
      out.unlockOld = await api.unlock({ password: 'smoke-test-password-1' });
      await api.lock();
      out.unlockNew = await api.unlock({ password: 'smoke-test-password-2' }); // will hit 2FA gate
      out.totpGateAgain = out.unlockNew.ok && out.unlockNew.locked2FA === true;
      await api.lock();
      out.recoveryReuse = await api.unlockRecovery({ code: ${JSON.stringify(r2.codes[0])} });
      out.recoverySecond = await api.unlockRecovery({ code: ${JSON.stringify(r2.codes[1])} });
      const del = await api.deleteSecret({ id: ${JSON.stringify(r2.savedId)} });
      const list2 = await api.listSecrets();
      out.deleted = del.ok && list2.secrets.length === 1;
      return out;
    })()`);

    check('recovery code unlocks via UI (bypasses 2FA)', r5.recoveryStepOk === true && r5.unlockedAfterRecovery === true);
    check('vault view after recovery unlock', r5.vaultViewAfterRecovery === true);
    check('change password ok', r5.changePw.ok === true, r5.changePw);
    check('vault locks', r5.lockedStatus.unlocked === false);
    check('old password fails after change', r5.unlockOld.ok === false);
    check('new password reaches 2FA gate', r5.totpGateAgain === true, r5.unlockNew);
    check('used recovery code rejected', r5.recoveryReuse.ok === false);
    check('second recovery code works', r5.recoverySecond.ok === true);
    check('delete works', r5.deleted === true);

    const vaultFile = path.join(tmp, 'vault.dat');
    check('vault file exists in userData', fs.existsSync(vaultFile));
    const raw = fs.readFileSync(vaultFile, 'utf8');
    check('vault file has no plaintext secrets', !raw.includes('Xq7!secret-pw-9931') && !raw.includes('uniq-note-7741') && raw.includes('"payload"'));

    console.log(failures === 0 ? '\nSMOKE OK' : `\n${failures} SMOKE FAILURES`);
  } catch (err) {
    console.error('SMOKE ERROR', err);
    failures++;
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* chromium cache locks */ }
    app.exit(failures === 0 ? 0 : 1);
  }
});
