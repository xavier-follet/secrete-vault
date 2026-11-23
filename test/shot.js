'use strict';
/* Screenshot every main screen. Run: npx electron test/shot.js --no-sandbox [outDir]
   Output PNGs go to outDir (default: the OS temp folder). */
const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secrete-shot-'));
app.setPath('userData', tmp);
const outDir = process.argv.filter((a) => !a.startsWith('-')).slice(2)[0] || os.tmpdir();
require('../src/main.js');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

app.whenReady().then(async () => {
  try {
    let win = null;
    for (let i = 0; i < 50 && !win; i++) {
      win = BrowserWindow.getAllWindows()[0] || null;
      if (!win) await sleep(200);
    }
    if (!win) throw new Error('No window created');
    let ready = false;
    for (let i = 0; i < 50 && !ready; i++) {
      try { ready = await win.webContents.executeJavaScript('!!window.api'); } catch {}
      if (!ready) await sleep(200);
    }
    win.show();
    win.focus();
    const run = (code) => win.webContents.executeJavaScript(`(async () => {
      const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
      const $ = (s) => document.querySelector(s);
      const waitFor = async (fn, ms = 8000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(100); } return false; };
      ${code}
    })()`);
    const snap = async (name) => {
      await sleep(700);
      let img = await win.capturePage();
      if (img.isEmpty()) { await sleep(800); img = await win.capturePage(); }
      if (img.isEmpty()) throw new Error('capturePage returned empty');
      const file = path.join(outDir, `shot-${name}.png`);
      fs.writeFileSync(file, img.toPNG());
      console.log('saved', file);
    };

    // setup
    await run(`$('#setup-password').value = 'shot-password-123'; $('#setup-password2').value = 'shot-password-123'; $('#setup-password').dispatchEvent(new Event('input', { bubbles: true }));`);
    await snap('01-setup-password');
    await run(`$('#setup-pw-next').click(); await waitFor(() => !$('#setup-step-2fa').classList.contains('hidden'));`);
    await snap('02-setup-2fa');
    await run(`$('#choose-totp').click(); await waitFor(() => $('#totp-qr').src.startsWith('data:'));`);
    await snap('03-setup-totp');
    await run(`$('#totp-back').click(); $('#choose-skip').click(); await waitFor(() => !$('#setup-step-recovery').classList.contains('hidden'));`);
    await snap('04-setup-recovery');

    // vault
    await run(`$('#recovery-open').click(); await waitFor(() => $('#view-vault').classList.contains('active'));
      await api.saveSecret({ secret: { title: 'Email account', type: 'login', username: 'me@example.com', password: 'Xq7!secret-pw-9931', text: 'Primary mailbox. Recovery phone ends in 4417.' } });
      await api.saveSecret({ secret: { title: 'WiFi password', type: 'note', text: 'uniq-note-7741: hunter2' } });
      await api.saveSecret({ secret: { title: 'Bank PIN note', type: 'note', text: 'Something secret' } });
      await api.saveSecret({ secret: { title: 'Server root', type: 'login', username: 'root@10.0.0.4', password: 'a-long-server-pass', text: '' } });
      await refreshSecrets();`);
    await snap('05-vault-empty');
    await run(`document.querySelector('#secret-list li').click(); await sleep(300); $('#f-eye').click();`);
    await snap('06-vault-record');
    await run(`document.querySelector('#btn-new-note').click(); await sleep(200);`);
    await snap('07-vault-note');
    await run(`document.querySelector('#btn-new-login').click(); await sleep(200); $('#f-gen').click(); await sleep(300);`);
    await snap('08-vault-generate');
    await run(`$('#btn-security').click(); await sleep(300); $('#sec-add-passkey').click(); await sleep(200);`);
    await snap('09-security');
    await run(`$('#backup-block').scrollIntoView(); document.querySelector('.how').open = true; await sleep(200);`);
    await snap('09b-security-backup');

    // narrow window
    win.setSize(860, 560);
    await run(`document.querySelector('#secret-list li').click(); await sleep(300);`);
    await snap('10-vault-860');

    // unlock
    await run(`await api.lock(); await sleep(400);`);
    await snap('11-unlock-860');
    win.setSize(1080, 700);
    await run(`$('#unlock-password').value = 'wrong'; $('#unlock-btn').click(); await sleep(200);`);
    await snap('12-unlock-error');
  } catch (e) {
    console.error(e);
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
    app.exit(0);
  }
});
