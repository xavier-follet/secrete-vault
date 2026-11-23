'use strict';
/* Diagnostic: why does the TOTP QR <img> show broken? Run: npx electron test/qr-diag.js --no-sandbox */
const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');
const os = require('os');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'secrete-qrdiag-'));
app.setPath('userData', tmp);
require('../src/main.js');

app.whenReady().then(async () => {
  const win = BrowserWindow.getAllWindows()[0];
  win.webContents.on('console-message', (e, level, msg) => console.log('[console]', msg));
  await new Promise((r) => setTimeout(r, 1200));

  const res = await win.webContents.executeJavaScript(`(async () => {
    const out = {};
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const $ = (s) => document.querySelector(s);
    window.__csp = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' blocked ' + e.blockedURI));

    // 1) does ANY data: image load under this page's CSP?
    const tiny = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
    const img0 = new Image();
    img0.src = tiny;
    await sleep(300);
    out.plainDataUrlLoads = img0.complete && img0.naturalWidth > 0;

    // 2) run the real setup + totp flow
    await api.setup({ password: 'diag-password-123' });
    const t = await api.totpStart();
    out.totpOk = t.ok;
    out.qrType = typeof t.qr;
    out.qrPrefix = String(t.qr).slice(0, 40);
    out.qrLen = String(t.qr).length;

    const img = $('#totp-qr');
    img.src = t.qr;
    await sleep(500);
    out.qrImgComplete = img.complete;
    out.qrImgNaturalWidth = img.naturalWidth;

    // 3) CSP violations recorded?
    out.cspViolations = window.__csp;
    out.cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content || null;
    return out;
  })()`);
  console.log(JSON.stringify(res, null, 2));
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  app.exit(0);
});
