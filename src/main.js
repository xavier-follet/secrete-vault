'use strict';
/**
 * Secrete Vault — Electron main process.
 *
 * Owns the encrypted vault file (in the OS user folder: %APPDATA%/SecreteVault
 * on Windows, ~/.config/SecreteVault on Linux, ~/Library/Application Support
 * on macOS) and exposes a minimal IPC API to the renderer. The decrypted
 * vault only ever lives in this process's memory.
 */
const { app, BrowserWindow, ipcMain, shell, Menu, safeStorage } = require('electron');
const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const QRCode = require('qrcode');
const { Vault, RP_ID, derivePasswordKey } = require('./vault');
const { DriveBackup } = require('./drive');

const AUTO_LOCK_MS = 5 * 60 * 1000;

const vaultPath = path.join(app.getPath('userData'), 'vault.dat');
const vault = new Vault(vaultPath);

// Optional Google Drive backup (off until the user connects it in Security).
const drive = new DriveBackup({
  file: path.join(app.getPath('userData'), 'drive-backup.json'),
  vaultPath,
  safeStorage,
  openUrl: (url) => shell.openExternal(url),
  onStatus: (st) => { if (win) win.webContents.send('backup:status', st); },
});
vault.onWrite = () => drive.schedule();

let win = null;
let server = null;
let lastActivity = Date.now();
let pendingChallenge = null; // { b64u, purpose: 'register'|'assert', credId? }

function touch() { lastActivity = Date.now(); }

/**
 * Serve the renderer over plain HTTP on 127.0.0.1 with an ephemeral port.
 * Chromium only allows WebAuthn (passkeys) on HTTPS origins or on HTTP
 * "localhost" origins — http://localhost:<port> is a secure context and is
 * explicitly allowed, with rpId "localhost". The server binds to loopback
 * only and rejects any Host header that is not localhost/127.0.0.1.
 */
function startLocalServer() {
  const root = path.join(__dirname, '..', 'renderer');
  const MIME = {
    '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
    '.json': 'application/json', '.ico': 'image/x-icon', '.woff2': 'font/woff2',
  };
  server = http.createServer((req, res) => {
    const host = String(req.headers.host || '').toLowerCase();
    if (!/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(host)) {
      res.writeHead(403); res.end(); return;
    }
    const url = new URL(req.url, 'http://localhost');
    let p = decodeURIComponent(url.pathname);
    if (p === '/' || p === '') p = '/index.html';
    const file = path.normalize(path.join(root, p));
    if (!file.startsWith(root)) { res.writeHead(403); res.end(); return; }
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(404); res.end('Not found'); return; }
      res.writeHead(200, {
        'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
        'Cache-Control': 'no-store',
      });
      res.end(data);
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function createWindow(port) {
  win = new BrowserWindow({
    width: 1080,
    height: 700,
    minWidth: 860,
    minHeight: 560,
    backgroundColor: '#0f1613',
    title: 'Secrete Vault',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadURL(`http://localhost:${port}/index.html`);
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.on('closed', () => { vault.lock(); win = null; });
}

/* ---------------- auto-lock ---------------- */

setInterval(() => {
  if (vault.isUnlocked() && Date.now() - lastActivity > AUTO_LOCK_MS) {
    vault.lock();
    pendingChallenge = null;
    if (win) win.webContents.send('vault:locked');
  }
}, 15 * 1000);

/* ---------------- WebAuthn option builders ---------------- */

function newChallenge(purpose) {
  pendingChallenge = { b64u: crypto.randomBytes(32).toString('base64url'), purpose, at: Date.now() };
  return pendingChallenge.b64u;
}

function takeChallenge(purpose) {
  if (!pendingChallenge || pendingChallenge.purpose !== purpose || Date.now() - pendingChallenge.at > 60000) {
    return null;
  }
  const c = pendingChallenge.b64u;
  pendingChallenge = null;
  return c;
}

/* ---------------- IPC API ---------------- */

function registerIpc() {
  const needUnlock = (fn) => (e, ...args) => {
    touch();
    if (!vault.isUnlocked()) return { ok: false, error: 'Vault is locked.', locked: true };
    try { return fn(e, ...args); } catch (err) { return { ok: false, error: err.message }; }
  };

  ipcMain.handle('vault:status', () => ({
    exists: vault.exists(),
    unlocked: vault.isUnlocked(),
    path: vaultPath,
    autoLockMs: AUTO_LOCK_MS,
  }));

  ipcMain.handle('vault:setup', (e, { password, issuer, account }) => {
    touch();
    if (vault.exists()) return { ok: false, error: 'Vault already exists.' };
    try {
      const codes = vault.create(password, { issuer, account });
      return { ok: true, recoveryCodes: codes };
    } catch (err) { return { ok: false, error: err.message }; }
  });

  ipcMain.handle('vault:unlock', (e, { password }) => {
    touch();
    return vault.unlock(password);
  });

  ipcMain.handle('vault:unlockTotp', (e, { code }) => {
    touch();
    const r = vault.completeTotp(code);
    if (r.ok && win) win.webContents.send('vault:unlocked');
    return r;
  });

  ipcMain.handle('vault:unlockRecovery', (e, { code }) => {
    touch();
    const r = vault.unlockWithRecoveryCode(code);
    if (r.ok && win) win.webContents.send('vault:unlocked');
    return r;
  });

  ipcMain.handle('vault:changePassword', (e, { current, next }) => {
    touch();
    try {
      if (!vault.isUnlocked()) return { ok: false, error: 'Vault is locked.' };
      // re-verify current password against the stored wrap
      const kdf = vault.header.kdf;
      const pwKey = derivePasswordKey(current, Buffer.from(kdf.salt, 'base64'), kdf);
      let mk;
      try {
        const d = crypto.createDecipheriv('aes-256-gcm', pwKey, Buffer.from(vault.header.keyWrap.iv, 'base64'));
        d.setAuthTag(Buffer.from(vault.header.keyWrap.tag, 'base64'));
        mk = Buffer.concat([d.update(Buffer.from(vault.header.keyWrap.data, 'base64')), d.final()]);
      } catch { return { ok: false, error: 'Current password is incorrect.' }; }
      if (!mk.equals(vault.masterKey)) return { ok: false, error: 'Current password is incorrect.' };
      return vault.changePassword(next);
    } catch (err) { return { ok: false, error: err.message }; }
  });

  ipcMain.handle('vault:lock', () => {
    touch();
    vault.lock();
    pendingChallenge = null;
    if (win) win.webContents.send('vault:locked');
    return { ok: true };
  });

  ipcMain.handle('vault:rotateRecovery', needUnlock(() => ({ ok: true, recoveryCodes: vault.rotateRecoveryCodes() })));
  ipcMain.handle('vault:hasTwoFA', needUnlock(() => ({ ok: true, ...vault.hasTwoFA() })));
  ipcMain.handle('vault:disableTotp', needUnlock(() => vault.disableTotp()));
  ipcMain.handle('vault:listPasskeys', needUnlock(() => ({ ok: true, passkeys: vault.listPasskeys() })));
  ipcMain.handle('vault:removePasskey', needUnlock((e, { credId }) => vault.removePasskey(credId)));

  // TOTP setup
  ipcMain.handle('totp:start', needUnlock(async () => {
    const { secret, url } = vault.startTotpSetup();
    const qr = await QRCode.toDataURL(url, { margin: 1, width: 220, color: { dark: '#0f1117', light: '#ffffff' } });
    return { ok: true, secret, url, qr };
  }));
  ipcMain.handle('totp:confirm', needUnlock((e, { code }) => vault.confirmTotpSetup(code)));

  // Passkey registration
  ipcMain.handle('passkey:registerOptions', needUnlock((e, { name }) => {
    const challenge = newChallenge('register');
    return {
      ok: true,
      name,
      publicKey: {
        rp: { name: 'Secrete Vault', id: RP_ID },
        user: { id: crypto.randomBytes(16).toString('base64url'), name: 'vault-owner', displayName: 'Secrete Vault owner' },
        challenge,
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        timeout: 60000,
        attestation: 'none',
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
      },
    };
  }));
  ipcMain.handle('passkey:registerSubmit', needUnlock((e, { name, attestationObject, clientDataJSON }) => {
    const challenge = takeChallenge('register');
    if (!challenge) return { ok: false, error: 'Challenge expired, try again.' };
    try {
      return vault.addPasskey(attestationObject, clientDataJSON, challenge, name);
    } catch (err) { return { ok: false, error: 'Could not register passkey: ' + err.message }; }
  }));

  // Passkey assertion (unlock)
  ipcMain.handle('passkey:assertOptions', () => {
    touch();
    if (!vault.data?.twoFA?.passkeys?.length) return { ok: false, error: 'No passkey registered.' };
    const challenge = newChallenge('assert');
    return {
      ok: true,
      publicKey: {
        challenge,
        rpId: RP_ID,
        timeout: 60000,
        userVerification: 'required',
        allowCredentials: vault.data.twoFA.passkeys.map((p) => ({ type: 'public-key', id: p.credId })),
      },
    };
  });
  ipcMain.handle('passkey:assertSubmit', (e, { assertion }) => {
    touch();
    const challenge = takeChallenge('assert');
    if (!challenge) return { ok: false, error: 'Challenge expired, try again.' };
    const r = vault.completePasskey(assertion, challenge);
    if (r.ok && win) win.webContents.send('vault:unlocked');
    return r;
  });

  // Secrets CRUD
  ipcMain.handle('secrets:list', needUnlock(() => ({ ok: true, secrets: vault.listSecrets() })));
  ipcMain.handle('secrets:get', needUnlock((e, { id }) => ({ ok: true, secret: vault.getSecret(id) })));
  ipcMain.handle('secrets:save', needUnlock((e, { secret }) => ({ ok: true, secret: vault.saveSecret(secret) })));
  ipcMain.handle('secrets:delete', needUnlock((e, { id }) => vault.deleteSecret(id)));
  ipcMain.handle('secrets:generatePassword', (e, opts) => {
    touch();
    try { return { ok: true, password: Vault.generatePassword(opts) }; }
    catch (err) { return { ok: false, error: err.message }; }
  });

  // Google Drive backup (the renderer never sees the client secret or tokens)
  const asyncOk = (fn) => needUnlock(async (e, arg) => {
    try { return { ok: true, ...(await fn(arg)) }; } catch (err) { return { ok: false, error: err.message }; }
  });
  ipcMain.handle('backup:status', asyncOk(() => drive.status()));
  ipcMain.handle('backup:configure', asyncOk((creds) => drive.configure(creds)));
  ipcMain.handle('backup:connect', asyncOk(() => drive.connect()));
  ipcMain.handle('backup:disconnect', asyncOk(() => drive.disconnect()));
  ipcMain.handle('backup:now', asyncOk(() => drive.backupNow()));
}

/* ---------------- boot ---------------- */

app.whenReady().then(async () => {
  Menu.setApplicationMenu(null); // remove the standard File/Edit/View/… menu
  const port = await startLocalServer();
  registerIpc();
  createWindow(port);
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0 && server) createWindow(server.address().port);
  });
});

app.on('window-all-closed', async () => {
  vault.lock();
  // give a pending Drive upload up to 8 s to finish before quitting
  await Promise.race([drive.flush(), new Promise((r) => setTimeout(r, 8000))]);
  app.quit();
});
app.on('will-quit', () => { if (server) server.close(); });
