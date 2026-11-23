'use strict';
/**
 * Optional backup of the vault file to the user's own Google Drive.
 *
 * - Uploads vault.dat exactly as it sits on disk (already AES-256-GCM encrypted),
 *   so Google only ever sees ciphertext.
 * - Scope is drive.file: the app can touch only files it created itself.
 * - Sign-in is the installed-app flow: system browser + loopback redirect + PKCE.
 *   The user supplies their own OAuth client ID/secret (Google Cloud "Desktop app").
 * - The client secret and refresh token are stored with Electron safeStorage
 *   (Windows DPAPI), never inside vault.dat and never sent to the renderer.
 * Pure Node: Electron pieces (safeStorage, openUrl) and fetch are injected for tests.
 */
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const REVOKE_URL = 'https://oauth2.googleapis.com/revoke';
const UPLOAD_URL = 'https://www.googleapis.com/upload/drive/v3/files';
const SCOPE = 'https://www.googleapis.com/auth/drive.file';
const BACKUP_NAME = 'secrete-vault-backup.dat';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

async function apiError(res) {
  const j = await res.json().catch(() => ({}));
  return new Error((j.error && j.error.message) || j.error_description || `Google Drive error ${res.status}`);
}

class DriveBackup {
  constructor({ file, vaultPath, safeStorage, openUrl, onStatus = () => {}, fetchFn = fetch, debounceMs = 2000 }) {
    Object.assign(this, { file, vaultPath, safeStorage, openUrl, onStatus, fetchFn, debounceMs });
    this.cfg = this._load(); // { clientId, enc, fileId, lastOk, lastError }
    this.timer = null;
    this.running = null;
    this.dirty = false;
  }

  /* ---------- persisted config ---------- */

  _load() {
    try { return JSON.parse(fs.readFileSync(this.file, 'utf8')); } catch { return {}; }
  }
  _save() { fs.writeFileSync(this.file, JSON.stringify(this.cfg), { mode: 0o600 }); }
  _secrets() {
    if (!this.cfg.enc) return {};
    try { return JSON.parse(this.safeStorage.decryptString(Buffer.from(this.cfg.enc, 'base64'))); } catch { return {}; }
  }
  _setSecrets(obj) {
    this.cfg.enc = this.safeStorage.encryptString(JSON.stringify(obj)).toString('base64');
  }

  status() {
    const s = this._secrets();
    return {
      canEncrypt: this.safeStorage.isEncryptionAvailable(),
      hasClient: !!(this.cfg.clientId && s.clientSecret),
      connected: !!s.refreshToken,
      busy: !!this.running,
      lastOk: this.cfg.lastOk || null,
      lastError: this.cfg.lastError || null,
    };
  }

  configure({ clientId, clientSecret }) {
    clientId = String(clientId || '').trim();
    clientSecret = String(clientSecret || '').trim();
    if (!clientId || !clientSecret) throw new Error('Enter both the client ID and the client secret.');
    if (!this.safeStorage.isEncryptionAvailable()) throw new Error('Secure storage is not available on this device.');
    this.cfg.clientId = clientId;
    this._setSecrets({ clientSecret }); // a new client invalidates any old sign-in
    this.cfg.fileId = null;
    this._save();
    return this.status();
  }

  /* ---------- OAuth (system browser + loopback + PKCE) ---------- */

  async _post(url, form) {
    const res = await this.fetchFn(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form),
    });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(j.error_description || j.error || `Google error ${res.status}`);
      err.code = j.error;
      throw err;
    }
    return j;
  }

  async connect() {
    const { clientId } = this.cfg;
    const { clientSecret } = this._secrets();
    if (!clientId || !clientSecret) throw new Error('Enter your Google client ID and secret first.');

    const verifier = b64url(crypto.randomBytes(32));
    const state = b64url(crypto.randomBytes(16));
    const srv = http.createServer();
    await new Promise((res, rej) => { srv.once('error', rej); srv.listen(0, '127.0.0.1', res); });
    const redirect = `http://127.0.0.1:${srv.address().port}`;
    try {
      const code = await new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('Google sign-in timed out.')), 180000);
        t.unref();
        srv.on('request', (req, res) => {
          const q = new URL(req.url, redirect).searchParams;
          if (!q.has('state') && !q.has('error')) { res.writeHead(404).end(); return; } // favicon etc.
          const ok = q.get('state') === state && q.get('code');
          res.writeHead(ok ? 200 : 400, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end(ok ? 'Signed in. You can close this tab and go back to Secrete Vault.'
                     : 'Sign-in failed. Go back to Secrete Vault and try again.');
          clearTimeout(t);
          if (ok) resolve(q.get('code'));
          else reject(new Error(q.get('error') === 'access_denied' ? 'Google sign-in was cancelled.' : 'Google sign-in failed.'));
        });
        this.openUrl(AUTH_URL + '?' + new URLSearchParams({
          client_id: clientId,
          redirect_uri: redirect,
          response_type: 'code',
          scope: SCOPE,
          state,
          code_challenge: b64url(crypto.createHash('sha256').update(verifier).digest()),
          code_challenge_method: 'S256',
          access_type: 'offline',
          prompt: 'consent', // forces a refresh token even on re-connect
        }));
      });
      const tok = await this._post(TOKEN_URL, {
        client_id: clientId, client_secret: clientSecret, code,
        code_verifier: verifier, redirect_uri: redirect, grant_type: 'authorization_code',
      });
      if (!tok.refresh_token) throw new Error('Google did not return a refresh token. Try connecting again.');
      this._setSecrets({ clientSecret, refreshToken: tok.refresh_token });
      this.cfg.fileId = null;
      this.cfg.lastError = null;
      this._save();
    } finally {
      srv.close();
      if (srv.closeAllConnections) srv.closeAllConnections();
    }
    await this.backupNow(); // first copy right away
    return this.status();
  }

  async disconnect() {
    const s = this._secrets();
    if (s.refreshToken) {
      // best effort: tell Google to drop the grant. The backup file in Drive stays.
      await this._post(REVOKE_URL, { token: s.refreshToken }).catch(() => {});
    }
    this._setSecrets({ clientSecret: s.clientSecret });
    this.cfg.fileId = null;
    this.cfg.lastError = null;
    this._save();
    return this.status();
  }

  async _accessToken() {
    const { clientId } = this.cfg;
    const { clientSecret, refreshToken } = this._secrets();
    try {
      const r = await this._post(TOKEN_URL, {
        client_id: clientId, client_secret: clientSecret, refresh_token: refreshToken, grant_type: 'refresh_token',
      });
      return r.access_token;
    } catch (err) {
      if (err.code === 'invalid_grant') {
        this._setSecrets({ clientSecret }); // grant is dead: show "connect" again
        throw new Error('Google sign-in expired. Connect Google Drive again.');
      }
      throw err;
    }
  }

  /* ---------- upload ---------- */

  async _send(token, bytes) {
    const auth = { Authorization: 'Bearer ' + token };
    if (this.cfg.fileId) {
      const r = await this.fetchFn(`${UPLOAD_URL}/${this.cfg.fileId}?uploadType=media`, {
        method: 'PATCH', headers: { ...auth, 'Content-Type': 'application/octet-stream' }, body: bytes,
      });
      if (r.ok) return this.cfg.fileId;
      if (r.status !== 404) throw await apiError(r); // 404 = file was removed, create it again
    }
    const boundary = 'sv' + crypto.randomBytes(8).toString('hex');
    const body = Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify({ name: BACKUP_NAME })}\r\n` +
                  `--${boundary}\r\nContent-Type: application/octet-stream\r\n\r\n`),
      bytes,
      Buffer.from(`\r\n--${boundary}--`),
    ]);
    const r = await this.fetchFn(`${UPLOAD_URL}?uploadType=multipart&fields=id`, {
      method: 'POST', headers: { ...auth, 'Content-Type': `multipart/related; boundary=${boundary}` }, body,
    });
    if (!r.ok) throw await apiError(r);
    return (await r.json()).id;
  }

  async _upload() {
    try {
      if (!this.status().connected) throw new Error('Google Drive is not connected.');
      const token = await this._accessToken();
      this.cfg.fileId = await this._send(token, fs.readFileSync(this.vaultPath));
      this.cfg.lastOk = new Date().toISOString();
      this.cfg.lastError = null;
    } catch (err) {
      this.cfg.lastError = err.message;
    }
    this._save();
    this.onStatus(this.status());
    return this.status();
  }

  /** Upload now. Never rejects: failures land in status().lastError. */
  backupNow() {
    if (this.running) { this.dirty = true; return this.running; }
    this.running = this._upload().finally(() => {
      this.running = null;
      if (this.dirty) { this.dirty = false; this.schedule(); }
    });
    this.onStatus(this.status());
    return this.running;
  }

  /** Called after every vault write; batches bursts of saves into one upload. */
  schedule() {
    if (!this.status().connected) return;
    clearTimeout(this.timer);
    this.timer = setTimeout(() => { this.timer = null; this.backupNow(); }, this.debounceMs);
  }

  /** Push any pending change now (used on lock and quit). */
  async flush() {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; await this.backupNow(); }
    else if (this.running) await this.running;
  }
}

module.exports = { DriveBackup, BACKUP_NAME };
