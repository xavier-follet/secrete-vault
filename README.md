# Secrete Vault

A local-first, encrypted secret vault built with **Electron**. Secrets never leave
your machine unless you turn on the optional Google Drive backup — there is no
server, no account, no telemetry.

## Run

```bash
npm install
npm start          # launch the app (dev)
npm test           # crypto unit tests (plain Node)
npm run test:smoke # full Electron end-to-end test (drives the real UI)
npm run dist       # build Windows exe into dist/
```

### Windows build output (`npm run dist`)

| File | What it is |
|---|---|
| `dist/Secrete Vault-Setup-1.0.0-x64.exe` | NSIS installer (install dir choice, desktop + start-menu shortcuts, uninstaller) |
| `dist/Secrete Vault-1.0.0-x64-portable.exe` | single portable exe, runs from anywhere (vault still goes to `%APPDATA%\Secrete Vault\vault.dat`) |

The app is packed into an asar archive with a custom lock icon
(`npm run icon` regenerates `build/icon.png`). The exe is **unsigned** —
Windows SmartScreen will warn on first run until the binary gains reputation;
sign it with a code-signing certificate (`CSC_LINK`/`CSC_KEY_PASSWORD`) before
distributing widely.

## What it does

### First run (setup)
1. **Master password** — with a live strength meter.
2. **Optional 2FA**, choose one:
   - **Authenticator app** — TOTP (RFC 6238): shows a QR code + manual key, you
     confirm a 6-digit code to enable it.
   - **Passkey** — WebAuthn with the platform authenticator (Windows Hello /
     Touch ID), verified with an ES256 signature at every unlock.
3. **Recovery codes** — 10 single-use codes (`XXXXX-XXXXX-XXXXX`), shown once,
   with copy / `.txt` download. Each code works exactly once and bypasses 2FA.

### Vault
- Sidebar list of secrets (searchable), click one to open its form:
  - **Title**
  - **Login** → username + password (show/hide, copy, built-in generator)
  - **Note** → free text
- A new secret is saved with **Save**; from then on every edit autosaves. A
  validation error (for example an empty title) pauses autosave and shows the
  message. Leaving an unsaved secret (opening another, Security, the Lock
  button, closing the window) asks first.
- Auto-lock after 5 minutes idle keeps an unsaved draft in the form and
  restores it when you unlock. The Lock button locks instantly.
- Delete, change master password, manage 2FA and recovery codes in
  *Security settings*.
- Security view (sidebar, bottom): change master password, manage the
  authenticator and passkeys, make new recovery codes.

### Backup to Google Drive (optional, off by default)
Security view, "Backup to Google Drive". After you connect it, the app uploads
`vault.dat` (still encrypted, so Google only sees ciphertext) to your Drive about
2 seconds after every change, on **Back up now**, and when you close the app.

- Sign-in is Google's installed-app flow (system browser, loopback redirect,
  PKCE). Scope is `drive.file`: the app can only see the one file it created,
  `secrete-vault-backup.dat`, in My Drive.
- You bring your own OAuth client: in Google Cloud Console enable the Drive API,
  set up the OAuth consent screen, **publish** it (in testing mode Google expires
  the sign-in after 7 days), then create a *Desktop app* client and paste its ID
  and secret into the app.
- The client secret and refresh token are stored with Electron `safeStorage`
  (Windows DPAPI) in `drive-backup.json` next to the vault. They never enter
  `vault.dat` or the renderer.
- Restore: close the app, download `secrete-vault-backup.dat` from Drive and
  save it over `vault.dat` (path shown at the bottom of the Security view).
  There is no in-app restore button yet.
- The backup can be attacked offline, so the master password is the only
  protection: use a strong one.

See [PRIVACY.md](PRIVACY.md) for what the app does with your data.

### Look and feel
"Enamel safe": green-black painted steel, ivory lettering, and a combination
dial on the setup and unlock screens that clicks once per keystroke. Fonts are
bundled in `renderer/fonts/` (no network): Archivo and Martian Mono, both under
the SIL Open Font License 1.1 (license files alongside).
`npx electron test/shot.js --no-sandbox <outDir>` screenshots every screen.

## Where the file lives

One encrypted file in the OS user folder (`app.getPath('userData')`):

| OS | Path |
|---|---|
| Windows | `%APPDATA%\SecreteVault\vault.dat` |
| macOS | `~/Library/Application Support/SecreteVault/vault.dat` |
| Linux | `~/.config/SecreteVault/vault.dat` |

Written atomically (tmp + rename), permission `0600`.

## Security design

```
vault.dat (JSON)
├─ kdf      scrypt params + salt            (N=32768, r=8, p=1)
├─ keyWrap  AES-256-GCM( scrypt(password), masterKey )
├─ check    AES-256-GCM( masterKey, const )  ← verifies the key
├─ payload  AES-256-GCM( masterKey, secrets )← the actual data
└─ recovery [{ id, salt, hash, wrap: AES-256-GCM( scrypt(code), masterKey ) }]
```

- The payload is encrypted with a **random 32-byte master key**, so changing
  the password or consuming recovery codes never re-encrypts the secrets —
  only the wraps change.
- AES-256-GCM everywhere: any tampering with the file fails authentication.
- Recovery codes are stored only as salted SHA-256 hashes; each is single-use.
- TOTP secret and passkey public keys live *inside* the encrypted payload;
  2FA is enforced at unlock time (password → TOTP/passkey).
- Renderer has `contextIsolation: true`, `nodeIntegration: false`,
  `sandbox: true`; it talks to the main process only through a minimal
  `contextBridge` API (`src/preload.js`). Decrypted data exists only in the
  main process memory and is wiped on lock.
- The renderer is served by a **loopback-only HTTP server** on
  `127.0.0.1` (ephemeral port, Host-header checked). Chromium only permits
  WebAuthn passkeys on HTTPS origins or plain-HTTP `localhost` origins, so the
  app loads as `http://localhost:<port>/` — a secure context with rpId
  `localhost` — which is what makes passkeys work in a local app.

## Project layout

```
src/
  main.js      Electron main: window, IPC API, auto-lock, WebAuthn options
  preload.js   contextBridge API exposed to the renderer
  vault.js     vault file format, crypto, CRUD, recovery, 2FA (pure Node)
  totp.js      base32 + HOTP/TOTP + otpauth:// URLs
  webauthn.js  minimal CBOR decoder, attestation parsing, assertion verify
  drive.js     optional Google Drive backup (OAuth loopback + PKCE, upload)
renderer/
  index.html   setup / unlock / vault screens
  styles.css
  app.js       UI state machine + WebAuthn client calls
test/
  vault.test.js  18 crypto tests (node test/vault.test.js)
  smoke.js       23 end-to-end checks inside real Electron
```

## Notes

- Passkeys use the OS platform authenticator. If the OS/browser stack refuses
  (`NotAllowedError`), the app shows the error and you can use an authenticator
  app instead — TOTP is the fully portable 2FA path.
- Back up `vault.dat` **and** your recovery codes; without them there is no
  way back in (by design).
