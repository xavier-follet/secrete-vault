# Privacy policy

Secrete Vault is a desktop app that keeps your passwords and notes in an encrypted file on your own computer. This page says what the app does with your data. Last updated 23 November 2026.

## What the app collects

Nothing. The app has no accounts, no analytics, no crash reporting and no server run by its author. The author never receives any of your data.

## What is stored on your computer

- `vault.dat`: your secrets, encrypted with AES-256-GCM under a key protected by your master password. The app cannot read it without that password.
- `drive-backup.json`: only if you turn on Google Drive backup. It holds your Google client ID, plus your client secret and Google sign-in token encrypted with Windows secure storage.

Both files live in the app's user data folder (`%APPDATA%\SecreteVault` on Windows).

## Google Drive backup (optional, off by default)

If you connect Google Drive, the app:

- asks Google for one permission, `drive.file`, which lets the app see and change only the files it creates itself. It cannot see any other file in your Drive.
- creates one file in My Drive named `secrete-vault-backup.dat` and updates it after you change your vault, when you click **Back up now**, and when you close the app.
- uploads the vault file exactly as stored on disk, so the contents are encrypted. Google stores that file under your own account.
- keeps your Google sign-in token only on your computer.

The app talks to Google directly from your computer. No other service is involved.

Use of information received from Google APIs adheres to the [Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy), including the Limited Use requirements. The app uses Drive access only to store this one backup file, and does not share, sell or use it for anything else.

## How to remove your data

- Click **Disconnect** in the app's Security view, or revoke the app at [myaccount.google.com/permissions](https://myaccount.google.com/permissions).
- Delete `secrete-vault-backup.dat` from your Google Drive. Disconnecting does not delete it.
- Uninstall the app and delete its user data folder to remove the local files.

## Questions

Open an issue at [github.com/xavier-follet/secrete-vault/issues](https://github.com/xavier-follet/secrete-vault/issues).
