'use strict';
/**
 * Preload bridge: exposes a minimal, explicit API to the renderer.
 * contextIsolation is on; the renderer has no direct Node access.
 */
const { contextBridge, ipcRenderer } = require('electron');

const invoke = (channel) => (...args) => ipcRenderer.invoke(channel, ...args);

contextBridge.exposeInMainWorld('api', {
  // vault lifecycle
  status: invoke('vault:status'),
  setup: invoke('vault:setup'),
  unlock: invoke('vault:unlock'),
  unlockTotp: invoke('vault:unlockTotp'),
  unlockRecovery: invoke('vault:unlockRecovery'),
  changePassword: invoke('vault:changePassword'),
  lock: invoke('vault:lock'),
  rotateRecovery: invoke('vault:rotateRecovery'),
  hasTwoFA: invoke('vault:hasTwoFA'),
  disableTotp: invoke('vault:disableTotp'),
  listPasskeys: invoke('vault:listPasskeys'),
  removePasskey: invoke('vault:removePasskey'),

  // TOTP (authenticator app) setup
  totpStart: invoke('totp:start'),
  totpConfirm: invoke('totp:confirm'),

  // passkeys (WebAuthn)
  passkeyRegisterOptions: invoke('passkey:registerOptions'),
  passkeyRegisterSubmit: invoke('passkey:registerSubmit'),
  passkeyAssertOptions: invoke('passkey:assertOptions'),
  passkeyAssertSubmit: invoke('passkey:assertSubmit'),

  // secrets
  listSecrets: invoke('secrets:list'),
  getSecret: invoke('secrets:get'),
  saveSecret: invoke('secrets:save'),
  deleteSecret: invoke('secrets:delete'),
  generatePassword: invoke('secrets:generatePassword'),

  // Google Drive backup
  backupStatus: invoke('backup:status'),
  backupConfigure: invoke('backup:configure'),
  backupConnect: invoke('backup:connect'),
  backupDisconnect: invoke('backup:disconnect'),
  backupNow: invoke('backup:now'),
  onBackupStatus: (cb) => ipcRenderer.on('backup:status', (_e, st) => cb(st)),

  // events from main (auto-lock etc.)
  onLocked: (cb) => ipcRenderer.on('vault:locked', cb),
  onUnlocked: (cb) => ipcRenderer.on('vault:unlocked', cb),
});
