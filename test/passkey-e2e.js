'use strict';
/**
 * Passkey + inline-TOTP end-to-end test against the dev app via CDP.
 *
 * Prereq: the app must be running with --remote-debugging-port=9223, e.g.:
 *   npx electron . --no-sandbox --remote-debugging-port=9223 --user-data-dir=<tmp>
 * Then: node test/passkey-e2e.js
 *
 * Uses a CDP virtual authenticator to simulate a platform passkey (Windows Hello).
 */
const { totp } = require('../src/totp');

async function getPage(port) {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/json`);
      const list = await r.json();
      const page = list.find((t) => t.type === 'page' && t.url.includes('localhost'));
      if (page) return page;
    } catch {}
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('no page target');
}

async function main() {
  const port = 9223;
  const page = await getPage(port);
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  };
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  const send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
  const evaljs = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) throw new Error('page exception: ' + JSON.stringify(r.result.exceptionDetails).slice(0, 400));
    return r.result?.result?.value;
  };

  // 0) wait until the app page is fully loaded
  for (let i = 0; i < 50; i++) {
    const ready = await evaljs('!!window.api && !!document.querySelector("#setup-password")').catch(() => false);
    if (ready) break;
    await new Promise((r) => setTimeout(r, 300));
  }

  // 1) virtual platform authenticator
  await send('WebAuthn.enable');
  const va = await send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
      automaticPresenceEmulation: true,
    },
  });
  console.log('virtual authenticator:', va.result?.authenticatorId ? 'added' : JSON.stringify(va).slice(0, 200));

  let failures = 0;
  const check = (label, cond, extra) => {
    if (cond) console.log('  ✔ ' + label);
    else { failures++; console.error('  ✘ ' + label + (extra !== undefined ? ' -> ' + JSON.stringify(extra) : '')); }
  };

  // 2) setup with passkey through the real UI
  const r1 = await evaljs(`(async () => {
    const out = {};
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const $ = (s) => document.querySelector(s);
    const waitFor = async (fn, ms = 10000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(100); } return false; };
    $('#setup-password').value = 'pk-test-password-1';
    $('#setup-password2').value = 'pk-test-password-1';
    $('#setup-pw-next').click();
    await waitFor(() => !$('#setup-step-2fa').classList.contains('hidden'));
    $('#choose-passkey').click();
    await sleep(300);
    $('#passkey-name').value = 'Test Laptop';
    $('#passkey-create').click();
    out.registered = await waitFor(() => !$('#passkey-ok').classList.contains('hidden'));
    out.error = $('#passkey-error').textContent;
    out.twoFA = await api.hasTwoFA();
    out.passkeys = await api.listPasskeys();
    return out;
  })()`);
  console.log('Passkey registration via UI');
  check('passkey registered through UI', r1.registered === true, r1.error);
  check('vault reports 1 passkey', r1.twoFA?.passkeys === 1, r1.twoFA);
  check('passkey name stored', r1.passkeys?.passkeys?.[0]?.name === 'Test Laptop', r1.passkeys);

  // 3) open vault, add TOTP via the inline security-panel box
  const r2 = await evaljs(`(async () => {
    const out = {};
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const $ = (s) => document.querySelector(s);
    const waitFor = async (fn, ms = 10000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(100); } return false; };
    $('#recovery-open').click();
    await waitFor(() => $('#view-vault').classList.contains('active'));
    document.querySelector('.security-panel').open = true;
    await sleep(200);
    $('#sec-add-totp').click();
    out.boxShown = await waitFor(() => !$('#sec-totp-box').classList.contains('hidden'));
    out.qrLoads = await waitFor(() => { const im = $('#sec-totp-qr'); return im.complete && im.naturalWidth > 0; });
    out.secret = $('#sec-totp-secret').textContent;
    return out;
  })()`);
  console.log('Inline authenticator (TOTP) box in settings');
  check('settings TOTP box opens', r2.boxShown === true);
  check('settings QR image renders', r2.qrLoads === true);

  const code = totp(r2.secret);
  const r3 = await evaljs(`(async () => {
    const out = {};
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const $ = (s) => document.querySelector(s);
    const waitFor = async (fn, ms = 10000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(100); } return false; };
    $('#sec-totp-code').value = '${code}';
    $('#sec-totp-verify').click();
    out.boxClosed = await waitFor(() => $('#sec-totp-box').classList.contains('hidden'));
    out.secOk = $('#sec-ok').textContent;
    out.twoFA = await api.hasTwoFA();
    return out;
  })()`);
  check('TOTP enabled from settings box', r3.boxClosed === true && r3.twoFA?.totp === true, r3.secOk);

  // 4) lock, unlock with password, then passkey at the 2FA gate
  const r4 = await evaljs(`(async () => {
    const out = {};
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const $ = (s) => document.querySelector(s);
    const waitFor = async (fn, ms = 10000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(100); } return false; };
    await api.lock();
    await waitFor(() => $('#view-unlock').classList.contains('active'));
    $('#unlock-password').value = 'pk-test-password-1';
    $('#unlock-btn').click();
    out.gateShown = await waitFor(() => !$('#unlock-2fa-wrap').classList.contains('hidden'));
    out.passkeyBtnVisible = !$('#unlock-passkey-wrap').classList.contains('hidden');
    $('#unlock-passkey-btn').click();
    out.unlocked = await waitFor(() => $('#view-vault').classList.contains('active'));
    out.error = $('#unlock-passkey-error').textContent;
    return out;
  })()`);
  console.log('Passkey unlock at the 2FA gate');
  check('2FA gate shown after password', r4.gateShown === true);
  check('passkey button offered', r4.passkeyBtnVisible === true);
  check('passkey unlocks the vault', r4.unlocked === true, r4.error);

  console.log(failures === 0 ? '\nPASSKEY E2E OK' : `\n${failures} FAILURES`);
  ws.close();
  process.exit(failures === 0 ? 0 : 1);
}
main().catch((e) => { console.error(e); process.exit(1); });
