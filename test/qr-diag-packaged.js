'use strict';
/**
 * Diagnostic against the PACKAGED exe via CDP.
 * Launch the exe first with: APPDATA=<tmp> "dist/Secrete Vault-1.0.0-x64-portable.exe" --no-sandbox --remote-debugging-port=9222
 * Then: node test/qr-diag-packaged.js
 */
async function getTarget(port) {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/json`);
      const list = await r.json();
      const page = list.find((t) => t.type === 'page' && t.url.includes('localhost'));
      if (page) return page;
    } catch {}
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('no page target found');
}

async function main() {
  const port = 9222;
  const target = await getTarget(port);
  console.log('target:', target.url);
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  };
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  const send = (method, params) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });

  await send('Runtime.enable');
  // Drive the REAL setup UI: password -> "Authenticator app" -> QR must render
  const expr = `(async () => {
    const out = {};
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const $ = (s) => document.querySelector(s);
    const waitFor = async (fn, ms = 8000) => {
      const t0 = Date.now();
      while (Date.now() - t0 < ms) { if (fn()) return true; await sleep(100); }
      return false;
    };
    window.__csp = [];
    window.__errs = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(e.violatedDirective + ' blocked ' + e.blockedURI));
    window.addEventListener('error', (e) => window.__errs.push('error: ' + e.message));
    window.addEventListener('unhandledrejection', (e) => window.__errs.push('rejection: ' + String(e.reason && e.reason.message || e.reason)));

    out.hasApi = !!window.api;
    out.status = await api.status();
    $('#setup-password').value = 'diag-password-123';
    $('#setup-password2').value = 'diag-password-123';
    $('#setup-pw-next').click();
    out.step2fa = await waitFor(() => !$('#setup-step-2fa').classList.contains('hidden'));
    out.pwError = $('#setup-pw-error').textContent;
    out.vaultCreated = (await api.status()).exists === true;
    $('#choose-totp').click();
    out.qrImgLoads = await waitFor(() => {
      const im = $('#totp-qr');
      return im.complete && im.naturalWidth > 0 && im.naturalHeight > 0;
    });
    out.totpErrorText = $('#totp-error').textContent;
    out.qrSrcPrefix = String($('#totp-qr').src).slice(0, 30);
    out.cspViolations = window.__csp;
    out.jsErrors = window.__errs;
    return out;
  })()`;
  const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
  console.log(JSON.stringify(r.result?.result?.value ?? r, null, 2));
  ws.close();
  process.exit(0);
}
main().catch((e) => { console.error(e); process.exit(1); });
