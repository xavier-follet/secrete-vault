'use strict';
/* Dump a real attestationObject from the CDP virtual authenticator for debugging. */
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
  const ws = new WebSocket((await getPage(9223)).webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();
  ws.onmessage = (e) => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  const send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
  const evaljs = async (expression) => {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    return r.result?.result?.value;
  };

  await send('WebAuthn.enable');
  await send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceEmulation: true } });

  const out = await evaljs(`(async () => {
    const b64urlToBuffer = (b64url) => { const b64 = b64url.replace(/-/g,'+').replace(/_/g,'/'); const pad = b64.length % 4 ? '='.repeat(4-(b64.length%4)) : ''; const bin = atob(b64+pad); const buf = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) buf[i]=bin.charCodeAt(i); return buf.buffer; };
    const bufferToB64url = (buf) => { const bytes = new Uint8Array(buf); let bin=''; for (let i=0;i<bytes.length;i++) bin+=String.fromCharCode(bytes[i]); return btoa(bin).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,''); };
    await api.setup({ password: 'debug-password-1' });
    const opts = await api.passkeyRegisterOptions({ name: 'debug' });
    const pk = opts.publicKey;
    pk.challenge = b64urlToBuffer(pk.challenge);
    pk.user.id = b64urlToBuffer(pk.user.id);
    const cred = await navigator.credentials.create({ publicKey: pk });
    return {
      id: cred.id,
      type: cred.type,
      attestationObject: bufferToB64url(cred.response.attestationObject),
      clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
    };
  })()`);
  require('fs').writeFileSync('C:/Users/xavie/AppData/Local/Temp/pk-attestation.json', JSON.stringify(out));
  console.log('saved. id:', out.id, 'type:', out.type, 'attLen:', out.attestationObject.length);
  ws.close();
  process.exit(0);
}
main().catch((e) => { console.error(e); process.exit(1); });
