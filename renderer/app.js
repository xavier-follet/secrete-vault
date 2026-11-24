'use strict';
/* Secrete Vault — renderer app (no Node access; talks to main via window.api) */

/* ---------------- helpers ---------------- */
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const icon = (name) => `<svg class="ic"><use href="#i-${name}"/></svg>`;
const reducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;

function showView(name) {
  $$('.view').forEach((v) => v.classList.remove('active'));
  $('#view-' + name).classList.add('active');
  document.body.dataset.view = name;
}

const SETUP_STEPS = { '#setup-step-password': 1, '#setup-step-2fa': 2, '#setup-step-recovery': 3 };
function showStep(id) {
  $$('#view-setup .step').forEach((s) => s.classList.add('hidden'));
  $(id).classList.remove('hidden');
  $('#view-setup').dataset.step = SETUP_STEPS[id];
  dialSet((SETUP_STEPS[id] - 1) * 36);
}

/* ---------------- the dial (setup + unlock backdrop) ---------------- */
const DIAL_TICK = 3.6; // 100 ticks per turn
let dialAngle = 0;

function buildDial() {
  let g = '<circle class="dial-disc" cx="200" cy="200" r="196"/><circle class="dial-edge" cx="200" cy="200" r="148"/>';
  for (let i = 0; i < 100; i++) {
    const major = i % 5 === 0;
    const rot = `rotate(${(i * DIAL_TICK).toFixed(1)} 200 200)`;
    g += `<line class="dial-tick${major ? ' major' : ''}" x1="200" y1="10" x2="200" y2="${major ? 30 : 21}" transform="${rot}"/>`;
    if (i % 10 === 0) g += `<text class="dial-num" x="200" y="44" transform="${rot}">${i}</text>`;
  }
  $('#dial-ring').innerHTML = g;
}
function dialSet(deg) {
  dialAngle = deg;
  $('#dial-ring').style.transform = `rotate(${deg}deg)`;
}
function dialShake() {
  const d = $('#dial');
  d.classList.remove('shake');
  void d.offsetWidth; // restart the animation
  d.classList.add('shake');
}
/** Turn the dial a full lap and resolve when it has landed. */
function dialSweep() {
  if (reducedMotion()) return Promise.resolve();
  const d = $('#dial');
  d.classList.add('sweep');
  dialSet(dialAngle + 360 + 9 * DIAL_TICK);
  return new Promise((r) => setTimeout(() => { d.classList.remove('sweep'); r(); }, 950));
}
function initDial() {
  buildDial();
  // each keystroke on a gate screen clicks the dial one tick
  document.addEventListener('input', (e) => {
    if (!e.target.closest || !e.target.closest('.gate')) return;
    dialSet(dialAngle + (e.inputType && e.inputType.startsWith('delete') ? -DIAL_TICK : DIAL_TICK));
  });
  // any new error message on a gate screen rattles the dial
  new MutationObserver((muts) => {
    if (muts.some((m) => m.target.classList && m.target.classList.contains('error') && m.target.textContent && m.target.closest('.gate'))) dialShake();
  }).observe(document.body, { childList: true, subtree: true });
}

let toastTimer = null;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 2200);
}

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast('Copied'); }
  catch {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove(); toast('Copied');
  }
}

function downloadText(filename, text) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

/* base64url <-> ArrayBuffer for WebAuthn */
function b64urlToBuffer(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
  const bin = atob(b64 + pad);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufferToB64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Run a WebAuthn create() ceremony and register the credential with the vault. */
async function registerPasskey(name) {
  const opts = await api.passkeyRegisterOptions({ name });
  if (!opts.ok) throw new Error(opts.error);
  const pk = opts.publicKey;
  pk.challenge = b64urlToBuffer(pk.challenge);
  pk.user.id = b64urlToBuffer(pk.user.id);
  const cred = await navigator.credentials.create({ publicKey: pk });
  if (!cred) throw new Error('No credential returned.');
  const r = await api.passkeyRegisterSubmit({
    name,
    attestationObject: bufferToB64url(cred.response.attestationObject),
    clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
  });
  if (!r.ok) throw new Error(r.error);
  return r;
}

/**
 * Two-step inline confirm (Electron has no window.confirm): the first click
 * arms the button for 3 s, the second click runs the action.
 */
function twoStepConfirm(btn, armedLabel, fn) {
  if (btn.dataset.armed === '1') {
    delete btn.dataset.armed;
    btn.textContent = btn.dataset.orig;
    fn();
    return;
  }
  btn.dataset.armed = '1';
  btn.dataset.orig = btn.textContent;
  btn.textContent = armedLabel;
  btn.classList.add('danger');
  setTimeout(() => {
    delete btn.dataset.armed;
    btn.textContent = btn.dataset.orig;
    btn.classList.remove('danger');
  }, 3000);
}

function passwordEntropy(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  return pw.length * Math.log2(pool || 1);
}

function updateMeter() {
  const pw = $('#setup-password').value;
  const e = passwordEntropy(pw);
  const bar = $('#pw-meter');
  const label = $('#pw-meter-label');
  const pct = Math.min(100, (e / 80) * 100);
  bar.style.width = pct + '%';
  let txt = '', color = 'var(--rust)';
  if (pw.length === 0) { txt = ''; }
  else if (e < 28) { txt = 'Weak'; color = 'var(--rust)'; }
  else if (e < 50) { txt = 'Fair'; color = 'var(--amber)'; }
  else if (e < 65) { txt = 'Good'; color = '#b9d977'; }
  else { txt = 'Strong'; color = 'var(--mint)'; }
  bar.style.background = color;
  label.textContent = txt;
}

/* ---------------- app state ---------------- */
const state = {
  setupDone: false,       // vault file created during setup
  setupPassword: null,
  recoveryCodes: [],
  secrets: [],
  currentId: null,
  currentType: 'login',
  unlocked: false,
  dirty: false,           // the open form has edits that are not saved yet
  rev: 0,                 // bumps on every edit, so a save knows if newer edits arrived meanwhile
};
let autosaveTimer = null;

/* ---------------- boot ---------------- */
async function boot() {
  const st = await api.status();
  $('#vault-path').textContent = 'Vault file: ' + st.path;
  $('#sec-path').textContent = st.path;
  if (!st.exists) {
    showView('setup');
    showStep('#setup-step-password');
  } else {
    showView('unlock');
    $('#unlock-password').focus();
  }
  api.onLocked(() => {
    state.unlocked = false;
    state.secrets = [];
    clearTimeout(autosaveTimer);
    // an unsaved draft survives the lock; anything else is wiped from the form
    if (!state.dirty) { state.currentId = null; $('#detail-form').reset(); }
    showView('unlock');
    resetUnlockForm();
    toast(state.dirty ? 'Vault locked. Your unsaved edits are kept until you unlock.' : 'Vault locked');
  });
  // closing the window: main shows the warning dialog when this blocks the unload
  window.addEventListener('beforeunload', (e) => { if (state.dirty) { e.preventDefault(); e.returnValue = ''; } });
}

/* ---------------- setup flow ---------------- */
function initSetup() {
  $('#setup-password').addEventListener('input', updateMeter);

  $('#setup-pw-next').addEventListener('click', async () => {
    const p1 = $('#setup-password').value;
    const p2 = $('#setup-password2').value;
    const err = $('#setup-pw-error');
    err.textContent = '';
    if (p1.length < 8) { err.textContent = 'Password must be at least 8 characters.'; return; }
    if (p1 !== p2) { err.textContent = 'Passwords do not match.'; return; }
    if (passwordEntropy(p1) < 28) { err.textContent = 'Password is too weak — use a longer one.'; return; }
    // Create the vault file NOW, so the 2FA step can configure it while unlocked.
    if (!state.setupDone) {
      const r = await api.setup({ password: p1, issuer: 'Secrete Vault', account: 'vault' });
      if (!r.ok) { err.textContent = r.error; return; }
      state.setupDone = true;
      state.setupPassword = p1;
      state.recoveryCodes = r.recoveryCodes;
    }
    $('#setup-password').value = '';
    $('#setup-password2').value = '';
    showStep('#setup-step-2fa');
  });

  $('#choose-skip').addEventListener('click', () => showRecoveryStep());
  $('#totp-back').addEventListener('click', () => { $('#setup-totp').classList.add('hidden'); });
  $('#passkey-back').addEventListener('click', () => { $('#setup-passkey').classList.add('hidden'); });
  $('#recovery-back').addEventListener('click', () => showStep('#setup-step-2fa'));

  $('#choose-totp').addEventListener('click', async () => {
    $('#setup-totp').classList.remove('hidden');
    $('#totp-error').textContent = '';
    $('#totp-qr').removeAttribute('src');
    const r = await api.totpStart();
    if (!r.ok) { $('#totp-error').textContent = r.error; return; }
    $('#totp-qr').src = r.qr;
    $('#totp-secret').textContent = r.secret;
  });
  $('#totp-copy').addEventListener('click', () => copyText($('#totp-secret').textContent));
  $('#totp-verify').addEventListener('click', async () => {
    const r = await api.totpConfirm({ code: $('#totp-code').value });
    if (r.ok) { toast('Authenticator enabled'); showRecoveryStep(); }
    else $('#totp-error').textContent = r.error;
  });

  $('#choose-passkey').addEventListener('click', () => {
    $('#setup-passkey').classList.remove('hidden');
    $('#passkey-error').textContent = '';
    $('#passkey-ok').classList.add('hidden');
  });
  $('#passkey-create').addEventListener('click', async () => {
    $('#passkey-error').textContent = '';
    try {
      const name = $('#passkey-name').value.trim() || 'This device';
      await registerPasskey(name);
      $('#passkey-ok').classList.remove('hidden');
      setTimeout(showRecoveryStep, 700);
    } catch (err) {
      $('#passkey-error').textContent = String(err.message || err).replace(/^Error:\s*/, '');
    }
  });

  $('#recovery-copy').addEventListener('click', () => copyText(state.recoveryCodes.join('\n')));
  $('#recovery-download').addEventListener('click', () =>
    downloadText('secrete-vault-recovery-codes.txt',
      'Secrete Vault recovery codes\nEach code works once.\n\n' + state.recoveryCodes.join('\n') + '\n'));
  $('#recovery-open').addEventListener('click', async () => {
    const err = $('#recovery-error');
    err.textContent = '';
    await enterVault();
  });
}

function showRecoveryStep() {
  const box = $('#recovery-codes');
  box.innerHTML = '';
  state.recoveryCodes.forEach((c) => {
    const s = document.createElement('span');
    s.textContent = c;
    box.appendChild(s);
  });
  showStep('#setup-step-recovery');
}

/* ---------------- unlock flow ---------------- */
function resetUnlockForm() {
  $('#unlock-password-wrap').classList.remove('hidden');
  $('#unlock-2fa-wrap').classList.add('hidden');
  $('#unlock-recovery-wrap').classList.add('hidden');
  $('#unlock-error').textContent = '';
  $('#unlock-totp-error').textContent = '';
  $('#unlock-passkey-error').textContent = '';
  $('#unlock-recovery-error').textContent = '';
  $('#unlock-password').value = '';
  $('#unlock-totp').value = '';
  $('#unlock-recovery').value = '';
}

function initUnlock() {
  $('#unlock-btn').addEventListener('click', doUnlockPassword);
  $('#unlock-password').addEventListener('keydown', (e) => { if (e.key === 'Enter') doUnlockPassword(); });

  $('#show-recovery').addEventListener('click', (e) => {
    e.preventDefault();
    $('#unlock-password-wrap').classList.add('hidden');
    $('#unlock-recovery-wrap').classList.remove('hidden');
  });
  $('#recovery-back').addEventListener('click', (e) => { e.preventDefault(); resetUnlockForm(); });
  $('#unlock-back').addEventListener('click', (e) => { e.preventDefault(); resetUnlockForm(); });

  $('#unlock-totp-btn').addEventListener('click', async () => {
    const r = await api.unlockTotp({ code: $('#unlock-totp').value });
    if (r.ok) await enterVault();
    else $('#unlock-totp-error').textContent = r.error;
  });
  $('#unlock-totp').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#unlock-totp-btn').click(); });

  $('#unlock-passkey-btn').addEventListener('click', async () => {
    $('#unlock-passkey-error').textContent = '';
    try {
      const opts = await api.passkeyAssertOptions();
      if (!opts.ok) throw new Error(opts.error);
      const pk = opts.publicKey;
      pk.challenge = b64urlToBuffer(pk.challenge);
      pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64urlToBuffer(c.id) }));
      const cred = await navigator.credentials.get({ publicKey: pk });
      if (!cred) throw new Error('No credential returned.');
      const r = await api.passkeyAssertSubmit({
        assertion: {
          id: cred.id,
          response: {
            clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
            authenticatorData: bufferToB64url(cred.response.authenticatorData),
            signature: bufferToB64url(cred.response.signature),
          },
        },
      });
      if (r.ok) await enterVault();
      else $('#unlock-passkey-error').textContent = r.error;
    } catch (err) {
      $('#unlock-passkey-error').textContent = String(err.message || err).replace(/^Error:\s*/, '');
    }
  });

  $('#unlock-recovery-btn').addEventListener('click', async () => {
    const r = await api.unlockRecovery({ code: $('#unlock-recovery').value });
    if (r.ok) { toast('Unlocked with a recovery code. Change your password in Security.'); await enterVault(); }
    else $('#unlock-recovery-error').textContent = r.error;
  });
}

async function doUnlockPassword() {
  const pw = $('#unlock-password').value;
  $('#unlock-error').textContent = '';
  const r = await api.unlock({ password: pw });
  if (!r.ok) { $('#unlock-error').textContent = r.error; return; }
  if (r.locked2FA) {
    $('#unlock-password-wrap').classList.add('hidden');
    $('#unlock-2fa-wrap').classList.remove('hidden');
    if (r.needTotp) { $('#unlock-totp-wrap').classList.remove('hidden'); $('#unlock-totp').focus(); }
    else $('#unlock-totp-wrap').classList.add('hidden');
    if (r.needPasskey) $('#unlock-passkey-wrap').classList.remove('hidden');
    else $('#unlock-passkey-wrap').classList.add('hidden');
  } else {
    $('#unlock-password').value = '';
    await enterVault();
  }
}

/* ---------------- vault view ---------------- */
async function enterVault() {
  state.unlocked = true;
  await dialSweep(); // the one reveal: dial turns, then the vault opens
  showView('vault');
  resetUnlockForm();
  await refreshSecrets();
  await refreshSecurityPanel();
}

async function reloadList() {
  const r = await api.listSecrets();
  if (!r.ok) { if (r.locked) { showView('unlock'); } return false; }
  state.secrets = r.secrets;
  renderList();
  return true;
}

async function refreshSecrets(selectId) {
  if (!(await reloadList())) return;
  if (state.dirty) { // keep the draft in the form; resume saving it if it belongs to a saved secret
    $('#f-error').textContent = '';
    scheduleAutosave();
    return;
  }
  if (selectId) selectSecret(selectId);
  else if (state.currentId) selectSecret(state.currentId);
  else showEmpty();
}

function renderList() {
  const q = $('#search').value.trim().toLowerCase();
  const ul = $('#secret-list');
  ul.innerHTML = '';
  const items = state.secrets.filter((s) =>
    !q || s.title.toLowerCase().includes(q) || (s.username || '').toLowerCase().includes(q));
  if (!items.length) {
    const li = document.createElement('li');
    li.className = 'empty-note';
    li.textContent = state.secrets.length ? 'No secrets match your search.' : 'Your vault is empty. Add a password or note below.';
    ul.appendChild(li);
    return;
  }
  for (const s of items) {
    const li = document.createElement('li');
    li.dataset.id = s.id;
    if (s.id === state.currentId) li.classList.add('active');
    li.innerHTML = icon(s.type === 'note' ? 'note' : 'key') + `<span class="t">${escapeHtml(s.title)}</span>` +
      (s.username ? `<span class="u">${escapeHtml(s.username)}</span>` : '');
    li.addEventListener('click', async () => { if (await canLeave()) selectSecret(s.id); });
    ul.appendChild(li);
  }
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/** Show exactly one pane in the detail area: 'empty' | 'form' | 'security'. */
function showPane(name) {
  $('#detail-empty').classList.toggle('hidden', name !== 'empty');
  $('#detail-form').classList.toggle('hidden', name !== 'form');
  $('#security-view').classList.toggle('hidden', name !== 'security');
  $('#btn-security').setAttribute('aria-pressed', String(name === 'security'));
}

function setEye(show) {
  $('#f-password').type = show ? 'text' : 'password';
  const eye = $('#f-eye');
  eye.setAttribute('aria-pressed', String(show));
  eye.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
  eye.innerHTML = icon(show ? 'eye-off' : 'eye');
}

/** Called before the form is replaced or the vault locked by hand. False = the user chose to stay. */
async function canLeave() {
  if (!state.dirty) return true;
  if (state.currentId) await saveCurrentSecret(); // flush a pending autosave
  if (!state.dirty) return true;
  return confirm("This secret isn't saved. Leave and lose your changes?");
}

function scheduleAutosave() {
  clearTimeout(autosaveTimer);
  if (state.dirty && state.currentId && state.unlocked) autosaveTimer = setTimeout(saveCurrentSecret, 700);
}

function markDirty() {
  state.dirty = true;
  state.rev++;
  scheduleAutosave();
}

function resetDirty() {
  clearTimeout(autosaveTimer);
  state.dirty = false;
}

function showEmpty() {
  resetDirty();
  state.currentId = null;
  showPane('empty');
  $$('#secret-list li').forEach((li) => li.classList.remove('active'));
}

async function selectSecret(id) {
  const r = await api.getSecret({ id });
  if (!r.ok || !r.secret) { showEmpty(); return; }
  const s = r.secret;
  resetDirty();
  state.currentId = id;
  state.currentType = s.type;
  $$('#secret-list li').forEach((li) => li.classList.toggle('active', li.dataset.id === id));
  showPane('form');
  $('#f-title').value = s.title;
  $('#f-username').value = s.username || '';
  $('#f-password').value = s.password || '';
  setEye(false);
  $('#f-text').value = s.text || '';
  setTypeUI(s.type);
  $('#f-error').textContent = '';
  $('#f-ok').textContent = '';
  $('#f-meta').textContent = `Updated ${new Date(s.updatedAt).toLocaleString()}`;
}

function setTypeUI(type) {
  state.currentType = type;
  const login = type === 'login';
  $('#f-login-fields').classList.toggle('hidden', !login);
  $('#f-text-label').textContent = login ? 'Notes' : 'Secret text';
}

async function showNewForm(type = 'login') {
  if (!(await canLeave())) return;
  resetDirty();
  state.currentId = null;
  $$('#secret-list li').forEach((li) => li.classList.remove('active'));
  showPane('form');
  $('#f-title').value = '';
  $('#f-username').value = '';
  $('#f-password').value = '';
  setEye(false);
  $('#f-text').value = '';
  setTypeUI(type);
  $('#f-error').textContent = '';
  $('#f-ok').textContent = '';
  $('#f-meta').textContent = '';
  $('#f-title').focus();
}

async function saveCurrentSecret() {
  const secret = {
    id: state.currentId || undefined,
    title: $('#f-title').value,
    type: state.currentType,
    username: $('#f-username').value,
    password: $('#f-password').value,
    text: $('#f-text').value,
  };
  clearTimeout(autosaveTimer);
  const rev = state.rev;
  const r = await api.saveSecret({ secret });
  if (!r.ok) {
    if (!r.locked) $('#f-error').textContent = r.error; // a validation error stops autosave until the next edit
    return;
  }
  // from the first save on, the secret autosaves (state.currentId is now set)
  state.currentId = r.secret.id;
  $('#f-error').textContent = '';
  $('#f-ok').textContent = 'Saved';
  setTimeout(() => { $('#f-ok').textContent = ''; }, 1500);
  $('#f-meta').textContent = `Updated ${new Date(r.secret.updatedAt).toLocaleString()}`;
  if (rev === state.rev) state.dirty = false;
  else scheduleAutosave(); // typed while saving
  await reloadList(); // the open form is not reloaded, so the cursor and the eye state stay put
}

function initVault() {
  $('#search').addEventListener('input', renderList);
  $('#btn-new-login').addEventListener('click', () => showNewForm('login'));
  $('#btn-new-note').addEventListener('click', () => showNewForm('note'));
  $$('[data-new]').forEach((b) => b.addEventListener('click', () => showNewForm(b.dataset.new)));
  $('#btn-lock').addEventListener('click', async () => {
    if (!(await canLeave())) return;
    resetDirty(); // the user chose to discard
    await api.lock();
  });
  $('#btn-security').addEventListener('click', async () => {
    if ($('#btn-security').getAttribute('aria-pressed') === 'true') { showEmpty(); return; }
    if (!(await canLeave())) return;
    showEmpty(); // deselects the list
    showPane('security');
  });

  $('#detail-form').addEventListener('submit', (e) => { e.preventDefault(); saveCurrentSecret(); });
  // typing, but not the generator's own options
  $('#detail-form').addEventListener('input', (e) => { if (!e.target.closest('#gen-options')) markDirty(); });

  $('#f-eye').addEventListener('click', () => setEye($('#f-password').type === 'password'));

  const doGen = async () => {
    const r = await api.generatePassword({
      length: +$('#gen-length').value || 20,
      upper: $('#gen-upper').checked, lower: $('#gen-lower').checked,
      digits: $('#gen-digits').checked, symbols: $('#gen-symbols').checked,
    });
    if (r.ok) { $('#f-password').value = r.password; setEye(true); markDirty(); }
    else $('#f-error').textContent = r.error;
  };
  // explicit Generate button
  $('#f-gen').addEventListener('click', doGen);
  // if the field is still empty, tweaking an option generates one right away
  $('#gen-options').addEventListener('change', () => { if (!$('#f-password').value) doGen(); });

  $$('#detail-form [data-copy]').forEach((b) =>
    b.addEventListener('click', () => copyText($('#' + b.dataset.copy).value)));

  $('#f-delete').addEventListener('click', () => {
    if (!state.currentId) return;
    twoStepConfirm($('#f-delete'), 'Click again to delete', async () => {
      const r = await api.deleteSecret({ id: state.currentId });
      if (r.ok) { toast('Deleted'); resetDirty(); await refreshSecrets(); showEmpty(); }
    });
  });

  initSecurityPanel();
  initBackupPanel();
}

/* ---------------- Google Drive backup ---------------- */
function renderBackup(st) {
  $('#bk-setup').classList.toggle('hidden', st.connected || !st.canEncrypt);
  $('#bk-connected').classList.toggle('hidden', !st.connected);
  $('#bk-now').disabled = st.busy;
  const keep = st.hasClient ? 'Saved. Leave blank to keep it.' : '';
  $('#bk-client-id').placeholder = keep;
  $('#bk-client-secret').placeholder = keep;
  let msg = 'Not connected.';
  if (!st.canEncrypt) msg = "Secure storage isn't available on this device, so Drive backup can't be turned on.";
  else if (st.connected) msg = st.busy ? 'Backing up…' : st.lastOk ? `Last backup ${new Date(st.lastOk).toLocaleString()}` : 'Connected.';
  $('#bk-status').textContent = msg;
  $('#bk-error').textContent = st.lastError || '';
}

async function refreshBackupPanel() {
  const r = await api.backupStatus();
  if (r.ok) renderBackup(r);
}

function initBackupPanel() {
  api.onBackupStatus(renderBackup);

  $('#bk-connect').addEventListener('click', async () => {
    const btn = $('#bk-connect');
    const id = $('#bk-client-id').value;
    const secret = $('#bk-client-secret').value;
    let errMsg = '';
    $('#bk-error').textContent = '';
    btn.disabled = true;
    btn.textContent = 'Waiting for Google…';
    try {
      // blank fields = keep the saved client and just sign in again
      if (id || secret || !$('#bk-client-id').placeholder) {
        const c = await api.backupConfigure({ clientId: id, clientSecret: secret });
        if (!c.ok) throw new Error(c.error);
      }
      const r = await api.backupConnect();
      if (!r.ok) throw new Error(r.error);
      $('#bk-client-id').value = '';
      $('#bk-client-secret').value = '';
      toast('Google Drive connected');
    } catch (err) {
      errMsg = err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Connect Google Drive';
      await refreshBackupPanel();
      if (errMsg) $('#bk-error').textContent = errMsg;
    }
  });

  $('#bk-now').addEventListener('click', async () => {
    $('#bk-error').textContent = '';
    const r = await api.backupNow();
    if (!r.ok) { $('#bk-error').textContent = r.error; return; }
    renderBackup(r);
    if (!r.lastError) toast('Backed up to Google Drive');
  });

  $('#bk-disconnect').addEventListener('click', async () => {
    const r = await api.backupDisconnect();
    if (r.ok) { renderBackup(r); toast('Disconnected. The backup file stays in your Drive.'); }
  });
}

/* ---------------- security panel ---------------- */
async function refreshSecurityPanel() {
  refreshBackupPanel();
  const st = await api.hasTwoFA();
  if (st.ok) {
    $('#sec-2fa-status').textContent =
      `Authenticator app is ${st.totp ? 'on' : 'off'}. ${st.passkeys} ${st.passkeys === 1 ? 'passkey' : 'passkeys'} registered.`;
  }
  const pk = await api.listPasskeys();
  const ul = $('#sec-passkeys');
  ul.innerHTML = '';
  if (pk.ok) for (const p of pk.passkeys) {
    const li = document.createElement('li');
    li.innerHTML = `<span>${icon('passkey')}${escapeHtml(p.name)}</span>`;
    const btn = document.createElement('button');
    btn.className = 'btn tiny quiet danger';
    btn.textContent = 'Remove';
    btn.addEventListener('click', async () => {
      await api.removePasskey({ credId: p.credId });
      refreshSecurityPanel();
    });
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

function renderCodes(codes) {
  const box = $('#sec-codes');
  box.innerHTML = '';
  codes.forEach((c) => { const s = document.createElement('span'); s.textContent = c; box.appendChild(s); });
  box.classList.remove('hidden');
  $('#sec-codes-actions').classList.remove('hidden');
  state.recoveryCodes = codes;
}

function initSecurityPanel() {
  $('#cp-btn').addEventListener('click', async () => {
    $('#cp-error').textContent = ''; $('#cp-ok').textContent = '';
    const r = await api.changePassword({ current: $('#cp-current').value, next: $('#cp-new').value });
    if (r.ok) { $('#cp-ok').textContent = 'Password changed'; $('#cp-current').value = ''; $('#cp-new').value = ''; }
    else $('#cp-error').textContent = r.error;
  });

  // --- inline authenticator (TOTP) setup box ---
  $('#sec-add-totp').addEventListener('click', async () => {
    $('#sec-error').textContent = ''; $('#sec-ok').textContent = '';
    $('#sec-passkey-box').classList.add('hidden');
    const r = await api.totpStart();
    if (!r.ok) { $('#sec-error').textContent = r.error; return; }
    $('#sec-totp-qr').src = r.qr;
    $('#sec-totp-secret').textContent = r.secret;
    $('#sec-totp-code').value = '';
    $('#sec-totp-box').classList.remove('hidden');
    $('#sec-totp-code').focus();
  });
  $('#sec-totp-copy').addEventListener('click', () => copyText($('#sec-totp-secret').textContent));
  $('#sec-totp-cancel').addEventListener('click', () => $('#sec-totp-box').classList.add('hidden'));
  $('#sec-totp-verify').addEventListener('click', async () => {
    const r = await api.totpConfirm({ code: $('#sec-totp-code').value });
    if (r.ok) {
      $('#sec-totp-box').classList.add('hidden');
      $('#sec-ok').textContent = 'Authenticator enabled';
      refreshSecurityPanel();
    } else {
      $('#sec-error').textContent = r.error;
    }
  });
  $('#sec-totp-code').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#sec-totp-verify').click(); });

  // --- inline passkey setup box ---
  $('#sec-add-passkey').addEventListener('click', () => {
    $('#sec-error').textContent = ''; $('#sec-ok').textContent = '';
    $('#sec-totp-box').classList.add('hidden');
    $('#sec-passkey-box').classList.remove('hidden');
    $('#sec-passkey-name').focus();
  });
  $('#sec-passkey-cancel').addEventListener('click', () => $('#sec-passkey-box').classList.add('hidden'));
  $('#sec-passkey-create').addEventListener('click', async () => {
    $('#sec-error').textContent = ''; $('#sec-ok').textContent = '';
    try {
      const name = $('#sec-passkey-name').value.trim() || 'This device';
      await registerPasskey(name);
      $('#sec-passkey-box').classList.add('hidden');
      $('#sec-ok').textContent = `Passkey "${name}" added`;
      refreshSecurityPanel();
    } catch (err) {
      $('#sec-error').textContent = String(err.message || err).replace(/^Error:\s*/, '');
    }
  });

  $('#sec-disable-totp').addEventListener('click', async () => {
    const r = await api.disableTotp();
    if (r.ok) { toast('Authenticator turned off'); refreshSecurityPanel(); }
  });

  $('#sec-rotate').addEventListener('click', () => {
    twoStepConfirm($('#sec-rotate'), 'Click again to replace all codes', async () => {
      const r = await api.rotateRecovery({});
      if (r.ok) { renderCodes(r.recoveryCodes); toast('New recovery codes ready'); }
    });
  });
  $('#sec-codes-copy').addEventListener('click', () => copyText(state.recoveryCodes.join('\n')));
  $('#sec-codes-download').addEventListener('click', () =>
    downloadText('secrete-vault-recovery-codes.txt', 'Secrete Vault recovery codes\n\n' + state.recoveryCodes.join('\n') + '\n'));
}

/* ---------------- go ---------------- */
initDial();
boot();
initSetup();
initUnlock();
initVault();
