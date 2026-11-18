// UI wiring for FTT Data. All cryptography lives in crypto.js and all content rules in
// safety.js; this file only moves bytes between the DOM, those modules and the API.
// Decrypted content only ever reaches the page through textContent or a download Blob.
import * as C from './crypto.js';
import * as S from './safety.js';
import qrcode from './vendor/qrcode.js';

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const ALERT_STYLES = {
  error: 'mt-4 rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-900 dark:border-red-800 dark:bg-red-950 dark:text-red-200',
  warn: 'mt-4 rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200',
  info: 'mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-200',
};

const state = { cfg: null, kind: 'text', file: null, warningsAcked: false, recv: null, timers: {}, objectUrl: null };

class UserError extends Error {}

// ============================================================== API

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function detailOf(body, status) {
  try {
    const detail = JSON.parse(body).detail;
    if (typeof detail === 'string') return detail;
  } catch {
    // not JSON
  }
  return status === 0 ? 'Network error. Check your connection and try again.' : `Request failed (${status}).`;
}

async function request(method, path, { headers = {}, json } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method,
      cache: 'no-store',
      headers: json ? { ...headers, 'Content-Type': 'application/json' } : headers,
      body: json ? JSON.stringify(json) : undefined,
    });
  } catch {
    throw new ApiError(0, detailOf('', 0));
  }
  if (!res.ok) throw new ApiError(res.status, detailOf(await res.text(), res.status));
  return res;
}

// XHR rather than fetch, because only XHR reports upload progress.
function putChunk(id, index, token, data, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', `/api/drops/${id}/chunks/${index}`);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.setRequestHeader('X-Upload-Token', token);
    xhr.upload.onprogress = (e) => onProgress(e.loaded);
    xhr.onload = () => (xhr.status === 204 ? resolve() : reject(new ApiError(xhr.status, detailOf(xhr.responseText, xhr.status))));
    xhr.onerror = () => reject(new ApiError(0, detailOf('', 0)));
    xhr.send(data);
  });
}

async function getChunk(id, index, headers, onProgress) {
  const res = await request('GET', `/api/drops/${id}/chunks/${index}`, { headers });
  const reader = res.body.getReader();
  const parts = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
    received += value.length;
    onProgress(received);
  }
  const out = new Uint8Array(received);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

// Retry network drops and server hiccups. A 409 on a *retried* upload means the earlier attempt
// actually landed before the connection failed, so it counts as success.
async function withRetry(fn, { conflictMeansDone = false } = {}) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn();
    } catch (e) {
      if (attempt > 0 && conflictMeansDone && e.status === 409) return null;
      const transient = e.status === 0 || (e.status >= 500 && e.status !== 507);
      if (!transient || attempt >= 2) throw e;
      await sleep(1000 * (attempt + 1));
    }
  }
}

// ============================================================== UI helpers

function showAlert(el, kind, messages) {
  const list = [].concat(messages);
  el.className = ALERT_STYLES[kind];
  el.replaceChildren();
  if (list.length === 1) {
    el.textContent = list[0];
  } else {
    const ul = document.createElement('ul');
    ul.className = 'list-disc space-y-1 pl-5';
    ul.append(...list.map((text) => Object.assign(document.createElement('li'), { textContent: text })));
    el.append(ul);
  }
  el.hidden = false;
}

function hideAlert(el) {
  el.hidden = true;
  el.replaceChildren();
}

function setProgress(prefix, done, total, label) {
  $(`${prefix}-progress`).hidden = false;
  $(`${prefix}-bar`).style.width = `${total ? Math.min(100, (done / total) * 100) : 0}%`;
  $(`${prefix}-status`).textContent = label;
}

function countdown(el, expiresAt) {
  clearInterval(state.timers[el.id]);
  const tick = () => {
    const ms = expiresAt - Date.now();
    if (ms <= 0) {
      el.textContent = 'Expired. It has been deleted from the server.';
      clearInterval(state.timers[el.id]);
      return;
    }
    const s = Math.ceil(ms / 1000);
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const pad = (n) => String(n).padStart(2, '0');
    el.textContent = `Expires in ${h ? `${h}:${pad(m)}` : m}:${pad(s % 60)}`;
  };
  tick();
  state.timers[el.id] = setInterval(tick, 1000);
  el.hidden = false;
}

function errorMessage(e) {
  if (e instanceof ApiError || e instanceof UserError || e instanceof C.CodeFormatError || e instanceof C.DecryptionError) {
    return e.message;
  }
  console.error(e);
  return 'Something went wrong. Please try again.';
}

function setBusy(busy) {
  const disabled = busy || !C.hasWebCrypto();
  for (const id of ['send-btn', 'open-btn', 'reveal-btn', 'send-again']) $(id).disabled = disabled;
}

const listItems = (texts) => texts.map((text) => Object.assign(document.createElement('li'), { textContent: text }));

function flash(button, text) {
  const original = button.dataset.label ?? button.textContent;
  button.dataset.label = original;
  button.textContent = text;
  setTimeout(() => (button.textContent = original), 1500);
}

// ============================================================== send

function selectTab(name) {
  for (const tab of ['send', 'receive']) {
    $(`tab-${tab}`).setAttribute('aria-selected', String(tab === name));
    $(`panel-${tab}`).hidden = tab !== name;
  }
}

function selectKind(kind) {
  state.kind = kind;
  $('kind-text').setAttribute('aria-selected', String(kind === 'text'));
  $('kind-file').setAttribute('aria-selected', String(kind === 'file'));
  $('text-pane').hidden = kind !== 'text';
  $('file-pane').hidden = kind !== 'file';
  inputChanged();
}

function inputChanged() {
  state.warningsAcked = false;
  $('send-btn').textContent = 'Encrypt & send';
  hideAlert($('send-alert'));
}

function updateTextCount() {
  const bytes = new Blob([$('text-input').value]).size;
  $('text-count').textContent = `${S.formatBytes(bytes)} / ${S.formatBytes(state.cfg?.max_text_bytes ?? Infinity)}`;
}

function chooseFile(file) {
  state.file = file ?? null;
  inputChanged();
  const info = $('file-info');
  info.hidden = !file;
  if (!file) return;
  info.textContent = `${file.name} · ${S.formatBytes(file.size)}`;
  const verdict = S.checkFileMeta(file, state.cfg);
  if (verdict.blocked.length) showAlert($('send-alert'), 'error', verdict.blocked);
}

const ttlLabel = (s) => (s % 3600 === 0 ? `${s / 3600} hour${s === 3600 ? '' : 's'}` : `${s / 60} minutes`);

function applyConfig(cfg) {
  const select = $('ttl-select');
  for (const seconds of cfg.ttl.presets) {
    select.add(new Option(ttlLabel(seconds), String(seconds), false, seconds === cfg.ttl.default));
  }
  select.add(new Option('Custom…', 'custom'));
  $('ttl-custom').min = String(Math.ceil(cfg.ttl.min / 60));
  $('ttl-custom').max = String(Math.floor(cfg.ttl.max / 60));
  $('file-limit').textContent = `Up to ${S.formatBytes(cfg.max_file_bytes)}`;
  updateTextCount();
}

function readTtl() {
  const { min, max } = state.cfg.ttl;
  const choice = $('ttl-select').value;
  const seconds = choice === 'custom' ? Math.round(Number($('ttl-custom').value) * 60) : Number(choice);
  if (!Number.isFinite(seconds) || seconds < min || seconds > max) {
    throw new UserError(`Custom expiry must be between ${min / 60} and ${max / 60} minutes.`);
  }
  return seconds;
}

async function collectSendInput() {
  if (state.kind === 'text') {
    const text = $('text-input').value;
    return {
      source: new Blob([text]), // UTF-8
      meta: { kind: 'text', name: '', mime: 'text/plain;charset=utf-8' },
      verdict: S.checkText(text, state.cfg),
    };
  }
  const file = state.file;
  if (!file) throw new UserError('Choose a file first.');
  return {
    source: file,
    meta: { kind: 'file', name: S.sanitizeFilename(file.name), mime: file.type || 'application/octet-stream' },
    verdict: await S.checkFile(file, state.cfg),
  };
}

async function onSend() {
  const alertEl = $('send-alert');
  hideAlert(alertEl);
  setBusy(true);
  try {
    const { source, meta, verdict } = await collectSendInput();
    if (verdict.blocked.length) return showAlert(alertEl, 'error', verdict.blocked);
    if (verdict.warnings.length && !state.warningsAcked) {
      state.warningsAcked = true;
      $('send-btn').textContent = 'Send anyway';
      return showAlert(alertEl, 'warn', [...verdict.warnings, 'Check the content, then press "Send anyway" to continue.']);
    }
    const ttl = readTtl();
    const result = await sendDrop(source, meta, { ttl, burn: $('burn').checked, linkOnly: $('link-only').checked });
    showSendResult(result);
  } catch (e) {
    $('send-progress').hidden = true;
    showAlert(alertEl, 'error', errorMessage(e));
  } finally {
    setBusy(false);
  }
}

async function sendDrop(source, meta, { ttl, burn, linkOnly }) {
  const chunkSize = state.cfg.chunk_size;
  const total = C.chunkCount(source.size, chunkSize);
  const size = C.ciphertextSize(source.size, chunkSize);
  for (let attempt = 1; ; attempt++) {
    setProgress('send', 0, size, linkOnly ? 'Generating key…' : 'Deriving key from code…');
    const id = C.newDropId();
    const secret = linkOnly ? null : C.newSecret();
    const master = secret ? await C.deriveMasterKey(secret, id) : C.randomMasterKey();
    const keys = await C.deriveDropKeys(master, id);
    const manifest = await C.encryptManifest(keys.encKey, id, { v: 2, ...meta, size: source.size, chunkSize, chunks: total });

    let created;
    try {
      const body = { id, ttl, burn, auth_hash: keys.authHash, chunks: total, size, manifest: C.b64Encode(manifest) };
      created = await (await request('POST', '/api/drops', { json: body })).json();
    } catch (e) {
      if (e.status === 409 && attempt < 3) continue; // the random ID was taken: pick another
      throw e;
    }

    let sent = 0;
    for (let i = 0; i < total; i++) {
      const plain = new Uint8Array(await source.slice(i * chunkSize, (i + 1) * chunkSize).arrayBuffer());
      const sealed = await C.encryptChunk(keys.encKey, id, i, total, plain);
      const label = (n) => `Encrypting & uploading… ${S.formatBytes(n)} of ${S.formatBytes(size)}`;
      await withRetry(
        () => putChunk(id, i, created.upload_token, sealed, (n) => setProgress('send', sent + n, size, label(sent + n))),
        { conflictMeansDone: true },
      );
      sent += sealed.length;
      setProgress('send', sent, size, label(sent));
    }
    const done = await (await request('POST', `/api/drops/${id}/complete`, { headers: { 'X-Upload-Token': created.upload_token } })).json();
    return { id, secret, master, burn, expiresAt: Date.now() + done.expires_in_ms };
  }
}

function showSendResult({ id, secret, master, burn, expiresAt }) {
  const link = `${location.origin}/r/${id}#${C.fragmentFromMasterKey(master)}`;
  const qr = qrcode(0, 'M');
  qr.addData(link);
  qr.make();
  $('qr-img').src = qr.createDataURL(6, 2);
  $('code-block').hidden = !secret;
  $('share-code').textContent = secret ? C.formatCode(id, secret) : '';
  $('share-link').value = link;
  $('send-burn-note').hidden = !burn;
  countdown($('send-expiry'), expiresAt);
  $('send-form').hidden = true;
  $('send-progress').hidden = true;
  $('send-result').hidden = false;
}

function resetSend() {
  clearInterval(state.timers['send-expiry']);
  $('send-result').hidden = true;
  $('send-form').hidden = false;
  $('qr-img').removeAttribute('src');
  $('share-link').value = '';
  $('share-code').textContent = '';
  $('text-input').value = '';
  $('file-input').value = '';
  chooseFile(null);
  updateTextCount();
}

// ============================================================== receive

function resetReceiveOutput() {
  hideAlert($('recv-alert'));
  for (const id of ['burn-confirm', 'recv-progress', 'recv-text', 'text-warning', 'text-box', 'recv-file', 'recv-expiry']) {
    $(id).hidden = true;
  }
  $('text-output').textContent = '';
  clearInterval(state.timers['recv-expiry']);
  if (state.objectUrl) URL.revokeObjectURL(state.objectUrl);
  state.objectUrl = null;
}

async function receive({ id, master = null, secret = null }) {
  resetReceiveOutput();
  setBusy(true);
  try {
    if (!master) {
      setProgress('recv', 0, 1, 'Deriving key from code…');
      master = await C.deriveMasterKey(secret, id);
    }
    state.recv = { id, keys: await C.deriveDropKeys(master, id) };
    const info = await openDrop(false);
    if (info.claim_required) {
      $('recv-progress').hidden = true;
      $('burn-confirm').hidden = false;
      return;
    }
    await download(info);
  } catch (e) {
    $('recv-progress').hidden = true;
    showAlert($('recv-alert'), 'error', errorMessage(e));
  } finally {
    setBusy(false);
  }
}

async function onReveal() {
  $('burn-confirm').hidden = true;
  setBusy(true);
  try {
    await download(await openDrop(true));
  } catch (e) {
    $('recv-progress').hidden = true;
    showAlert($('recv-alert'), 'error', errorMessage(e));
  } finally {
    setBusy(false);
  }
}

async function openDrop(claim) {
  const { id, keys } = state.recv;
  const headers = { 'X-Auth-Token': keys.authToken };
  if (claim) headers['X-Claim'] = '1';
  for (let waited = 0; ; waited++) {
    try {
      return await (await request('POST', `/api/drops/${id}/open`, { headers })).json();
    } catch (e) {
      if (e.status !== 409 || waited >= 90) throw e;
      setProgress('recv', 0, 1, 'The sender is still uploading. Waiting…');
      await sleep(2000);
    }
  }
}

async function download(info) {
  const { id, keys } = state.recv;
  const manifest = await C.decryptManifest(keys.encKey, id, info.chunks, C.b64Decode(info.manifest));
  const headers = { 'X-Auth-Token': keys.authToken };
  if (info.claim_token) headers['X-Claim-Token'] = info.claim_token;

  const parts = [];
  let received = 0;
  const label = (n) => `Downloading & decrypting… ${S.formatBytes(n)} of ${S.formatBytes(info.size)}`;
  for (let i = 0; i < info.chunks; i++) {
    const sealed = await withRetry(() => getChunk(id, i, headers, (n) => setProgress('recv', received + n, info.size, label(received + n))));
    received += sealed.length;
    parts.push(await C.decryptChunk(keys.encKey, id, i, info.chunks, sealed));
  }
  if (parts.reduce((n, p) => n + p.length, 0) !== manifest.size) {
    throw new C.DecryptionError('The drop is incomplete: its size does not match what the sender encrypted.');
  }
  $('recv-progress').hidden = true;
  state.recv = null;

  if (manifest.kind === 'text') showText(await new Blob(parts).text());
  else showFile(manifest, parts);

  if (info.burn) showAlert($('recv-alert'), 'info', 'This was a one-time drop. It has now been deleted from the server.');
  else countdown($('recv-expiry'), Date.now() + info.expires_in_ms);
}

function showText(text) {
  const matches = S.scanText(text, state.cfg.rules?.text_rules);
  const reveal = () => {
    $('text-output').textContent = text; // never innerHTML
    $('text-warning').hidden = true;
    $('text-box').hidden = false;
  };
  $('recv-text').hidden = false;
  if (!matches.length) return reveal();
  $('text-warning-list').replaceChildren(...listItems(matches.map((m) => m.name)));
  $('text-warning').hidden = false;
  $('show-anyway').onclick = reveal;
}

function showFile(manifest, parts) {
  const name = S.sanitizeFilename(manifest.name);
  const verdict = S.merge(
    S.checkFileMeta({ name, type: manifest.mime, size: manifest.size }, { ...state.cfg, max_file_bytes: Infinity }),
    S.checkFileHead(parts[0].subarray(0, 64), state.cfg),
  );
  const reasons = [...verdict.blocked, ...verdict.warnings];
  // application/octet-stream + <a download> forces a download: the browser never renders it.
  const blob = new Blob(parts, { type: 'application/octet-stream' });
  state.objectUrl = URL.createObjectURL(blob);
  const link = $('download-link');
  link.href = state.objectUrl;
  link.download = name;
  link.textContent = `Download ${name}`;
  $('file-name').textContent = name;
  $('file-meta').textContent = `${S.formatBytes(manifest.size)} · ${manifest.mime || 'unknown type'}`;
  $('file-warning-list').replaceChildren(...listItems(reasons));
  $('file-warning-list').hidden = !reasons.length;
  $('recv-file').hidden = false;
}

function onCodeSubmit(event) {
  event.preventDefault();
  hideAlert($('recv-alert'));
  try {
    const { id, secret } = C.parseCode($('code-input').value);
    receive({ id, secret });
  } catch (e) {
    showAlert($('recv-alert'), 'error', errorMessage(e));
  }
}

// ============================================================== boot

function wireEvents() {
  $('tab-send').addEventListener('click', () => selectTab('send'));
  $('tab-receive').addEventListener('click', () => selectTab('receive'));
  $('kind-text').addEventListener('click', () => selectKind('text'));
  $('kind-file').addEventListener('click', () => selectKind('file'));
  $('text-input').addEventListener('input', () => {
    inputChanged();
    updateTextCount();
  });
  $('file-input').addEventListener('change', (e) => chooseFile(e.target.files[0]));
  $('ttl-select').addEventListener('change', (e) => ($('ttl-custom-wrap').hidden = e.target.value !== 'custom'));
  $('send-btn').addEventListener('click', onSend);
  $('send-again').addEventListener('click', resetSend);
  $('code-form').addEventListener('submit', onCodeSubmit);
  $('reveal-btn').addEventListener('click', onReveal);

  const zone = $('file-drop');
  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.dataset.drag = 'true';
  });
  zone.addEventListener('dragleave', () => (zone.dataset.drag = 'false'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.dataset.drag = 'false';
    chooseFile(e.dataTransfer.files[0]);
  });
  // A file dropped anywhere else would make the browser navigate away to it.
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => e.preventDefault());
  // Opening another link in this tab may only change the #fragment, which doesn't reload the
  // page; reload so boot() reads the new key and strips it from the address bar again.
  window.addEventListener('hashchange', () => location.reload());

  document.addEventListener('click', async (e) => {
    const button = e.target.closest('[data-copy]');
    if (!button) return;
    const source = $(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(source instanceof HTMLInputElement ? source.value : source.textContent);
      flash(button, 'Copied');
    } catch {
      flash(button, 'Copy failed');
    }
  });
}

async function boot() {
  wireEvents();
  const route = location.pathname.match(/^\/r\/([^/]+)\/?$/);
  selectTab(route ? 'receive' : 'send');

  // Take the key out of the address bar and browser history before anything else happens.
  const fragment = location.hash.slice(1);
  if (fragment) history.replaceState(null, '', location.pathname + location.search);

  if (!C.hasWebCrypto()) {
    $('no-crypto').hidden = false;
    setBusy(true);
  }
  try {
    state.cfg = await (await request('GET', '/api/config')).json();
  } catch (e) {
    showAlert($(route ? 'recv-alert' : 'send-alert'), 'error', `Could not load settings. ${errorMessage(e)}`);
    return;
  }
  applyConfig(state.cfg);
  if (!route || !C.hasWebCrypto()) return;

  const id = route[1].toUpperCase();
  if (!C.isValidId(id)) return showAlert($('recv-alert'), 'error', 'This is not a valid drop link.');
  if (!fragment) {
    $('code-input').value = `${id}-`;
    return showAlert($('recv-alert'), 'info', 'Type the rest of the code shown on the sending device.');
  }
  try {
    await receive({ id, master: C.masterKeyFromFragment(fragment) });
  } catch (e) {
    showAlert($('recv-alert'), 'error', errorMessage(e));
  }
}

boot();
