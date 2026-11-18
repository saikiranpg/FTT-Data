// Tests for static/crypto.js using Node's built-in Web Crypto (no npm packages).
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import * as C from '../../static/crypto.js';

const enc = new TextEncoder();
const FAST = 1_000; // PBKDF2 iterations where the production cost isn't the point of the test
const VECTOR = JSON.parse(readFileSync(new URL('../vectors/ftt_v2.json', import.meta.url)));

async function freshKeys(id = C.newDropId(), master = C.randomMasterKey()) {
  return { id, master, ...(await C.deriveDropKeys(master, id)) };
}

const concat = (parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
};

const flip = (bytes, index) => {
  const copy = bytes.slice();
  copy[index] ^= 0x01;
  return copy;
};

// ------------------------------------------------------------------ codes

test('codes are Crockford base32: 6-char id + 8-char secret', () => {
  for (let i = 0; i < 200; i++) {
    const id = C.newDropId();
    const secret = C.newSecret();
    assert.match(id, /^[0-9A-HJKMNP-TV-Z]{6}$/);
    assert.match(secret, /^[0-9A-HJKMNP-TV-Z]{8}$/);
    assert.ok(C.isValidId(id));
    const code = C.formatCode(id, secret);
    assert.match(code, /^[0-9A-Z]{6}-[0-9A-Z]{4}-[0-9A-Z]{4}$/);
    assert.deepEqual(C.parseCode(code), { id, secret });
  }
});

test('parseCode forgives case, spacing and look-alike characters', () => {
  assert.deepEqual(C.parseCode(' k7qm3f 9xtr-2pwd '), { id: 'K7QM3F', secret: '9XTR2PWD' });
  assert.deepEqual(C.parseCode('K7QM3F9XTR2PWO'), { id: 'K7QM3F', secret: '9XTR2PW0' }); // O → 0
  assert.deepEqual(C.parseCode('K7QM3F-9XTR-2PWl'), { id: 'K7QM3F', secret: '9XTR2PW1' }); // l → 1
});

test('parseCode rejects malformed codes', () => {
  for (const bad of ['', 'K7QM3F', 'K7QM3F-9XTR-2PW', 'K7QM3F-9XTR-2PWDX', 'K7QM3F-9XTR-2PWU', 'K7QM3F-9XTR-2PW!']) {
    assert.throws(() => C.parseCode(bad), C.CodeFormatError, `accepted ${JSON.stringify(bad)}`);
  }
});

// ------------------------------------------------------------------ keys

test('the key is derived from the secret and bound to the drop id', async () => {
  const a = await C.deriveMasterKey('9XTR2PWD', 'K7QM3F', FAST);
  assert.equal(a.length, 32);
  assert.deepEqual(a, await C.deriveMasterKey('9XTR2PWD', 'K7QM3F', FAST));
  assert.notDeepEqual(a, await C.deriveMasterKey('9XTR2PWE', 'K7QM3F', FAST));
  assert.notDeepEqual(a, await C.deriveMasterKey('9XTR2PWD', 'K7QM3G', FAST));
});

test('only a hash of the auth token is uploaded, and the AES key cannot be exported', async () => {
  const k = await freshKeys();
  assert.match(k.authToken, /^[A-Za-z0-9_-]{43}$/);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', C.b64urlDecode(k.authToken)));
  assert.equal(C.toHex(digest), k.authHash);
  assert.equal(k.encKey.extractable, false);
});

test('link fragment carries exactly the 256-bit key', () => {
  const master = C.randomMasterKey();
  const fragment = C.fragmentFromMasterKey(master);
  assert.equal(fragment.length, 43);
  assert.deepEqual(C.masterKeyFromFragment(`#${fragment}`), master);
  for (const bad of ['', fragment.slice(0, 40), `${fragment}AA`, 'not/base64url']) {
    assert.throws(() => C.masterKeyFromFragment(bad), C.CodeFormatError);
  }
});

// ------------------------------------------------------------------ round trips

test('text round-trip (single chunk)', async () => {
  const k = await freshKeys();
  const text = 'héllo 👋 from device A';
  const sealed = await C.encryptChunk(k.encKey, k.id, 0, 1, enc.encode(text));
  assert.equal(sealed.length, enc.encode(text).length + C.CHUNK_OVERHEAD);
  const opened = await C.decryptChunk(k.encKey, k.id, 0, 1, sealed);
  assert.equal(new TextDecoder().decode(opened), text);
});

test('file round-trip across chunks cut with Blob.slice, like File.slice in the browser', async () => {
  const k = await freshKeys();
  const data = crypto.getRandomValues(new Uint8Array(10_000));
  const blob = new Blob([data]);
  const chunkSize = 4096;
  const total = C.chunkCount(blob.size, chunkSize);
  assert.equal(total, 3);

  const sealed = [];
  for (let i = 0; i < total; i++) {
    const plain = new Uint8Array(await blob.slice(i * chunkSize, (i + 1) * chunkSize).arrayBuffer());
    sealed.push(await C.encryptChunk(k.encKey, k.id, i, total, plain));
  }
  assert.equal(sealed.reduce((n, c) => n + c.length, 0), C.ciphertextSize(blob.size, chunkSize));

  const opened = [];
  for (let i = 0; i < total; i++) opened.push(await C.decryptChunk(k.encKey, k.id, i, total, sealed[i]));
  assert.deepEqual(concat(opened), data);
});

test('an empty file is still one authenticated chunk', async () => {
  const k = await freshKeys();
  assert.equal(C.chunkCount(0, 4096), 1);
  const sealed = await C.encryptChunk(k.encKey, k.id, 0, 1, new Uint8Array(0));
  assert.equal((await C.decryptChunk(k.encKey, k.id, 0, 1, sealed)).length, 0);
});

test('manifest round-trip hides name, type and size inside the ciphertext', async () => {
  const k = await freshKeys();
  const manifest = { v: 2, kind: 'file', name: 'secret-plans.pdf', mime: 'application/pdf', size: 12345, chunkSize: 4096, chunks: 4 };
  const sealed = await C.encryptManifest(k.encKey, k.id, manifest);
  assert.equal(Buffer.from(sealed).indexOf('secret-plans'), -1);
  assert.deepEqual(await C.decryptManifest(k.encKey, k.id, 4, sealed), manifest);
});

// ------------------------------------------------------------------ rejection

test('a wrong typed code cannot decrypt', async () => {
  const id = 'K7QM3F';
  const right = await C.deriveDropKeys(await C.deriveMasterKey('9XTR2PWD', id, FAST), id);
  const wrong = await C.deriveDropKeys(await C.deriveMasterKey('9XTR2PWE', id, FAST), id);
  assert.notEqual(right.authToken, wrong.authToken); // the server rejects it before decryption…
  const sealed = await C.encryptChunk(right.encKey, id, 0, 1, enc.encode('hi'));
  await assert.rejects(C.decryptChunk(wrong.encKey, id, 0, 1, sealed), C.DecryptionError); // …and so does AES-GCM
});

test('any modified byte (IV, ciphertext or tag) is rejected', async () => {
  const k = await freshKeys();
  const sealed = await C.encryptChunk(k.encKey, k.id, 0, 1, enc.encode('do not touch'));
  for (const index of [0, C.IV_LENGTH + 2, sealed.length - 1]) {
    await assert.rejects(C.decryptChunk(k.encKey, k.id, 0, 1, flip(sealed, index)), C.DecryptionError);
  }
  await assert.rejects(C.decryptChunk(k.encKey, k.id, 0, 1, sealed.subarray(0, 20)), C.DecryptionError);
});

test('reordered chunks are rejected', async () => {
  const k = await freshKeys();
  const first = await C.encryptChunk(k.encKey, k.id, 0, 2, enc.encode('first'));
  const second = await C.encryptChunk(k.encKey, k.id, 1, 2, enc.encode('second'));
  await assert.rejects(C.decryptChunk(k.encKey, k.id, 0, 2, second), C.DecryptionError);
  await assert.rejects(C.decryptChunk(k.encKey, k.id, 1, 2, first), C.DecryptionError);
});

test('truncation is detected because the total chunk count is authenticated', async () => {
  const k = await freshKeys();
  const sealed = [];
  for (let i = 0; i < 3; i++) sealed.push(await C.encryptChunk(k.encKey, k.id, i, 3, enc.encode(`part ${i}`)));
  // A server that drops the last chunk and claims there were only 2 is caught on every chunk…
  await assert.rejects(C.decryptChunk(k.encKey, k.id, 0, 2, sealed[0]), C.DecryptionError);
  await assert.rejects(C.decryptChunk(k.encKey, k.id, 1, 2, sealed[1]), C.DecryptionError);
  // …and on the manifest, which is bound to the same count.
  const manifest = await C.encryptManifest(k.encKey, k.id, { v: 2, kind: 'text', name: '', mime: 'text/plain', size: 18, chunkSize: 8, chunks: 3 });
  await assert.rejects(C.decryptManifest(k.encKey, k.id, 2, manifest), C.DecryptionError);
});

test('chunks cannot be moved into another drop', async () => {
  const k = await freshKeys('AAAAAA');
  const sealed = await C.encryptChunk(k.encKey, 'AAAAAA', 0, 1, enc.encode('mine'));
  await assert.rejects(C.decryptChunk(k.encKey, 'BBBBBB', 0, 1, sealed), C.DecryptionError);
});

test('every encryption uses a fresh IV, and ciphertext never contains the plaintext', async () => {
  const k = await freshKeys();
  const plain = enc.encode('TOP-SECRET-PLAINTEXT-MARKER '.repeat(20));
  const a = await C.encryptChunk(k.encKey, k.id, 0, 1, plain);
  const b = await C.encryptChunk(k.encKey, k.id, 0, 1, plain);
  assert.notDeepEqual(a.subarray(0, C.IV_LENGTH), b.subarray(0, C.IV_LENGTH));
  assert.notDeepEqual(a, b);
  assert.equal(Buffer.from(a).indexOf('TOP-SECRET'), -1);
});

test('invalid chunk positions are refused before encrypting', async () => {
  const k = await freshKeys();
  for (const [index, total] of [[1, 1], [-1, 2], [0, 0], [0.5, 2]]) {
    assert.throws(() => C.encryptChunk(k.encKey, k.id, index, total, new Uint8Array(1)), RangeError);
  }
});

// ------------------------------------------------------------------ interop

test('matches the known-answer vector shared with the Python suite', async () => {
  const master = await C.deriveMasterKey(VECTOR.secret, VECTOR.id, VECTOR.iterations);
  assert.equal(C.toHex(master), VECTOR.master_hex);
  assert.equal(C.fragmentFromMasterKey(master), VECTOR.fragment);
  assert.equal(C.formatCode(VECTOR.id, VECTOR.secret), VECTOR.code);

  const k = await C.deriveDropKeys(master, VECTOR.id);
  assert.equal(k.authToken, VECTOR.auth_token);
  assert.equal(k.authHash, VECTOR.auth_hash);

  const iv = Uint8Array.from(Buffer.from(VECTOR.iv_hex, 'hex'));
  const plaintext = Uint8Array.from(Buffer.from(VECTOR.plaintext_hex, 'hex'));
  const chunk = await C.encryptChunk(k.encKey, VECTOR.id, VECTOR.chunk_index, VECTOR.chunk_total, plaintext, iv);
  assert.equal(C.toHex(chunk), VECTOR.chunk_hex);
  const manifest = await C.encryptManifest(k.encKey, VECTOR.id, JSON.parse(VECTOR.manifest_json), iv);
  assert.equal(C.toHex(manifest), VECTOR.manifest_hex);
});
