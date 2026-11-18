// FTT Data — client-side cryptography, protocol "ftt/v2".
// Pure ES module with no DOM access: it runs unchanged in browsers and under `node --test`.
//
// Share code:  <id: 6 chars>-<secret: 4>-<secret: 4>   (Crockford base32, e.g. K7QM3F-9XTR-2PWD)
//   The id is the server's lookup key. The 8-char secret (40 bits) never leaves the browser.
//
// Key schedule
//   typed code : M = PBKDF2-SHA256(secret, salt = "ftt/v2/salt/<id>", 600 000 iterations)  32 bytes
//   link-only  : M = 32 random bytes                                                   (256-bit)
//   encKey     = HKDF-SHA256(M, info = "ftt/v2/enc/<id>")  -> AES-GCM-256, non-extractable
//   authToken  = HKDF-SHA256(M, info = "ftt/v2/auth/<id>") -> 32 bytes; the server stores only
//                SHA-256(authToken) and hands out ciphertext only to callers who present it.
//   The QR link is /r/<id>#<base64url(M)>; URL fragments are never sent to the server.
//
// Every encrypted blob (manifest and chunks) is  iv(12) | ciphertext | tag(16),  with a fresh
// random IV each time and AES-GCM additional authenticated data (AAD) of
//   manifest : "ftt/v2|<id>|manifest|<total>"
//   chunk    : "ftt/v2|<id>|chunk|<index>|<total>"
// so a chunk that is swapped from another drop, reordered, or truncated fails to decrypt.

export const PROTOCOL = 'ftt/v2';
export const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32: no I, L, O, U
export const ID_LENGTH = 6;
export const SECRET_LENGTH = 8;
export const PBKDF2_ITERATIONS = 600_000;
export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;
export const CHUNK_OVERHEAD = IV_LENGTH + TAG_LENGTH;

const ID_RE = /^[0-9A-HJKMNP-TV-Z]{6}$/;
const encoder = new TextEncoder();

export class DecryptionError extends Error {
  constructor(message = 'Decryption failed: the key is wrong or the data was modified.') {
    super(message);
    this.name = 'DecryptionError';
  }
}

export class CodeFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CodeFormatError';
  }
}

/** Web Crypto exists only in secure contexts (HTTPS or localhost). */
export function hasWebCrypto() {
  return globalThis.isSecureContext !== false && Boolean(globalThis.crypto?.subtle);
}

const subtle = () => globalThis.crypto.subtle; // looked up lazily: undefined on insecure origins

// ------------------------------------------------------------------ codes

export function randomBase32(length) {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (const b of bytes) out += ALPHABET[b & 31]; // 256 is a multiple of 32, so this is unbiased
  return out;
}

export const newDropId = () => randomBase32(ID_LENGTH);
export const newSecret = () => randomBase32(SECRET_LENGTH);
export const isValidId = (id) => ID_RE.test(id);

export function formatCode(id, secret) {
  return `${id}-${secret.slice(0, 4)}-${secret.slice(4)}`;
}

/** Parse a typed code, forgiving case, spaces, hyphens and the look-alikes O→0, I/L→1. */
export function parseCode(input) {
  const s = String(input ?? '')
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
  const expected = ID_LENGTH + SECRET_LENGTH;
  if (s.length !== expected) {
    throw new CodeFormatError(`A code has ${expected} characters, like K7QM3F-9XTR-2PWD.`);
  }
  for (const ch of s) {
    if (!ALPHABET.includes(ch)) throw new CodeFormatError(`"${ch}" can't appear in a code.`);
  }
  return { id: s.slice(0, ID_LENGTH), secret: s.slice(ID_LENGTH) };
}

// ------------------------------------------------------------------ keys

export function randomMasterKey() {
  return globalThis.crypto.getRandomValues(new Uint8Array(32));
}

export async function deriveMasterKey(secret, id, iterations = PBKDF2_ITERATIONS) {
  const base = await subtle().importKey('raw', encoder.encode(secret), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle().deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: encoder.encode(`${PROTOCOL}/salt/${id}`), iterations },
    base,
    256,
  );
  return new Uint8Array(bits);
}

export async function deriveDropKeys(master, id) {
  const ikm = await subtle().importKey('raw', master, 'HKDF', false, ['deriveKey', 'deriveBits']);
  const hkdf = (label) => ({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: new Uint8Array(0),
    info: encoder.encode(`${PROTOCOL}/${label}/${id}`),
  });
  const encKey = await subtle().deriveKey(hkdf('enc'), ikm, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const token = new Uint8Array(await subtle().deriveBits(hkdf('auth'), ikm, 256));
  const authHash = toHex(new Uint8Array(await subtle().digest('SHA-256', token)));
  return { encKey, authToken: b64urlEncode(token), authHash };
}

export const fragmentFromMasterKey = (master) => b64urlEncode(master);

export function masterKeyFromFragment(fragment) {
  let key;
  try {
    key = b64urlDecode(String(fragment).replace(/^#/, ''));
  } catch {
    key = null;
  }
  if (!key || key.length !== 32) throw new CodeFormatError('This link is incomplete: its key is missing or damaged.');
  return key;
}

// ------------------------------------------------------------------ AES-GCM

export const manifestAad = (id, total) => encoder.encode(`${PROTOCOL}|${id}|manifest|${total}`);
export const chunkAad = (id, index, total) => encoder.encode(`${PROTOCOL}|${id}|chunk|${index}|${total}`);

async function seal(key, plaintext, aad, iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH))) {
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, plaintext));
  const out = new Uint8Array(IV_LENGTH + ct.length);
  out.set(iv);
  out.set(ct, IV_LENGTH);
  return out;
}

async function unseal(key, blob, aad) {
  if (!(blob instanceof Uint8Array) || blob.length < CHUNK_OVERHEAD) throw new DecryptionError('Encrypted data is truncated.');
  try {
    const iv = blob.subarray(0, IV_LENGTH);
    return new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, blob.subarray(IV_LENGTH)));
  } catch {
    throw new DecryptionError();
  }
}

function checkPosition(index, total) {
  if (!Number.isInteger(total) || total < 1 || !Number.isInteger(index) || index < 0 || index >= total) {
    throw new RangeError(`invalid chunk position ${index}/${total}`);
  }
}

export const chunkCount = (size, chunkSize) => Math.max(1, Math.ceil(size / chunkSize));
export const ciphertextSize = (size, chunkSize) => size + chunkCount(size, chunkSize) * CHUNK_OVERHEAD;

/** Encrypt one chunk. `iv` is only for known-answer tests; never reuse an IV with the same key. */
export function encryptChunk(key, id, index, total, plaintext, iv) {
  checkPosition(index, total);
  return seal(key, plaintext, chunkAad(id, index, total), iv);
}

export function decryptChunk(key, id, index, total, blob) {
  checkPosition(index, total);
  return unseal(key, blob, chunkAad(id, index, total));
}

/** The manifest carries everything the server must not see: kind, file name, MIME type, size. */
export function encryptManifest(key, id, manifest, iv) {
  checkPosition(0, manifest.chunks);
  return seal(key, encoder.encode(JSON.stringify(manifest)), manifestAad(id, manifest.chunks), iv);
}

export async function decryptManifest(key, id, total, blob) {
  const manifest = JSON.parse(new TextDecoder().decode(await unseal(key, blob, manifestAad(id, total))));
  if (manifest.v !== 2 || manifest.chunks !== total) throw new DecryptionError('Unsupported or inconsistent manifest.');
  return manifest;
}

// ------------------------------------------------------------------ encoding

export function b64Encode(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export function b64Decode(text) {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export const b64urlEncode = (bytes) => b64Encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function b64urlDecode(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new CodeFormatError('Invalid base64url text.');
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  return b64Decode(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
}

export const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
