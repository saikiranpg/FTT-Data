// Regenerates tests/vectors/ftt_v2.json from static/crypto.js (run: npm run vectors).
// Both test suites check against this file, and the Python one recomputes every value with an
// independent implementation, which proves the wire format is fully specified.
import { writeFileSync } from 'node:fs';
import * as C from '../../static/crypto.js';

const id = 'K7QM3F';
const secret = '9XTR2PWD';
const iv = Uint8Array.from({ length: 12 }, (_, i) => i + 1);
const plaintext = new TextEncoder().encode('ftt known-answer vector ✓');
const manifest = { v: 2, kind: 'text', name: '', mime: 'text/plain;charset=utf-8', size: plaintext.length, chunkSize: 5242880, chunks: 2 };

const master = await C.deriveMasterKey(secret, id);
const { encKey, authToken, authHash } = await C.deriveDropKeys(master, id);
const chunk = await C.encryptChunk(encKey, id, 1, manifest.chunks, plaintext, iv);
const manifestBlob = await C.encryptManifest(encKey, id, manifest, iv);

const vector = {
  id,
  secret,
  code: C.formatCode(id, secret),
  iterations: C.PBKDF2_ITERATIONS,
  master_hex: C.toHex(master),
  fragment: C.fragmentFromMasterKey(master),
  auth_token: authToken,
  auth_hash: authHash,
  iv_hex: C.toHex(iv),
  plaintext_hex: C.toHex(plaintext),
  chunk_index: 1,
  chunk_total: manifest.chunks,
  chunk_hex: C.toHex(chunk),
  manifest_json: JSON.stringify(manifest),
  manifest_hex: C.toHex(manifestBlob),
};
writeFileSync(new URL('../vectors/ftt_v2.json', import.meta.url), `${JSON.stringify(vector, null, 2)}\n`);
console.log('wrote tests/vectors/ftt_v2.json');
