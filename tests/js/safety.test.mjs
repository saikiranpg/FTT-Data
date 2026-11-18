// Tests for static/safety.js against the real safety_rules.json.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import * as S from '../../static/safety.js';

const rules = JSON.parse(readFileSync(new URL('../../safety_rules.json', import.meta.url)));
const cfg = { max_text_bytes: 100, max_file_bytes: 1000, rules };
const file = (bytes, name, type = '') => new File([Uint8Array.from(bytes)], name, { type });
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

// ------------------------------------------------------------------ text

test('text limit is measured in UTF-8 bytes, not characters', () => {
  assert.deepEqual(S.checkText('a'.repeat(100), cfg).blocked, []);
  const v = S.checkText('é'.repeat(51), cfg); // 51 characters, 102 bytes
  assert.equal(v.blocked.length, 1);
  assert.match(v.blocked[0], /limit/);
});

test('empty or whitespace-only text is blocked', () => {
  assert.equal(S.checkText('', cfg).blocked.length, 1);
  assert.equal(S.checkText('  \n\t', cfg).blocked.length, 1);
});

test('block rules block and warn rules only warn', () => {
  assert.match(S.checkText(EICAR, cfg).blocked.join(), /EICAR/);
  const key = S.checkText('-----BEGIN OPENSSH PRIVATE KEY-----\nabc', cfg);
  assert.deepEqual(key.blocked, []);
  assert.match(key.warnings.join(), /Private key/);
  assert.match(S.checkText('id AKIAABCDEFGHIJKLMNOP', cfg).warnings.join(), /AWS/);
  assert.deepEqual(S.checkText('just a note', cfg), { blocked: [], warnings: [] });
});

test('keyword rules are case-insensitive literals', () => {
  const custom = { ...cfg, rules: { text_rules: [{ name: 'dot', type: 'keyword', pattern: 'a.b', action: 'block' }] } };
  assert.equal(S.checkText('xx A.B yy', custom).blocked.length, 1);
  assert.equal(S.checkText('axb', custom).blocked.length, 0); // "." is not a regex wildcard here
});

test('a broken regex in the config is skipped, not fatal', () => {
  const custom = { ...cfg, rules: { text_rules: [{ name: 'broken', type: 'regex', pattern: '(', action: 'block' }] } };
  assert.deepEqual(S.checkText('hello', custom), { blocked: [], warnings: [] });
});

test('scanText reports matches for the receiver', () => {
  assert.deepEqual(S.scanText(EICAR, rules.text_rules), [{ name: 'EICAR antivirus test string', action: 'block' }]);
  assert.deepEqual(S.scanText('fine', rules.text_rules), []);
});

// ------------------------------------------------------------------ files

test('blocked extensions: case-insensitive, last extension wins, trailing dots ignored', () => {
  for (const name of ['setup.exe', 'invoice.PDF.EXE', 'run.bat', 'setup.exe.', 'app.APK']) {
    assert.equal(S.checkFileMeta({ name, type: '', size: 1 }, cfg).blocked.length, 1, name);
  }
  for (const name of ['report.pdf', 'notes.exe.txt', 'photo.jpeg', 'README']) {
    assert.deepEqual(S.checkFileMeta({ name, type: '', size: 1 }, cfg).blocked, [], name);
  }
});

test('blocked MIME types, ignoring parameters', () => {
  const v = S.checkFileMeta({ name: 'x.bin', type: 'application/x-msdownload; charset=binary', size: 1 }, cfg);
  assert.match(v.blocked.join(), /x-msdownload/);
});

test('direction-override tricks in names are blocked', () => {
  const v = S.checkFileMeta({ name: 'photo\u202Egpj.exe', type: '', size: 1 }, cfg);
  assert.ok(v.blocked.some((m) => /direction/.test(m)));
});

test('oversized files are blocked', () => {
  assert.match(S.checkFileMeta({ name: 'big.bin', type: '', size: 1001 }, cfg).blocked.join(), /limit/);
});

test('executable signatures are caught whatever the file is called', async () => {
  assert.match((await S.checkFile(file([0x4d, 0x5a, 0x90, 0], 'cat.jpg', 'image/jpeg'), cfg)).blocked.join(), /Windows/);
  assert.match((await S.checkFile(file([0x7f, 0x45, 0x4c, 0x46, 2], 'notes.txt'), cfg)).blocked.join(), /ELF/);
  assert.match((await S.checkFile(file([0xcf, 0xfa, 0xed, 0xfe], 'tool'), cfg)).blocked.join(), /Mach-O/);
  assert.deepEqual(await S.checkFile(file([0x25, 0x50, 0x44, 0x46], 'doc.pdf', 'application/pdf'), cfg), { blocked: [], warnings: [] });
});

test('receiver can re-check decrypted bytes with checkFileHead', () => {
  assert.equal(S.checkFileHead(Uint8Array.from([0x4d, 0x5a]), cfg).blocked.length, 1);
  assert.equal(S.checkFileHead(new Uint8Array(0), cfg).blocked.length, 0);
});

// ------------------------------------------------------------------ names

test('sanitizeFilename strips paths, control and bidi characters', () => {
  assert.equal(S.sanitizeFilename('../../etc/passwd'), '_.._etc_passwd');
  assert.equal(S.sanitizeFilename('C:\\Users\\me\\a.txt'), 'C__Users_me_a.txt');
  assert.equal(S.sanitizeFilename('a\u202Etxt.exe'), 'atxt.exe');
  assert.equal(S.sanitizeFilename('bad\u0000\u0007name.txt'), 'badname.txt');
  assert.equal(S.sanitizeFilename('.hidden'), 'hidden');
  assert.equal(S.sanitizeFilename(''), 'download');
  assert.equal(S.sanitizeFilename('   '), 'download');
  assert.equal(S.sanitizeFilename(undefined), 'download');
});

test('long names are shortened but keep their extension', () => {
  const name = S.sanitizeFilename(`${'a'.repeat(300)}.pdf`);
  assert.equal(name.length, 200);
  assert.ok(name.endsWith('.pdf'));
});

test('formatBytes', () => {
  assert.equal(S.formatBytes(0), '0 B');
  assert.equal(S.formatBytes(1536), '1.5 KB');
  assert.equal(S.formatBytes(5 * 1024 * 1024), '5 MB');
  assert.equal(S.formatBytes(500 * 1024 * 1024), '500 MB');
  assert.equal(S.formatBytes(Infinity), 'unlimited');
});
