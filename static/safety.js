// Content-safety rules shared by the sender (before encryption) and the receiver (after
// decryption). Pure ES module with no DOM access, so it is testable with `node --test`.
//
// These checks are guardrails for honest users. The server only ever sees ciphertext, so it
// cannot run them, and a modified sending client can skip them. The receiver runs them again on
// what it decrypted, and a sender cannot bypass that.
//
// A verdict is { blocked: string[], warnings: string[] }.

const DIRECTION_OVERRIDES = /[‪-‮⁦-⁩]/;
const UNSAFE_NAME_CHARS = /[\u0000-\u001f\u007f-\u009f‎‏‪-‮⁦-⁩]/g;
const PATH_CHARS = /[/\\:*?"<>|]/g;

export function formatBytes(n) {
  if (!Number.isFinite(n)) return 'unlimited';
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${i === 0 ? n : Number(n.toFixed(n < 10 ? 1 : 0))} ${units[i]}`;
}

/** Lower-cased last extension. Windows ignores trailing dots and spaces, so we do too. */
export function extensionOf(name) {
  const base = String(name ?? '').replace(/[.\s]+$/, '');
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : '';
}

/** A name that is safe to hand to `<a download>`: no paths, control or bidi characters. */
export function sanitizeFilename(name, maxLength = 200) {
  let clean = String(name ?? '')
    .normalize('NFC')
    .replace(UNSAFE_NAME_CHARS, '')
    .replace(PATH_CHARS, '_')
    .replace(/^[.\s]+/, '')
    .replace(/[.\s]+$/, '');
  if (clean.length > maxLength) {
    const ext = extensionOf(clean);
    const suffix = ext && ext.length < 16 ? `.${ext}` : '';
    clean = clean.slice(0, maxLength - suffix.length) + suffix;
  }
  return clean || 'download';
}

const emptyVerdict = () => ({ blocked: [], warnings: [] });

export const merge = (...verdicts) => ({
  blocked: verdicts.flatMap((v) => v.blocked),
  warnings: verdicts.flatMap((v) => v.warnings),
});

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function compileTextRules(rules) {
  const compiled = [];
  for (const rule of rules ?? []) {
    try {
      const re =
        rule.type === 'keyword'
          ? new RegExp(escapeRegExp(String(rule.pattern)), 'iu')
          : new RegExp(rule.pattern, String(rule.flags ?? '').replace(/[gy]/g, ''));
      compiled.push({ name: String(rule.name ?? rule.pattern), action: rule.action === 'block' ? 'block' : 'warn', re });
    } catch {
      // An invalid rule in the config must not break sending or receiving.
    }
  }
  return compiled;
}

/** Which text rules match: [{ name, action }]. */
export function scanText(text, rules) {
  return compileTextRules(rules)
    .filter((rule) => rule.re.test(text))
    .map(({ name, action }) => ({ name, action }));
}

export function checkText(text, cfg) {
  const verdict = emptyVerdict();
  const bytes = new TextEncoder().encode(text).length;
  if (!text.trim()) verdict.blocked.push('There is no text to send.');
  if (bytes > cfg.max_text_bytes) {
    verdict.blocked.push(`Text is ${formatBytes(bytes)}; the limit is ${formatBytes(cfg.max_text_bytes)}.`);
  }
  for (const match of scanText(text, cfg.rules?.text_rules)) {
    (match.action === 'block' ? verdict.blocked : verdict.warnings).push(`Matches safety rule: ${match.name}.`);
  }
  return verdict;
}

export function checkFileMeta({ name, type, size }, cfg) {
  const verdict = emptyVerdict();
  const rules = cfg.rules ?? {};
  if (size > cfg.max_file_bytes) {
    verdict.blocked.push(`File is ${formatBytes(size)}; the limit is ${formatBytes(cfg.max_file_bytes)}.`);
  }
  if (DIRECTION_OVERRIDES.test(String(name ?? ''))) {
    verdict.blocked.push('The file name contains hidden text-direction characters, a common disguise for programs.');
  }
  const ext = extensionOf(sanitizeFilename(name));
  if (ext && (rules.blocked_extensions ?? []).some((e) => e.toLowerCase() === ext)) {
    verdict.blocked.push(`.${ext} files are blocked for safety.`);
  }
  const mime = String(type ?? '').toLowerCase().split(';')[0].trim();
  if (mime && (rules.blocked_mime_types ?? []).includes(mime)) {
    verdict.blocked.push(`Files of type ${mime} are blocked for safety.`);
  }
  return verdict;
}

function hexToBytes(hex) {
  const clean = String(hex).replace(/[^0-9a-f]/gi, '');
  return Uint8Array.from(clean.match(/../g) ?? [], (h) => parseInt(h, 16));
}

/** Name of the first blocked file signature ("magic bytes") that `head` starts with, or null. */
export function sniffSignature(head, signatures) {
  for (const sig of signatures ?? []) {
    const magic = hexToBytes(sig.hex);
    if (magic.length && magic.length <= head.length && magic.every((b, i) => head[i] === b)) return sig.name;
  }
  return null;
}

export function checkFileHead(head, cfg) {
  const verdict = emptyVerdict();
  const hit = sniffSignature(head, cfg.rules?.blocked_signatures);
  if (hit) verdict.blocked.push(`The file's contents look like a ${hit}.`);
  return verdict;
}

/** Full sender-side check of a File/Blob: limits, name, type and content signature. */
export async function checkFile(file, cfg) {
  const head = new Uint8Array(await file.slice(0, 64).arrayBuffer());
  return merge(checkFileMeta(file, cfg), checkFileHead(head, cfg));
}
