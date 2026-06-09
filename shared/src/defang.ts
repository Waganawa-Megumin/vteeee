/**
 * Refang / normalization of defanged indicators.
 *
 * Two stages:
 *  - `refang(line)`  : whole-line transforms that collapse obfuscation which may
 *                       contain spaces (worded "dot"/"at", "hxxp", "[://]", "[:]"),
 *                       so that subsequent whitespace tokenization works.
 *  - `stripToken(t)` : per-token cleanup of wrapping characters and trailing
 *                       sentence punctuation.
 *
 * The bracketed forms ([.] (.) {.} [dot] (dot)) are unambiguous and handled fully.
 * The bare spaced forms (" dot ", " . ", " at ") are constrained with label-char
 * look-arounds to limit false positives in prose; for very messy report text the
 * optional Claude smart-parse is the recommended path.
 */

const LEADING_WRAP = /^[\s<>"'`“”‘’()[\]{}*•‣◦|]+/;
const TRAILING_WRAP = /[\s<>"'`“”‘’()[\]{}|]+$/;
const TRAILING_PUNCT = /[.,;:!?]+$/;

/** Collapse defanging artifacts across a whole line. Case-insensitive where relevant. */
export function refang(line: string): string {
  let s = line.normalize('NFKC');

  // Strip zero-width characters; normalize non-breaking spaces to a normal space.
  s = s.replace(/[\u200B-\u200D\uFEFF]/g, '').replace(/\u00A0/g, ' ');

  // Scheme obfuscation (do hxxps before hxxp).
  s = s
    .replace(/hxxps/gi, 'https')
    .replace(/hxxp/gi, 'http')
    .replace(/\bfxp:/gi, 'ftp:');

  // Scheme separator obfuscation: [://] (://) {://}  and  [:] (:) {:}
  s = s.replace(/[[({]\s*:\/\/\s*[\])}]/g, '://');
  s = s.replace(/[[({]\s*:\s*[\])}]/g, ':');
  // Stray space immediately after the scheme separator: "http:// evil.com"
  s = s.replace(/:\/\/\s+/g, '://');

  // @ obfuscation: [@] (@) [at] (at)  and worded " at " between label chars.
  s = s.replace(/[[({]\s*(?:@|at)\s*[\])}]/gi, '@');
  s = s.replace(/(?<=[a-z0-9_-])\s+at\s+(?=[a-z0-9_-])/gi, '@');

  // Dot obfuscation.
  s = s.replace(/[[({]\s*\.\s*[\])}]/g, '.'); // [.] (.) {.}
  s = s.replace(/[[({]\s*dot\s*[\])}]/gi, '.'); // [dot] (dot) {dot}
  s = s.replace(/\\\./g, '.'); // escaped dot
  s = s.replace(/(?<=[a-z0-9-])\s+dot\s+(?=[a-z0-9-])/gi, '.'); // worded spaced "dot"
  s = s.replace(/(?<=[a-z0-9-])\s+\.\s+(?=[a-z0-9-])/g, '.'); // spaced " . " between labels

  return s;
}

/** Strip wrapping characters, markdown link syntax, and trailing sentence punctuation. */
export function stripToken(token: string): string {
  let t = token.trim();

  // Markdown link: [text](url) -> url
  const md = t.match(/^\[[^\]]*\]\((.+)\)$/);
  if (md) t = md[1].trim();

  let prev = '';
  while (t !== prev) {
    prev = t;
    t = t.replace(LEADING_WRAP, '');
    t = t.replace(TRAILING_WRAP, '');
    t = t.replace(TRAILING_PUNCT, '');
  }
  return t;
}
