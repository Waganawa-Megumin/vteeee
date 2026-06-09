import type { ExtractResult, ParsedIndicator } from './types';
import { refang } from './defang';
import { classify } from './classify';

/**
 * Parse arbitrary input (newline list, CSV, or messy pasted text) into a
 * deduplicated list of classified indicators, with summary stats.
 *
 * Pipeline: split lines -> refang each line -> tokenize -> strip -> classify -> dedupe.
 * Tokens are split on whitespace, commas, semicolons, pipes and tabs (so CSV works);
 * defanged forms containing spaces are collapsed by `refang` before tokenization.
 */
export function extractIndicators(rawInput: string): ExtractResult {
  const seen = new Map<string, ParsedIndicator>();
  const indicators: ParsedIndicator[] = [];
  let total = 0;
  let duplicates = 0;

  for (const line of rawInput.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const refanged = refang(line);
    for (const rawTok of refanged.split(/[\s,;|\t]+/)) {
      const tok = rawTok.trim();
      if (!tok) continue;

      const { type, value, isPrivate } = classify(tok);
      if (!value) continue;
      total++;
      const key = `${type}|${value.toLowerCase()}`;
      if (seen.has(key)) {
        duplicates++;
        continue;
      }

      const ind: ParsedIndicator = {
        input: tok,
        value,
        type,
        private: isPrivate || undefined,
        excludedReason: type === 'unknown' ? 'unknown' : isPrivate ? 'private' : null,
        confidence: 1,
      };
      seen.set(key, ind);
      indicators.push(ind);
    }
  }

  const unknown = indicators.filter((i) => i.type === 'unknown').length;
  const priv = indicators.filter((i) => i.type !== 'unknown' && i.private).length;
  const enrichable = indicators.filter((i) => i.type !== 'unknown' && !i.private).length;

  return {
    indicators,
    stats: {
      total,
      unique: indicators.length,
      duplicates,
      unknown,
      private: priv,
      enrichable,
    },
  };
}

/**
 * Re-classify a list of (possibly Claude-extracted) candidate values, keeping
 * the regex engine as the source of truth for typing/normalization.
 */
export function reclassify(
  candidates: { value: string; input?: string; confidence?: number }[],
): ParsedIndicator[] {
  const seen = new Set<string>();
  const out: ParsedIndicator[] = [];
  for (const c of candidates) {
    const refanged = refang(c.value);
    const { type, value, isPrivate } = classify(refanged);
    const key = `${type}|${value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      input: c.input ?? c.value,
      value,
      type,
      private: isPrivate || undefined,
      excludedReason: type === 'unknown' ? 'unknown' : isPrivate ? 'private' : null,
      confidence: c.confidence ?? 1,
    });
  }
  return out;
}
