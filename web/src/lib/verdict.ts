import type { NormalizedResult, Verdict } from '@vteeee/shared';

export const VERDICT_LABEL: Record<Verdict, string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  harmless: 'Harmless',
  undetected: 'Undetected',
  unknown: 'Unknown',
};

/** Sort weight so the most dangerous indicators float to the top by default. */
export function verdictRank(v: Verdict): number {
  switch (v) {
    case 'malicious':
      return 5;
    case 'suspicious':
      return 4;
    case 'undetected':
      return 2;
    case 'harmless':
      return 1;
    default:
      return 0;
  }
}

export function detectionRatio(r: NormalizedResult): string {
  if (!r.detection) return '—';
  const flagged = r.detection.malicious + r.detection.suspicious;
  return `${flagged}/${r.detection.total}`;
}

export function gtiSeverityLabel(sev: string | null | undefined): string | null {
  if (!sev) return null;
  return sev.replace(/^SEVERITY_/, '');
}

export function gtiVerdictLabel(v: string | undefined): string | null {
  if (!v) return null;
  return v.replace(/^VERDICT_/, '');
}
