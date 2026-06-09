import type { IocType, NormalizedResult, ResultStatus, Verdict } from '@vteeee/shared';
import { gtiSeverityLabel, gtiVerdictLabel } from '../lib/verdict';

export function VerdictBadge({ verdict, status }: { verdict: Verdict; status?: ResultStatus }) {
  if (status && status !== 'success') {
    const map: Record<string, string> = {
      not_found: 'Not found',
      rate_limited: 'Rate limited',
      error: 'Error',
    };
    return <span className={`badge st-${status}`}>{map[status] ?? status}</span>;
  }
  const label = verdict.charAt(0).toUpperCase() + verdict.slice(1);
  return <span className={`badge v-${verdict}`}>{label}</span>;
}

export function TypeBadge({ type }: { type: IocType }) {
  return <span className={`badge type type-${type}`}>{type}</span>;
}

export function GtiBadge({ r }: { r: NormalizedResult }) {
  if (!r.gti) return null;
  const v = gtiVerdictLabel(r.gti.verdict);
  const sev = gtiSeverityLabel(r.gti.severity);
  const parts = [v, sev, r.gti.threatScore != null ? String(r.gti.threatScore) : null].filter(Boolean);
  return <span className="badge gti" title="Google Threat Intelligence assessment">GTI {parts.join(' · ')}</span>;
}
