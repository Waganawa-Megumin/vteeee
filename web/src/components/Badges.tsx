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

/** Compact Shodan summary for the results table: open-port count + CVE count. */
export function ShodanChips({ r }: { r: NormalizedResult }) {
  const s = r.shodan;
  if (!s?.found) return null;
  const portCount = s.ports?.length ?? 0;
  const vulnCount = s.vulns?.length ?? 0;
  if (!portCount && !vulnCount) return null;
  return (
    <span className="shodan-chips">
      {portCount > 0 && (
        <span className="chip shodan" title={`Shodan open ports: ${s.ports!.join(', ')}`}>
          ⚓ {portCount} {portCount === 1 ? 'port' : 'ports'}
        </span>
      )}
      {vulnCount > 0 && (
        <span className="chip shodan-vuln" title={`Shodan CVEs: ${s.vulns!.join(', ')}`}>
          ⚠ {vulnCount} CVE
        </span>
      )}
    </span>
  );
}
