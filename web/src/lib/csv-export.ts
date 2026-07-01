import type { NormalizedResult } from '@vteeee/shared';
import { detectionRatio } from './verdict';

function cell(v: unknown): string {
  const s = v == null ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function resultsToCsv(results: NormalizedResult[]): string {
  const header = [
    'indicator',
    'type',
    'status',
    'verdict',
    'detections',
    'reputation',
    'gti_verdict',
    'gti_severity',
    'country_or_registrar',
    'asn_or_categories',
    'shodan_ports',
    'shodan_vulns',
    'last_analysis',
    'first_seen',
    'last_seen',
    'times_submitted',
    'last_modified',
    'domaintools_risk',
    'dnslytics',
    'vt_link',
  ];
  const rows = results.map((r) => [
    r.value,
    r.type,
    r.status,
    r.verdict,
    detectionRatio(r),
    r.reputation ?? '',
    r.gti?.verdict ?? '',
    r.gti?.severity ?? '',
    r.ip?.country ?? r.domain?.registrar ?? '',
    r.ip?.asOwner ?? (r.domain?.categories ? Object.values(r.domain.categories).join('|') : ''),
    r.shodan?.found ? (r.shodan.ports?.join('|') ?? '') : '',
    r.shodan?.found ? (r.shodan.vulns?.join('|') ?? '') : '',
    r.lastAnalysisDate ?? '',
    r.firstSeen ?? '',
    r.lastSeen ?? '',
    r.timesSubmitted ?? '',
    r.lastModified ?? '',
    r.domaintools?.found
      ? r.domaintools.mode === 'reverse-ip'
        ? `${r.domaintools.hostedDomainCount ?? 0} domains on IP`
        : (r.domaintools.riskScore ?? '')
      : '',
    r.dnslytics?.found
      ? r.dnslytics.kind === 'ip'
        ? [r.dnslytics.asn ? `AS${r.dnslytics.asn}` : '', r.dnslytics.org].filter(Boolean).join(' ')
        : (r.dnslytics.ips?.[0] ?? r.dnslytics.nameServers?.[0] ?? '')
      : '',
    r.links.gui,
  ]);
  return [header, ...rows].map((row) => row.map(cell).join(',')).join('\n');
}

export function downloadCsv(filename: string, csv: string): void {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
