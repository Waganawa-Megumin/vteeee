import type { NormalizedResult } from '@vteeee/shared';
import { detectionRatio } from './verdict';

function cell(v: unknown): string {
  let s = v == null ? '' : String(v);
  // CSV formula-injection guard: a leading = + - @ TAB or CR makes Excel/Sheets treat the cell as a
  // formula (DDE / =HYPERLINK data-exfil). Prefix a single quote so it renders as literal text.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
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
    'maxmind_geo',
    'last_analysis',
    'first_seen',
    'last_seen',
    'times_submitted',
    'last_modified',
    'domaintools_risk',
    'dnslytics',
    'intel471',
    'cyfirma',
    'threatvision',
    'recordedfuture',
    'abuseipdb',
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
    r.maxmind?.found
      ? [
          [r.maxmind.city, r.maxmind.countryCode].filter(Boolean).join(', '),
          r.maxmind.asn != null ? `AS${r.maxmind.asn}` : '',
          r.maxmind.anonymizerType?.length ? r.maxmind.anonymizerType.join('/') : '',
        ]
          .filter(Boolean)
          .join(' · ')
      : '',
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
    r.intel471?.found
      ? [r.intel471.totalCount != null ? `${r.intel471.totalCount} recs` : '', r.intel471.reports ? `${r.intel471.reports} reports` : '']
          .filter(Boolean)
          .join(' · ')
      : '',
    r.cyfirma?.found
      ? [
          r.cyfirma.indicatorRiskScore != null ? `risk ${r.cyfirma.indicatorRiskScore}/10` : '',
          r.cyfirma.threatActors?.length ? r.cyfirma.threatActors.join('|') : '',
          r.cyfirma.relatedCount ? `${r.cyfirma.relatedCount} linked` : '',
        ]
          .filter(Boolean)
          .join(' · ')
      : '',
    r.threatvision?.found
      ? [
          r.threatvision.riskLevel ?? '',
          r.threatvision.adversaries?.length ? r.threatvision.adversaries.join('|') : '',
          r.threatvision.malwareFamilies?.length ? r.threatvision.malwareFamilies.join('|') : '',
        ]
          .filter(Boolean)
          .join(' · ')
      : '',
    r.recordedfuture?.found
      ? [
          r.recordedfuture.riskScore != null ? `risk ${r.recordedfuture.riskScore}/99` : '',
          r.recordedfuture.criticalityLabel ?? '',
          r.recordedfuture.relatedActors?.length ? r.recordedfuture.relatedActors.map((a) => a.name).join('|') : '',
          r.recordedfuture.relatedMalware?.length ? r.recordedfuture.relatedMalware.map((m) => m.name).join('|') : '',
        ]
          .filter(Boolean)
          .join(' · ')
      : '',
    r.abuseipdb?.found
      ? [
          r.abuseipdb.abuseConfidenceScore != null ? `abuse ${r.abuseipdb.abuseConfidenceScore}/100` : '',
          r.abuseipdb.totalReports != null ? `${r.abuseipdb.totalReports} reports` : '',
          r.abuseipdb.categories?.length ? r.abuseipdb.categories.join('|') : '',
        ]
          .filter(Boolean)
          .join(' · ')
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
