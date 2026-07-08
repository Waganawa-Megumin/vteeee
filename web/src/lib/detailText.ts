import type { NormalizedResult } from '@vteeee/shared';
import { detectionRatio } from './verdict';

/**
 * Render the full enrichment detail for one indicator as a readable, paste-into-a-ticket
 * plain-text report — VT core + every configured provider section + the VT deep link.
 */
export function resultToText(r: NormalizedResult): string {
  const L: string[] = [];
  const push = (k: string, v: unknown): void => {
    if (v == null || v === '' || (Array.isArray(v) && v.length === 0)) return;
    L.push(`${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
  };
  const dt = (d?: string | null): string | undefined => (d ? new Date(d).toLocaleString() : undefined);
  const day = (d?: string | null): string | undefined => (d ? new Date(d).toLocaleDateString() : undefined);

  L.push(`# ${r.value}  [${r.type}]`);
  push('Status', r.status);
  if (r.errorMessage) push('Note', r.errorMessage);
  push('Verdict', r.verdict);
  if (r.detection)
    push(
      'Detections',
      `${detectionRatio(r)} (mal ${r.detection.malicious} · sus ${r.detection.suspicious} · harmless ${r.detection.harmless} · undet ${r.detection.undetected})`,
    );
  push('Reputation', r.reputation ?? undefined);
  if (r.totalVotes) push('Community votes', `harmless ${r.totalVotes.harmless} · malicious ${r.totalVotes.malicious}`);
  push('Last analysis', dt(r.lastAnalysisDate));
  push('First seen', dt(r.firstSeen));
  push('Last seen', dt(r.lastSeen));
  push('Times submitted', r.timesSubmitted ?? undefined);
  push('Last modified (VT)', dt(r.lastModified));
  if (r.gti)
    push(
      'GTI',
      `${r.gti.verdict}${r.gti.severity ? ` · ${r.gti.severity}` : ''}${
        r.gti.threatScore != null ? ` · score ${r.gti.threatScore}` : ''
      }`,
    );
  push('Tags', r.tags);

  if (r.ip) {
    push('Country', r.ip.country);
    push('ASN', r.ip.asn != null ? `AS${r.ip.asn}` : undefined);
    push('AS owner', r.ip.asOwner);
    push('Network', r.ip.network);
    push('RIR', r.ip.rir);
  }
  if (r.domain) {
    push('Registrar', r.domain.registrar);
    push('Created', day(r.domain.creationDate));
    push('Expires', day(r.domain.expiration));
    if (r.domain.categories)
      push('Categories', Object.entries(r.domain.categories).map(([s, c]) => `${c} (${s})`));
  }
  if (r.url) {
    push('Final URL', r.url.finalUrl);
    push('Title', r.url.title);
    push('HTTP status', r.url.httpResponseCode);
  }
  if (r.file) {
    push('Name', r.file.meaningfulName);
    push('File type', r.file.typeDescription);
    push('Threat label', r.file.threatLabel);
    push('Size', r.file.size != null ? `${r.file.size} bytes` : undefined);
    push('MD5', r.file.md5);
    push('SHA-1', r.file.sha1);
    push('SHA-256', r.file.sha256);
  }

  if (r.shodan?.found) {
    L.push('', '## Shodan');
    push('Org', r.shodan.org);
    push('ISP', r.shodan.isp);
    push('OS', r.shodan.os);
    push('Location', [r.shodan.city, r.shodan.country].filter(Boolean).join(', '));
    push('ASN', r.shodan.asn);
    push('Open ports', r.shodan.ports);
    push('CVEs', r.shodan.vulns);
    push('Tags', r.shodan.tags);
  }
  if (r.maxmind?.found) {
    const m = r.maxmind;
    L.push('', '## MaxMind GeoIP');
    push('Country', [m.country, m.countryCode ? `(${m.countryCode})` : ''].filter(Boolean).join(' '));
    push('Region', m.subdivisions?.length ? m.subdivisions.join(' > ') : m.subdivision);
    push('City', m.city);
    push('Postal', m.postal);
    push('Time zone', m.timeZone);
    if (m.latitude != null && m.longitude != null) {
      // MaxMind ToS: coordinates are an approximate area — always paired with the accuracy radius.
      push(
        'Coordinates',
        `${m.latitude}, ${m.longitude}${m.accuracyRadius != null ? ` (approx — accuracy radius ±${m.accuracyRadius} km, not a precise address)` : ' (approximate area, not a precise address)'}`,
      );
    }
    push('Network', m.network);
    push('ASN', m.asn != null ? [`AS${m.asn}`, m.asnOrganization].filter(Boolean).join(' ') : m.asnOrganization);
    push('ISP', m.isp);
    push('Organization', m.organization);
    push('Domain', m.domain);
    push('Connection', m.connectionType);
    push('Anonymizer', m.anonymizerType);
    push('VPN provider', m.providerName);
    push('Static IP score', m.staticIpScore != null ? m.staticIpScore.toFixed(2) : undefined);
    push('IP risk', m.ipRisk);
    push('User type', m.userType);
  }
  if (r.domaintools?.found) {
    L.push('', '## DomainTools Iris');
    push('Risk score', r.domaintools.riskScore);
    push('Registrar', r.domaintools.registrar);
    push('Created', r.domaintools.created);
    push('IPs', r.domaintools.ips);
    push('Name servers', r.domaintools.nameServers);
    if (r.domaintools.mode === 'reverse-ip') push('Domains on IP', r.domaintools.hostedDomainCount);
  }
  if (r.dnslytics?.found) {
    L.push('', '## DNSLytics');
    push('ASN', r.dnslytics.asn != null ? `AS${r.dnslytics.asn}` : undefined);
    push('Org', r.dnslytics.org);
    push('Hostname', r.dnslytics.hostname);
    push('Domains on IP', r.dnslytics.domainsOnIp);
    push('IPs', r.dnslytics.ips);
    push('Name servers', r.dnslytics.nameServers);
    push('Threat', r.dnslytics.threat);
  }
  if (r.intel471?.found) {
    L.push('', '## Intel 471 (Titan)');
    push('Malware family', r.intel471.malwareFamily);
    push('Confidence', r.intel471.confidence);
    push('Threat type', r.intel471.threatType);
    push('Context', r.intel471.context);
    push('MITRE tactic', r.intel471.mitreTactics);
    push('ISP', [r.intel471.isp, r.intel471.ispCountryCode].filter(Boolean).join(' · '));
    push('IOC records', r.intel471.totalCount);
    push('Reports', r.intel471.reports);
    push('Actors', r.intel471.actors);
    push('Portal', r.intel471.portalUrl);
  }
  if (r.cyfirma?.found) {
    L.push('', '## CYFIRMA (DeCYFIR)');
    const risk = r.cyfirma.indicatorRiskScore ?? r.cyfirma.riskScore;
    push('Risk', risk != null ? `${risk}/10` : undefined);
    push('Recommended action', r.cyfirma.action);
    push('Story', r.cyfirma.story);
    push('ASN', [r.cyfirma.asn ? `AS${r.cyfirma.asn}` : '', r.cyfirma.asnOwner].filter(Boolean).join(' '));
    push('Country', r.cyfirma.country);
    push('Threat actors', r.cyfirma.threatActors);
    push('Campaigns', r.cyfirma.campaigns);
    push('Malware', r.cyfirma.malware);
    if (r.cyfirma.related) {
      push('Related IPs', r.cyfirma.related.ips);
      push('Related domains', r.cyfirma.related.domains);
      push('Related hashes', r.cyfirma.related.hashes);
      push('Related CVEs', r.cyfirma.related.cves);
    }
  }
  if (r.recordedfuture?.found) {
    const rf = r.recordedfuture;
    L.push('', '## Recorded Future');
    push('Risk', rf.riskScore != null ? `${rf.riskScore}/99 (${rf.criticalityLabel ?? rf.criticality ?? '—'})` : undefined);
    push('Summary', rf.riskSummary);
    if (rf.evidence?.length)
      push(
        'Evidence',
        rf.evidence.map((e) => `${e.criticalityLabel ?? e.criticality ?? ''} ${e.rule}`.trim()),
      );
    push('Threat lists', rf.threatLists);
    push('Threat actors', rf.relatedActors?.map((a) => a.name));
    push('Malware', rf.relatedMalware?.map((m) => m.name));
    push('MITRE', rf.mitre);
    push('ASN', [rf.asn, rf.organization].filter(Boolean).join(' · '));
    push('Location', [rf.city, rf.country].filter(Boolean).join(', '));
    push('AI Insights', rf.aiInsights);
    push('Intelligence Card', rf.intelCard);
  }
  if (r.abuseipdb?.found) {
    const a = r.abuseipdb;
    L.push('', '## AbuseIPDB');
    push('Abuse confidence', a.abuseConfidenceScore != null ? `${a.abuseConfidenceScore}/100` : undefined);
    push(
      'Reports',
      a.totalReports != null
        ? `${a.totalReports}${a.numDistinctUsers != null ? ` from ${a.numDistinctUsers} reporters` : ''}`
        : undefined,
    );
    push('Last reported', dt(a.lastReportedAt));
    push('Usage type', a.usageType);
    push('ISP', a.isp);
    push('Domain', a.domain);
    push('Country', [a.countryName, a.countryCode].filter(Boolean).join(' '));
    push('Flags', [a.isTor ? 'Tor exit node' : '', a.isWhitelisted ? 'Whitelisted' : ''].filter(Boolean).join(', '));
    push('Attack categories', a.categories);
  }
  if (r.threatvision?.found) {
    L.push('', '## ThreatVision (TeamT5)');
    push(
      'Risk',
      [r.threatvision.riskLevel, r.threatvision.riskScore != null ? `score ${r.threatvision.riskScore}` : '']
        .filter(Boolean)
        .join(' · '),
    );
    push('Adversaries', r.threatvision.adversaries);
    push('Malware', r.threatvision.malwareFamilies);
    push('Attributes', r.threatvision.attributes);
    push('Location', [r.threatvision.city, r.threatvision.region, r.threatvision.country].filter(Boolean).join(', '));
    push('Registrar', r.threatvision.registrar);
    push('First seen', day(r.threatvision.firstSeen));
  }

  L.push('', `VirusTotal: ${r.links.gui}`);
  return L.join('\n');
}
