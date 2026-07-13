import type { ReactNode } from 'react';
import type { EnrichableType, NormalizedResult } from '@vteeee/shared';
import { countryOf } from './enrichTrend';

/** ISO-3166 alpha-2 code → flag emoji (regional indicators). Empty for anything that isn't a 2-letter code. */
export function countryFlag(code: string | undefined): string {
  if (!code || !/^[A-Za-z]{2}$/.test(code)) return '';
  const cc = code.toUpperCase();
  return String.fromCodePoint(0x1f1e6 + cc.charCodeAt(0) - 65, 0x1f1e6 + cc.charCodeAt(1) - 65);
}

// Per-row intel chips (type-specific), so a row shows the concrete facts, not just a verdict.
/** IP: Shodan (org/ports/CVEs/OS/hostname) + MaxMind (flag/geo/ASN/ISP/anonymizer). */
export function ipInfraChips(r: NormalizedResult): ReactNode[] {
  const out: ReactNode[] = [];
  const cc = countryOf(r);
  const flag = countryFlag(cc);
  const geo = [r.maxmind?.city, cc].filter(Boolean).join(', ');
  if (geo) out.push(<span key="geo" className="mon-chip" title={cc ? `Country: ${cc}` : undefined}>{flag ? `${flag} ` : '📍 '}{geo}</span>);
  const net =
    r.maxmind?.asn != null
      ? `AS${r.maxmind.asn}${r.maxmind.organization ? ` ${r.maxmind.organization}` : ''}`
      : (r.shodan?.org ?? r.ip?.asOwner ?? '');
  if (net) out.push(<span key="net" className="mon-chip" title="ASN / 所有組織">{net}</span>);
  if (r.maxmind?.isp && r.maxmind.isp !== r.maxmind.organization)
    out.push(<span key="isp" className="mon-chip">ISP {r.maxmind.isp}</span>);
  const ports = r.shodan?.ports ?? [];
  if (ports.length)
    out.push(
      <span key="ports" className="mon-chip mono sev-med" title={ports.join(', ')}>
        {ports.length} ports: {ports.slice(0, 6).join(',')}
        {ports.length > 6 ? '…' : ''}
      </span>,
    );
  const vulns = r.shodan?.vulns ?? [];
  if (vulns.length)
    out.push(
      <span key="cve" className="mon-chip sev-high" title={vulns.join(', ')}>
        ⚠ {vulns.length} CVE: {vulns.slice(0, 3).join(', ')}
        {vulns.length > 3 ? '…' : ''}
      </span>,
    );
  if (r.shodan?.os) out.push(<span key="os" className="mon-chip">OS {r.shodan.os}</span>);
  if (r.shodan?.hostnames?.length) out.push(<span key="host" className="mon-chip mono">{r.shodan.hostnames[0]}</span>);
  if (r.maxmind?.anonymizerType?.length)
    out.push(<span key="anon" className="mon-chip sev-med">{r.maxmind.anonymizerType.join('/')}</span>);
  return out;
}
/** Domain: DomainTools (risk/registrar/created/NS) + DNSLytics + CTI actor/malware. */
export function domainChips(r: NormalizedResult): ReactNode[] {
  const out: ReactNode[] = [];
  const dt = r.domaintools;
  if (dt?.riskScore != null)
    out.push(
      <span key="dtr" className={`mon-chip ${dt.riskScore >= 70 ? 'sev-high' : 'sev-med'}`} title="DomainTools risk">
        DTリスク {dt.riskScore}
      </span>,
    );
  if (dt?.registrar) out.push(<span key="reg" className="mon-chip" title="Registrar">reg: {dt.registrar}</span>);
  const created = dt?.created ?? dt?.firstSeen;
  if (created) out.push(<span key="cre" className="mon-chip" title="登録/初観測">🗓 {String(created).slice(0, 10)}</span>);
  const ns = dt?.nameServers ?? r.dnslytics?.nameServers ?? [];
  if (ns.length) out.push(<span key="ns" className="mon-chip mono" title={ns.join(', ')}>NS {ns[0]}</span>);
  if (r.dnslytics?.threat) out.push(<span key="dns" className="mon-chip sev-high">DNSLytics: {r.dnslytics.threat}</span>);
  const actors = [...new Set([...(r.threatvision?.adversaries ?? []), ...(r.cyfirma?.threatActors ?? [])])];
  if (actors.length) out.push(<span key="act" className="mon-chip sev-high" title="関連アクター">🎭 {actors.slice(0, 2).join(', ')}</span>);
  const malware = [
    ...new Set([
      ...(r.threatvision?.malwareFamilies ?? []),
      ...(r.intel471?.malwareFamily ? [r.intel471.malwareFamily] : []),
      ...(r.cyfirma?.malware ?? []),
    ]),
  ];
  if (malware.length) out.push(<span key="mal" className="mon-chip sev-high" title="関連マルウェア">🦠 {malware.slice(0, 2).join(', ')}</span>);
  return out;
}
/** Hash: malware family / VT threat label / categories / file type. */
export function hashChips(r: NormalizedResult): ReactNode[] {
  const out: ReactNode[] = [];
  if (r.file?.threatLabel) out.push(<span key="lbl" className="mon-chip sev-high" title="VT 脅威ラベル">🦠 {r.file.threatLabel}</span>);
  const fam = [
    ...new Set([...(r.threatvision?.malwareFamilies ?? []), ...(r.intel471?.malwareFamily ? [r.intel471.malwareFamily] : [])]),
  ];
  if (fam.length) out.push(<span key="fam" className="mon-chip sev-high">{fam.slice(0, 2).join(', ')}</span>);
  if (r.file?.threatCategories?.length)
    out.push(<span key="cat" className="mon-chip">{r.file.threatCategories.slice(0, 3).join(', ')}</span>);
  if (r.file?.meaningfulName) out.push(<span key="nm" className="mon-chip mono" title="ファイル名">{r.file.meaningfulName}</span>);
  if (r.file?.typeDescription) out.push(<span key="ty" className="mon-chip">{r.file.typeDescription}</span>);
  if (r.file?.size) out.push(<span key="sz" className="mon-chip">{Math.round(r.file.size / 1024)} KB</span>);
  return out;
}
/** Type-appropriate intel chips for an enriched IOC row. */
export function intelChips(r: NormalizedResult, type: EnrichableType): ReactNode[] {
  if (type === 'ipv4' || type === 'ipv6') return ipInfraChips(r);
  if (type === 'domain') return domainChips(r);
  if (type === 'md5' || type === 'sha1' || type === 'sha256') return hashChips(r);
  return [];
}
