import type { DnslyticsContext, DomainToolsContext, ShodanContext, ShodanService } from '@vteeee/shared';
import { useStore } from '../state/store';
import { GtiBadge, VerdictBadge } from './Badges';
import { detectionRatio } from '../lib/verdict';

function Field({ k, v, mono }: { k: string; v?: string; mono?: boolean }) {
  if (!v) return null;
  return (
    <div className="field">
      <div className="fk">{k}</div>
      <div className={`fv${mono ? ' mono' : ''}`}>{v}</div>
    </div>
  );
}

function serviceLabel(s: ShodanService): string {
  return [s.port, s.product ?? s.module, s.version].filter(Boolean).join(' ');
}

/** Shodan OSINT block (IPs). Renders the host's ports, services, known CVEs and tags. */
function ShodanSection({ s, ip }: { s: ShodanContext; ip: string }) {
  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🛰
        </span>
        Shodan · OSINT
        {s.found && s.lastUpdate && (
          <span className="shodan-when">seen {new Date(s.lastUpdate).toLocaleDateString()}</span>
        )}
      </div>

      {!s.found ? (
        <div className="detail-note">{s.error ?? 'No Shodan record for this host.'}</div>
      ) : (
        <div className="detail-grid">
          <Field k="Org" v={s.org} />
          <Field k="ISP" v={s.isp && s.isp !== s.org ? s.isp : undefined} />
          <Field k="OS" v={s.os} />
          <Field k="Location" v={[s.city, s.country].filter(Boolean).join(', ') || undefined} />
          <Field k="ASN" v={s.asn} />
          {s.ports && s.ports.length > 0 && <Field k="Open ports" v={s.ports.join(', ')} mono />}
          {s.services && s.services.length > 0 && (
            <div className="field">
              <div className="fk">Services</div>
              <div className="fv chips">
                {s.services.map((svc, i) => (
                  <span key={`${svc.port}-${i}`} className="chip shodan mono">
                    {serviceLabel(svc)}
                  </span>
                ))}
              </div>
            </div>
          )}
          {s.vulns && s.vulns.length > 0 && (
            <div className="field">
              <div className="fk">Vulnerabilities</div>
              <div className="fv chips">
                {s.vulns.map((cve) => (
                  <a
                    key={cve}
                    className="chip shodan-vuln mono"
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noreferrer"
                    title="Open in NVD"
                  >
                    {cve}
                  </a>
                ))}
              </div>
            </div>
          )}
          {s.hostnames && s.hostnames.length > 0 && (
            <Field k="Hostnames" v={s.hostnames.join(', ')} mono />
          )}
          {s.tags && s.tags.length > 0 && (
            <div className="field">
              <div className="fk">Shodan tags</div>
              <div className="fv chips">
                {s.tags.map((t) => (
                  <span key={t} className="chip">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {s.found && (
        <a
          className="btn btn-ghost shodan-link"
          href={`https://www.shodan.io/host/${encodeURIComponent(ip)}`}
          target="_blank"
          rel="noreferrer"
        >
          Open in Shodan ↗
        </a>
      )}
    </div>
  );
}

function Chips({ items }: { items: string[] }) {
  return (
    <div className="fv chips">
      {items.map((t) => (
        <span key={t} className="chip">
          {t}
        </span>
      ))}
    </div>
  );
}

/** DomainTools Iris block — Enrich for domains, Investigate reverse for IPs. */
function DomainToolsSection({ d }: { d: DomainToolsContext }) {
  const riskClass = (s?: number) => (s != null && s >= 70 ? 'chip shodan-vuln' : 'chip shodan');
  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🧭
        </span>
        DomainTools · Iris{d.mode === 'reverse-ip' ? ' (reverse IP)' : ''}
      </div>

      {!d.found ? (
        <div className="detail-note">
          {d.error ??
            (d.mode === 'reverse-ip' ? 'No domains hosted on this IP in Iris.' : 'No Iris record for this domain.')}
        </div>
      ) : d.mode === 'enrich' ? (
        <div className="detail-grid">
          {d.riskScore != null && (
            <div className="field">
              <div className="fk">Risk score</div>
              <div className="fv chips">
                <span className={riskClass(d.riskScore)}>{d.riskScore}</span>
                {d.riskComponents?.map((c) => (
                  <span key={c.name} className="chip">
                    {c.name} {c.riskScore}
                  </span>
                ))}
              </div>
            </div>
          )}
          <Field k="Created" v={d.created} />
          <Field k="First seen" v={d.firstSeen} />
          <Field k="Registrar" v={d.registrar} />
          <Field k="IP(s)" v={d.ips?.join(', ')} mono />
          <Field k="ASN" v={d.asns?.length ? d.asns.map((a) => `AS${a}`).join(', ') : undefined} />
          <Field k="Name servers" v={d.nameServers?.join(', ')} mono />
          <Field k="MX" v={d.mailServers?.join(', ')} mono />
          <Field k="SSL issuer" v={d.sslIssuer} />
          <Field k="SSL expires" v={d.sslNotAfter} />
          <Field
            k="Website"
            v={
              [d.websiteResponse ? `HTTP ${d.websiteResponse}` : '', d.serverType, d.websiteTitle]
                .filter(Boolean)
                .join(' · ') || undefined
            }
          />
          {d.tags && d.tags.length > 0 && (
            <div className="field">
              <div className="fk">Tags</div>
              <Chips items={d.tags} />
            </div>
          )}
        </div>
      ) : (
        <div className="detail-grid">
          <Field
            k="Domains on IP"
            v={d.hostedDomainCount != null ? d.hostedDomainCount.toLocaleString() : undefined}
          />
          {d.sampleDomains && d.sampleDomains.length > 0 && (
            <div className="field">
              <div className="fk">Sample domains</div>
              <div className="fv chips">
                {d.sampleDomains.map((s) => (
                  <span key={s.domain} className={riskClass(s.riskScore)}>
                    {s.domain}
                    {s.riskScore != null ? ` (${s.riskScore})` : ''}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw DomainTools data</summary>
          <pre>{JSON.stringify(d.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

/** DNSLytics block — IPInfo for IPs, DomainInfo for domains. */
function DnslyticsSection({ d }: { d: DnslyticsContext }) {
  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🌐
        </span>
        DNSLytics · {d.kind === 'ip' ? 'IP' : 'Domain'}
      </div>

      {!d.found ? (
        <div className="detail-note">{d.error ?? 'No DNSLytics record.'}</div>
      ) : d.kind === 'ip' ? (
        <div className="detail-grid">
          <Field k="ASN" v={d.asn != null ? `AS${d.asn}` : undefined} />
          <Field k="Org" v={d.org} />
          <Field k="ISP" v={d.isp && d.isp !== d.org ? d.isp : undefined} />
          <Field k="Network" v={d.network} mono />
          <Field k="Location" v={[d.city, d.country].filter(Boolean).join(', ') || undefined} />
          <Field k="Reverse DNS" v={d.hostname} mono />
          <Field k="Domains on IP" v={d.domainsOnIp != null ? d.domainsOnIp.toLocaleString() : undefined} />
          <Field k="Threat" v={d.threat} />
        </div>
      ) : (
        <div className="detail-grid">
          <Field k="Registrar" v={d.registrar} />
          <Field k="Created" v={d.created} />
          <Field k="Updated" v={d.updated} />
          <Field k="Expires" v={d.expires} />
          <Field k="Name servers" v={d.nameServers?.join(', ')} mono />
          <Field k="MX" v={d.mailServers?.join(', ')} mono />
          <Field k="Provider" v={d.provider} />
          <Field k="Popularity" v={d.popularity != null ? d.popularity.toLocaleString() : undefined} />
          <Field k="Threat" v={d.threat} />
        </div>
      )}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw DNSLytics data</summary>
          <pre>{JSON.stringify(d.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

export function DetailPanel() {
  const selected = useStore((s) => s.selected);
  const results = useStore((s) => s.results);
  const select = useStore((s) => s.select);
  const r = selected ? results[selected] : null;
  if (!r) return null;

  return (
    <div className="detail-overlay" onClick={() => select(null)}>
      <aside className="detail-panel" onClick={(e) => e.stopPropagation()}>
        <div className="detail-head">
          <div>
            <div className="detail-title mono">{r.value}</div>
            <div className="detail-sub">
              <span className={`badge type type-${r.type}`}>{r.type}</span>{' '}
              <VerdictBadge verdict={r.verdict} status={r.status} /> <GtiBadge r={r} />
            </div>
          </div>
          <button className="btn btn-ghost" onClick={() => select(null)}>
            ✕
          </button>
        </div>

        {r.status !== 'success' && (
          <div className="detail-note">{r.errorMessage ?? `Status: ${r.status}`}</div>
        )}

        <div className="detail-grid">
          {r.detection && (
            <Field
              k="Detections"
              v={`${detectionRatio(r)}  ·  mal ${r.detection.malicious} · sus ${r.detection.suspicious} · harmless ${r.detection.harmless} · undet ${r.detection.undetected}`}
            />
          )}
          {r.reputation != null && <Field k="Reputation" v={String(r.reputation)} />}
          {r.totalVotes && (
            <Field
              k="Community votes"
              v={`harmless ${r.totalVotes.harmless} · malicious ${r.totalVotes.malicious}`}
            />
          )}
          {r.lastAnalysisDate && (
            <Field k="Last analysis" v={new Date(r.lastAnalysisDate).toLocaleString()} />
          )}
          {r.firstSeen && <Field k="First seen" v={new Date(r.firstSeen).toLocaleString()} />}
          {r.lastSeen && <Field k="Last seen" v={new Date(r.lastSeen).toLocaleString()} />}
          {r.lastModified && <Field k="Last modified (VT)" v={new Date(r.lastModified).toLocaleString()} />}
          {r.timesSubmitted != null && <Field k="Times submitted" v={r.timesSubmitted.toLocaleString()} />}
          {r.gti && (
            <Field
              k="GTI assessment"
              v={`${r.gti.verdict}${r.gti.severity ? ` · ${r.gti.severity}` : ''}${
                r.gti.threatScore != null ? ` · score ${r.gti.threatScore}` : ''
              }`}
            />
          )}

          {r.ip && (
            <>
              <Field k="Country" v={r.ip.country} />
              <Field k="ASN" v={r.ip.asn != null ? `AS${r.ip.asn}` : undefined} />
              <Field k="AS owner" v={r.ip.asOwner} />
              <Field k="Network" v={r.ip.network} mono />
              <Field k="RIR" v={r.ip.rir} />
              <Field
                k="WHOIS date"
                v={r.ip.whoisDate ? new Date(r.ip.whoisDate).toLocaleDateString() : undefined}
              />
            </>
          )}
          {r.domain && (
            <>
              <Field k="Registrar" v={r.domain.registrar} />
              <Field
                k="Created"
                v={r.domain.creationDate ? new Date(r.domain.creationDate).toLocaleDateString() : undefined}
              />
              <Field
                k="Expires"
                v={r.domain.expiration ? new Date(r.domain.expiration).toLocaleDateString() : undefined}
              />
              <Field
                k="Last DNS records"
                v={
                  r.domain.lastDnsRecordsDate
                    ? new Date(r.domain.lastDnsRecordsDate).toLocaleDateString()
                    : undefined
                }
              />
              <Field
                k="Categories"
                v={
                  r.domain.categories
                    ? Object.entries(r.domain.categories)
                        .map(([s, c]) => `${c} (${s})`)
                        .join(', ')
                    : undefined
                }
              />
            </>
          )}
          {r.url && (
            <>
              <Field k="Final URL" v={r.url.finalUrl} mono />
              <Field k="Title" v={r.url.title} />
              <Field k="HTTP status" v={r.url.httpResponseCode != null ? String(r.url.httpResponseCode) : undefined} />
            </>
          )}
          {r.file && (
            <>
              <Field k="Name" v={r.file.meaningfulName} />
              <Field k="File type" v={r.file.typeDescription} />
              <Field k="Threat label" v={r.file.threatLabel} />
              <Field k="Size" v={r.file.size != null ? `${r.file.size} bytes` : undefined} />
              <Field k="MD5" v={r.file.md5} mono />
              <Field k="SHA-1" v={r.file.sha1} mono />
              <Field k="SHA-256" v={r.file.sha256} mono />
            </>
          )}
          {r.tags.length > 0 && <Field k="Tags" v={r.tags.join(', ')} />}
          {r.links.apiId && <Field k="VT URL id (base64)" v={r.links.apiId} mono />}
        </div>

        {r.shodan && <ShodanSection s={r.shodan} ip={r.value} />}
        {r.domaintools && <DomainToolsSection d={r.domaintools} />}
        {r.dnslytics && <DnslyticsSection d={r.dnslytics} />}

        <a className="btn btn-primary detail-vt" href={r.links.gui} target="_blank" rel="noreferrer">
          Open in VirusTotal ↗
        </a>

        {r.raw != null && (
          <details className="raw">
            <summary>Raw VT attributes</summary>
            <pre>{JSON.stringify(r.raw, null, 2)}</pre>
          </details>
        )}
      </aside>
    </div>
  );
}
