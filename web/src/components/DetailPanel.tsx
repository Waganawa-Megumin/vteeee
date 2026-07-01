import { useState } from 'react';
import type {
  CyfirmaContext,
  CyfirmaRelated,
  CyfirmaSearch,
  DnslyticsContext,
  DomainToolsContext,
  EnrichableType,
  Intel471Context,
  Intel471Malware,
  Intel471Search,
  Intel471SearchItem,
  ShodanContext,
  ShodanService,
} from '@vteeee/shared';
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
        DNSLytics · {d.kind === 'ip' ? 'IP' : 'Domain (hosting history)'}
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
          {d.hostedDomains && d.hostedDomains.length > 0 && (
            <div className="field">
              <div className="fk">Hosted domains</div>
              <div className="fv chips">
                {d.hostedDomains.map((dm) => (
                  <span key={dm} className="chip mono">
                    {dm}
                  </span>
                ))}
              </div>
            </div>
          )}
          <Field k="Threat" v={d.threat} />
        </div>
      ) : (
        <div className="detail-grid">
          <Field k="IP history (A/AAAA)" v={d.ips?.join(', ')} mono />
          <Field k="Name servers" v={d.nameServers?.join(', ')} mono />
          <Field k="Mail servers" v={d.mailServers?.join(', ')} mono />
          <Field k="SPF" v={d.spf?.join('  |  ')} mono />
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

interface IntelCount {
  label: string;
  count: number;
  items?: Intel471SearchItem[];
}

/** Non-zero Global Search categories, each with its top drill-down items (when available). */
function intelCounts(s: Intel471Search): IntelCount[] {
  const it = s.items ?? {};
  const entries: { label: string; count?: number; items?: Intel471SearchItem[] }[] = [
    { label: 'reports', count: s.reports, items: it.reports },
    { label: 'malware', count: s.malwareReports, items: it.malwareReports },
    { label: 'actors', count: s.actors, items: it.actors },
    { label: 'entities', count: s.entities, items: it.entities },
    { label: 'events', count: s.events, items: it.events },
    { label: 'posts', count: s.posts, items: it.posts },
    { label: 'news', count: s.news, items: it.news },
    { label: 'IOCs', count: s.iocs, items: it.iocs },
    { label: 'indicators', count: s.indicators, items: it.indicators },
    { label: 'credentials', count: s.credentials, items: it.credentials },
    { label: 'cred sets', count: s.credentialSets },
    { label: 'data-leak posts', count: s.dataLeakPosts },
    { label: 'breach alerts', count: s.breachAlerts },
    { label: 'CVEs', count: s.cveReports, items: it.cveReports },
  ];
  return entries.filter((e): e is IntelCount => typeof e.count === 'number' && e.count > 0);
}

/** Intel 471 (Titan) IOC block — auto IOC context + on-demand Global Search counts. */
function Intel471Section({ d, value, type }: { d: Intel471Context; value: string; type: EnrichableType }) {
  const search = useStore((s) => s.intel471Search);
  const malware = useStore((s) => s.intel471Malware);
  const [gs, setGs] = useState<{ loading: boolean; data?: Intel471Search }>({ loading: false });
  const [mw, setMw] = useState<{ loading: boolean; data?: Intel471Malware } | null>(null);
  const [openCat, setOpenCat] = useState<string | null>(null);

  async function runSearch() {
    setOpenCat(null);
    setGs({ loading: true });
    setGs({ loading: false, data: await search(value, type) });
  }

  async function runMalware() {
    if (!d.malwareFamilyUid) return;
    setMw({ loading: true });
    setMw({ loading: false, data: await malware(d.malwareFamilyUid, d.malwareFamily) });
  }

  const activeRange =
    [d.activeFrom, d.activeTill].filter(Boolean).map((s) => new Date(s!).toLocaleDateString()).join(' – ') || undefined;
  const linked =
    [
      d.reports != null ? `${d.reports} reports` : '',
      d.actors != null ? `${d.actors} actors` : '',
      d.malwareReports ? `${d.malwareReports} malware` : '',
      d.events ? `${d.events} events` : '',
    ]
      .filter(Boolean)
      .join(' · ') || undefined;
  const counts = gs.data && !gs.data.error ? intelCounts(gs.data) : [];

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🦉
        </span>
        Intel 471 · Titan
        {d.found && (d.malwareFamily || d.totalCount != null) && (
          <span className="shodan-when">
            {d.malwareFamily ? 'Malware Intel + IOC' : `${d.totalCount!.toLocaleString()} IOC records`}
          </span>
        )}
      </div>

      {!d.found ? (
        <div className="detail-note">{d.error ?? 'No Intel 471 record for this indicator.'}</div>
      ) : (
        <div className="detail-grid">
          {d.malwareFamily && (
            <div className="field">
              <div className="fk">Malware family</div>
              <div className="fv chips">
                {d.malwareFamilyUid ? (
                  <button
                    className="chip shodan-vuln"
                    onClick={runMalware}
                    title="Fetch Intel 471 malware details (reports · aka · MITRE) + open in Titan"
                  >
                    🔎 {d.malwareFamily}
                  </button>
                ) : (
                  <span className="chip shodan-vuln">{d.malwareFamily}</span>
                )}
                {d.confidence && <span className="chip">confidence {d.confidence}</span>}
              </div>
            </div>
          )}
          <Field k="Threat type" v={d.threatType} />
          <Field k="Context" v={d.context} />
          <Field k="MITRE tactic" v={d.mitreTactics?.replace(/_/g, ' ')} />
          <Field k="Active" v={activeRange} />
          <Field k="Last updated" v={d.lastUpdated ? new Date(d.lastUpdated).toLocaleString() : undefined} />
          <Field k="IOC type" v={d.type} />
          <Field k="ISP" v={[d.isp, d.ispCountryCode].filter(Boolean).join(' · ') || undefined} />
          <Field k="Linked" v={linked} />
          {d.reportTitles && d.reportTitles.length > 0 && (
            <div className="field">
              <div className="fk">Reports</div>
              <div className="fv">
                {d.reportTitles.map((t, i) => (
                  <div key={i}>• {t}</div>
                ))}
              </div>
            </div>
          )}
          <Field k="GIR" v={d.girs && d.girs.length > 0 ? d.girs.join(', ') : undefined} />
        </div>
      )}

      {mw && (
        <div className="cyfirma-actor">
          {mw.loading ? (
            <div className="detail-note">Loading malware profile…</div>
          ) : mw.data?.error ? (
            <div className="detail-note">{mw.data.error}</div>
          ) : mw.data ? (
            <>
              <div className="cyfirma-actor-title">
                Malware · {mw.data.family ?? d.malwareFamily}
                {mw.data.reportCount != null ? ` · ${mw.data.reportCount.toLocaleString()} reports` : ''}
              </div>
              <div className="detail-grid">
                <Field k="aka" v={mw.data.aka && mw.data.aka.length ? mw.data.aka.join(', ') : undefined} />
                <Field k="Summary" v={mw.data.summary} />
                <Field
                  k="MITRE tactics"
                  v={mw.data.mitreTactics?.map((t) => t.replace(/_/g, ' ')).join(', ')}
                />
                <Field k="GIR" v={mw.data.girs && mw.data.girs.length ? mw.data.girs.join(', ') : undefined} />
                <Field
                  k="Active"
                  v={
                    [mw.data.activeFrom, mw.data.activeTill]
                      .filter(Boolean)
                      .map((s) => new Date(s!).toLocaleDateString())
                      .join(' – ') || undefined
                  }
                />
                {mw.data.reports && mw.data.reports.length > 0 && (
                  <div className="field">
                    <div className="fk">Reports</div>
                    <div className="fv">
                      {mw.data.reports.map((t, i) => (
                        <div key={i}>• {t}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              {mw.data.portalUrl && (
                <a className="btn btn-ghost shodan-link" href={mw.data.portalUrl} target="_blank" rel="noreferrer">
                  Open malware profile ↗
                </a>
              )}
            </>
          ) : null}
        </div>
      )}

      <div className="i471-actions">
        {d.portalUrl && (
          <a className="btn btn-ghost shodan-link" href={d.portalUrl} target="_blank" rel="noreferrer">
            Open report ↗
          </a>
        )}
        <button className="btn btn-ghost" onClick={runSearch} disabled={gs.loading}>
          {gs.loading ? 'Searching…' : 'Global Search'}
        </button>
      </div>

      {gs.data &&
        (gs.data.error ? (
          <div className="detail-note">{gs.data.error}</div>
        ) : counts.length ? (
          <div className="i471-search-results">
            <div className="fv chips">
              {counts.map((c) => {
                const hasItems = !!c.items && c.items.length > 0;
                const open = openCat === c.label;
                return (
                  <button
                    key={c.label}
                    className={`chip${hasItems ? ' chip-btn' : ''}${open ? ' chip-open' : ''}`}
                    onClick={() => hasItems && setOpenCat(open ? null : c.label)}
                    disabled={!hasItems}
                    title={hasItems ? `Show top ${c.label}` : `${c.count} ${c.label} — no preview available`}
                  >
                    {c.label} {c.count.toLocaleString()}
                    {hasItems ? (open ? ' ▾' : ' ▸') : ''}
                  </button>
                );
              })}
            </div>
            {(() => {
              const open = counts.find((c) => c.label === openCat);
              if (!open?.items?.length) return null;
              return (
                <div className="i471-search-items">
                  {open.items.map((it, i) =>
                    it.url ? (
                      <a key={i} className="i471-search-item" href={it.url} target="_blank" rel="noreferrer">
                        • {it.title} ↗
                      </a>
                    ) : (
                      <div key={i} className="i471-search-item">
                        • {it.title}
                      </div>
                    ),
                  )}
                </div>
              );
            })()}
          </div>
        ) : (
          <div className="detail-note">No matches across Intel 471 collections.</div>
        ))}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw Intel 471 data</summary>
          <pre>{JSON.stringify(d.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

function trendArrow(t?: string): string {
  const u = (t ?? '').toUpperCase();
  if (u === 'UP' || u === 'INCREASE' || u === 'HIGH') return ' ↑';
  if (u === 'DOWN' || u === 'DECREASE' || u === 'LOW') return ' ↓';
  return '';
}

/** CYFIRMA related-infra buckets that have at least one value, as [label, values] pairs. */
function cyfirmaRelated(rel: CyfirmaRelated): [string, string[]][] {
  const groups: [string, string[] | undefined][] = [
    ['IPs', rel.ips],
    ['domains', rel.domains],
    ['hostnames', rel.hostnames],
    ['URLs', rel.urls],
    ['hashes', rel.hashes],
    ['emails', rel.emails],
    ['CVEs', rel.cves],
    ['exploits', rel.exploits],
  ];
  return groups.filter((g): g is [string, string[]] => Array.isArray(g[1]) && g[1].length > 0);
}

/**
 * CYFIRMA DeCYFIR block — Risk Dossier scores + recommended action + correlated infrastructure
 * (attack-infra side), STIX attribution (actors/campaigns/malware), and an on-demand actor
 * deep-dive (broad search) reachable by clicking a threat-actor chip.
 */
function CyfirmaSection({ d }: { d: CyfirmaContext }) {
  const search = useStore((s) => s.cyfirmaSearch);
  const [actor, setActor] = useState<{ name: string; loading: boolean; data?: CyfirmaSearch } | null>(null);

  async function runActor(name: string) {
    setActor({ name, loading: true });
    setActor({ name, loading: false, data: await search(name) });
  }

  const rel = d.related ? cyfirmaRelated(d.related) : [];
  const scoreLine =
    [
      d.riskScore != null ? `risk ${d.riskScore}/10${trendArrow(d.riskScoreTrend)}` : '',
      d.externalThreatScore != null
        ? `ext threat ${d.externalThreatScore}/10${trendArrow(d.externalThreatScoreTrend)}`
        : '',
    ]
      .filter(Boolean)
      .join('  ·  ') || undefined;

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🛡
        </span>
        CYFIRMA · DeCYFIR
        {d.found && d.indicatorRiskScore != null && (
          <span className="shodan-when">risk {d.indicatorRiskScore}/10</span>
        )}
      </div>

      {!d.found ? (
        <div className="detail-note">{d.error ?? 'No CYFIRMA record for this indicator.'}</div>
      ) : (
        <div className="detail-grid">
          <Field k="Risk scores" v={scoreLine} />
          <Field k="Indicator" v={[d.indicatorType, d.indicatorName].filter(Boolean).join(' · ') || undefined} />
          {d.action && (
            <div className="field">
              <div className="fk">Recommended action</div>
              <div className="fv chips">
                <span className="chip shodan-vuln">{d.action}</span>
              </div>
            </div>
          )}
          <Field k="Story" v={d.story} />
          <Field k="Impact" v={d.impact} />
          <Field k="Description" v={d.description} />
          <Field k="ASN" v={[d.asn ? `AS${d.asn}` : '', d.asnOwner].filter(Boolean).join(' ') || undefined} />
          <Field k="Organization" v={d.organization && d.organization !== d.asnOwner ? d.organization : undefined} />
          <Field k="Country" v={d.country} />

          {d.threatActors && d.threatActors.length > 0 && (
            <div className="field">
              <div className="fk">Threat actors</div>
              <div className="fv chips">
                {d.threatActors.map((a) => (
                  <button
                    key={a}
                    className="chip chip-btn"
                    onClick={() => runActor(a)}
                    title={`CYFIRMA broad search — ${a}: campaigns, malware, targeted CVEs`}
                  >
                    🔎 {a}
                  </button>
                ))}
              </div>
            </div>
          )}
          <Field k="Campaigns" v={d.campaigns && d.campaigns.length ? d.campaigns.join(', ') : undefined} />
          <Field k="Malware" v={d.malware && d.malware.length ? d.malware.join(', ') : undefined} />

          {rel.length > 0 && (
            <div className="field">
              <div className="fk">Related infra{d.relatedCount ? ` · ${d.relatedCount} linked` : ''}</div>
              <div className="fv">
                {rel.map(([label, vals]) => (
                  <div key={label} className="cyfirma-rel-row">
                    <span className="cyfirma-rel-label">{label}</span>
                    <span className="fv chips">
                      {vals.map((v) => (
                        <span key={v} className="chip mono">
                          {v}
                        </span>
                      ))}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {actor && (
        <div className="cyfirma-actor">
          {actor.loading ? (
            <div className="detail-note">Searching {actor.name}…</div>
          ) : actor.data?.error ? (
            <div className="detail-note">{actor.data.error}</div>
          ) : actor.data ? (
            <>
              <div className="cyfirma-actor-title">Actor · {actor.data.actor}</div>
              <div className="detail-grid">
                <Field k="Aliases" v={actor.data.aliases?.join(', ')} />
                <Field k="Motivation" v={actor.data.motivation} />
                <Field k="Description" v={actor.data.description} />
                <Field k="Campaigns" v={actor.data.campaigns?.join(', ')} />
                <Field k="Malware" v={actor.data.malware?.join(', ')} />
                <Field k="Targeted CVEs" v={actor.data.vulnerabilities?.join(', ')} />
                <Field k="Related IOCs" v={actor.data.relatedIocs?.join(', ')} />
              </div>
            </>
          ) : null}
        </div>
      )}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw CYFIRMA data</summary>
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
        {r.intel471 && r.type !== 'unknown' && (
          <Intel471Section d={r.intel471} value={r.value} type={r.type as EnrichableType} />
        )}
        {r.cyfirma && <CyfirmaSection d={r.cyfirma} />}

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
