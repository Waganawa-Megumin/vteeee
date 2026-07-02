import { useEffect, useRef, useState } from 'react';
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
  NormalizedResult,
  ShodanContext,
  ShodanService,
  SocPrimeQueryResult,
  SocPrimeRuleSearchResult,
  ThreatVisionAdversary,
  ThreatVisionContext,
} from '@vteeee/shared';
import { useStore } from '../state/store';
import { GtiBadge, VerdictBadge } from './Badges';
import { detectionRatio } from '../lib/verdict';
import { resultToText } from '../lib/detailText';
import { RuleCard } from './RuleCard';
import { SIEM_FORMATS } from '../lib/siemFormats';

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

/**
 * TeamT5 ThreatVision block — APT-attribution CTI. Risk + adversary groups (clickable → on-demand
 * APT profile with origin/targeting), malware families (samples), attributes (Malware C2 / Hosting),
 * geo/registrar and related-intel counts.
 */
function ThreatVisionSection({ d }: { d: ThreatVisionContext }) {
  const lookup = useStore((s) => s.threatvisionAdversary);
  const [adv, setAdv] = useState<{ name: string; loading: boolean; data?: ThreatVisionAdversary } | null>(null);

  async function runAdv(name: string) {
    setAdv({ name, loading: true });
    setAdv({ name, loading: false, data: await lookup(name) });
  }

  const risk =
    [d.riskLevel, d.riskScore != null ? `score ${d.riskScore}` : ''].filter(Boolean).join(' · ') || undefined;
  const summary =
    [
      d.relatedReports ? `${d.relatedReports} reports` : '',
      d.relatedSamples ? `${d.relatedSamples} samples` : '',
      d.relatedAdversaries ? `${d.relatedAdversaries} adversaries` : '',
      d.dnsRecords ? `${d.dnsRecords} DNS` : '',
      d.osint ? `${d.osint} OSINT` : '',
    ]
      .filter(Boolean)
      .join(' · ') || undefined;

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🔭
        </span>
        ThreatVision · TeamT5
        {d.found && d.riskLevel && <span className="shodan-when">{d.riskLevel} risk</span>}
      </div>

      {!d.found ? (
        <div className="detail-note">{d.error ?? 'No ThreatVision record for this indicator.'}</div>
      ) : (
        <div className="detail-grid">
          <Field k="Risk" v={risk} />
          <Field k="Risk types" v={d.riskTypes && d.riskTypes.length ? d.riskTypes.join(', ') : undefined} />
          {d.adversaries && d.adversaries.length > 0 && (
            <div className="field">
              <div className="fk">Adversaries</div>
              <div className="fv chips">
                {d.adversaries.map((a) => (
                  <button
                    key={a}
                    className="chip chip-btn"
                    onClick={() => runAdv(a)}
                    title={`ThreatVision APT profile — ${a}: aliases, origin, targets`}
                  >
                    🔎 {a}
                  </button>
                ))}
              </div>
            </div>
          )}
          {d.malwareFamilies && d.malwareFamilies.length > 0 && (
            <div className="field">
              <div className="fk">Malware</div>
              <div className="fv chips">
                {d.malwareFamilies.map((m) => (
                  <span key={m} className="chip shodan-vuln">
                    {m}
                  </span>
                ))}
              </div>
            </div>
          )}
          {d.attributes && d.attributes.length > 0 && (
            <div className="field">
              <div className="fk">Attributes</div>
              <div className="fv chips">
                {d.attributes.map((a) => (
                  <span key={a} className="chip">
                    {a}
                  </span>
                ))}
              </div>
            </div>
          )}
          <Field k="Location" v={[d.city, d.region, d.country].filter(Boolean).join(', ') || undefined} />
          <Field k="Registrar" v={d.registrar} />
          <Field k="SHA-256" v={d.sha256} mono />
          <Field k="MD5" v={d.md5} mono />
          <Field k="Size" v={d.size != null ? `${d.size.toLocaleString()} bytes` : undefined} />
          <Field k="First seen" v={d.firstSeen ? new Date(d.firstSeen).toLocaleDateString() : undefined} />
          {d.hasNetworkActivity != null && <Field k="Network activity" v={d.hasNetworkActivity ? 'yes' : 'no'} />}
          <Field k="Related intel" v={summary} />
          <Field k="Updated" v={d.lastUpdate ? new Date(d.lastUpdate).toLocaleDateString() : undefined} />
        </div>
      )}

      {adv && (
        <div className="cyfirma-actor">
          {adv.loading ? (
            <div className="detail-note">Loading {adv.name}…</div>
          ) : adv.data?.error ? (
            <div className="detail-note">{adv.data.error}</div>
          ) : adv.data ? (
            <>
              <div className="cyfirma-actor-title">APT · {adv.data.name}</div>
              <div className="detail-grid">
                <Field k="Aliases" v={adv.data.aliases?.join(', ')} />
                <Field k="Origin" v={adv.data.originCountries?.join(', ')} />
                <Field k="Targets" v={adv.data.targetedCountries?.join(', ')} />
                <Field k="Industries" v={adv.data.targetedIndustries?.join(', ')} />
                <Field k="Overview" v={adv.data.overview} />
              </div>
            </>
          ) : null}
        </div>
      )}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw ThreatVision data</summary>
          <pre>{JSON.stringify(d.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

/**
 * SOC Prime block — checks the Threat Detection Marketplace for existing/related detections for this
 * indicator. On open it auto-searches by the threat the *other* providers attributed (Intel 471
 * malware family, CYFIRMA/ThreatVision actor/malware); you can also check for rules referencing this
 * exact IOC, or generate a fresh hunting query. The header shows how many rules exist in the Marketplace.
 */
function SocPrimeSection({ r }: { r: NormalizedResult }) {
  const searchRules = useStore((s) => s.socprimeRules);
  const genQuery = useStore((s) => s.socprimeQuery);
  const [siemType, setSiemType] = useState('splunk');
  const [rules, setRules] = useState<{
    loading: boolean;
    mode: 'threat' | 'ioc';
    basis: string;
    data?: SocPrimeRuleSearchResult;
  } | null>(null);
  const [query, setQuery] = useState<{ loading: boolean; data?: SocPrimeQueryResult } | null>(null);
  const [copied, setCopied] = useState(false);

  // Best available threat context from the other providers (malware family, then actor).
  const tool = r.intel471?.malwareFamily ?? r.cyfirma?.malware?.[0] ?? r.threatvision?.malwareFamilies?.[0];
  const actor = r.cyfirma?.threatActors?.[0] ?? r.threatvision?.adversaries?.[0];
  const threat = tool ?? actor ?? r.file?.threatLabel;

  async function searchBy(mode: 'threat' | 'ioc', siem = siemType) {
    const basis = mode === 'ioc' ? r.value : (threat ?? r.value);
    setRules({ loading: true, mode, basis });
    const params =
      mode === 'threat' && (tool || actor)
        ? { siemType: siem, tool, actor, pageSize: 5 }
        : mode === 'ioc'
          ? // Search the rule body specifically — "is this exact IOC already covered by a rule?"
            { siemType: siem, query: `sigma.text: "${r.value}"`, pageSize: 5 }
          : { siemType: siem, query: `"${basis}"`, pageSize: 5 };
    setRules({ loading: false, mode, basis, data: await searchRules(params) });
  }

  // Proactively check the Marketplace when opening a notable indicator.
  useEffect(() => {
    if (r.verdict === 'malicious' || r.verdict === 'suspicious') void searchBy('threat');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [r.value]);

  async function runQuery() {
    setQuery({ loading: true });
    setQuery({ loading: false, data: await genQuery(r.value, { siemType }) });
  }
  const q = query?.data?.queries?.join('\n\n') ?? '';
  async function copyQuery() {
    if (!q) return;
    try {
      await navigator.clipboard.writeText(q);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked */
    }
  }

  const list = rules?.data?.rules ?? [];
  const total = rules?.data && !rules.data.error ? (rules.data.total ?? list.length) : undefined;

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🛡
        </span>
        SOC Prime · TDM
        {rules?.loading ? (
          <span className="shodan-when">checking Marketplace…</span>
        ) : total != null ? (
          <span className="shodan-when">{total.toLocaleString()} in Marketplace</span>
        ) : (
          <span className="shodan-when">detection content</span>
        )}
      </div>

      <div className="soc-controls">
        <select
          className="soc-siem"
          value={siemType}
          onChange={(e) => {
            setSiemType(e.target.value);
            if (rules) void searchBy(rules.mode, e.target.value); // re-translate to the new format
          }}
        >
          {SIEM_FORMATS.map((f) => (
            <option key={f.value} value={f.value}>
              {f.label}
            </option>
          ))}
        </select>
        <button className="btn btn-ghost btn-sm" onClick={() => searchBy('threat')} disabled={rules?.loading}>
          {threat ? `Related to “${threat}”` : 'Related detections'}
        </button>
        <button className="btn btn-ghost btn-sm" onClick={() => searchBy('ioc')} disabled={rules?.loading}>
          This exact IOC
        </button>
        <button className="btn btn-ghost btn-sm" onClick={runQuery} disabled={query?.loading}>
          {query?.loading ? 'Generating…' : 'Create hunting query'}
        </button>
      </div>

      {rules?.data?.error && <div className="detail-note">{rules.data.error}</div>}
      {rules?.data && !rules.data.error && list.length === 0 && (
        <div className="detail-note">
          {rules.mode === 'ioc'
            ? 'No existing Marketplace rule references this exact IOC.'
            : `No related detections in the Marketplace for “${rules.basis}”.`}
        </div>
      )}
      {list.length > 0 && (
        <>
          <div className="hint">
            {rules?.mode === 'ioc'
              ? 'Existing Marketplace rules referencing this IOC:'
              : `Related detections in the SOC Prime Marketplace for “${rules?.basis}”:`}
          </div>
          <div className="rule-list">
            {list.map((rl, i) => (
              <RuleCard key={rl.id ?? i} r={rl} />
            ))}
          </div>
        </>
      )}

      {query?.data?.error && <div className="detail-note">{query.data.error}</div>}
      {q && (
        <>
          <div className="i471-actions">
            <span className="fk">{siemType} query (generated)</span>
            <button className="btn btn-sm btn-ghost" onClick={copyQuery}>
              {copied ? '✓ Copied' : 'Copy'}
            </button>
          </div>
          <textarea className="siem-output mono" readOnly rows={8} value={q} />
        </>
      )}
    </div>
  );
}

export function DetailPanel() {
  const selected = useStore((s) => s.selected);
  const results = useStore((s) => s.results);
  const select = useStore((s) => s.select);
  const socprimeOn = useStore((s) => s.mode === 'demo' || Boolean(s.health?.socprime));
  const panelRef = useRef<HTMLElement>(null);
  const [copied, setCopied] = useState<'text' | 'image' | 'err' | null>(null);
  const [busy, setBusy] = useState(false);
  const r = selected ? results[selected] : null;

  function flash(kind: 'text' | 'image' | 'err'): void {
    setCopied(kind);
    setTimeout(() => setCopied((c) => (c === kind ? null : c)), 1600);
  }

  async function copyText(): Promise<void> {
    if (!r) return;
    try {
      await navigator.clipboard.writeText(resultToText(r));
      flash('text');
    } catch {
      flash('err');
    }
  }

  async function copyImage(): Promise<void> {
    const node = panelRef.current;
    if (!node || busy) return;
    setBusy(true);
    try {
      const { toBlob } = await import('html-to-image');
      const bg = getComputedStyle(node).backgroundColor || '#2b3f37';
      const blob = await toBlob(node, {
        backgroundColor: bg,
        pixelRatio: 2,
        // Capture the full scroll height, not just the visible viewport of the panel.
        height: node.scrollHeight,
        style: { maxHeight: 'none', overflow: 'visible' },
        // Skip the action buttons (and anything else opted out) in the image.
        filter: (el) => !(el instanceof HTMLElement && el.dataset.noimage === 'true'),
      });
      if (!blob) throw new Error('no blob');
      await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
      flash('image');
    } catch {
      flash('err');
    } finally {
      setBusy(false);
    }
  }

  if (!r) return null;

  return (
    <div className="detail-overlay" onClick={() => select(null)}>
      <aside className="detail-panel" ref={panelRef} onClick={(e) => e.stopPropagation()}>
        <div className="detail-head">
          <div>
            <div className="detail-title mono">{r.value}</div>
            <div className="detail-sub">
              <span className={`badge type type-${r.type}`}>{r.type}</span>{' '}
              <VerdictBadge verdict={r.verdict} status={r.status} /> <GtiBadge r={r} />
            </div>
          </div>
          <div className="detail-actions" data-noimage="true">
            <button
              className="btn btn-sm btn-ghost"
              onClick={copyText}
              title="Copy the whole detail as text"
            >
              {copied === 'text' ? '✓ Copied' : copied === 'err' ? '⚠ Failed' : 'Copy text'}
            </button>
            <button
              className="btn btn-sm btn-ghost"
              onClick={copyImage}
              disabled={busy}
              title="Copy the whole detail as an image"
            >
              {busy ? '…' : copied === 'image' ? '✓ Copied' : 'Copy image'}
            </button>
            <button className="btn btn-ghost" onClick={() => select(null)} title="Close">
              ✕
            </button>
          </div>
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

        {/* VT call-to-action stays with the VirusTotal data at the top — the enrichment
            sections below can grow long, so the button must not sink to the bottom. */}
        <a className="btn btn-primary detail-vt" href={r.links.gui} target="_blank" rel="noreferrer">
          Open in VirusTotal ↗
        </a>

        {r.shodan && <ShodanSection s={r.shodan} ip={r.value} />}
        {r.domaintools && <DomainToolsSection d={r.domaintools} />}
        {r.dnslytics && <DnslyticsSection d={r.dnslytics} />}
        {r.intel471 && r.type !== 'unknown' && (
          <Intel471Section d={r.intel471} value={r.value} type={r.type as EnrichableType} />
        )}
        {r.cyfirma && <CyfirmaSection d={r.cyfirma} />}
        {r.threatvision && <ThreatVisionSection d={r.threatvision} />}
        {socprimeOn && r.type !== 'unknown' && <SocPrimeSection key={r.value} r={r} />}

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
