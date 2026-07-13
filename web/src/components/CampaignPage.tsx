import { useEffect, useMemo, useRef, useState } from 'react';
import { extractIndicators, type EnrichableType } from '@vteeee/shared';
import { useStore, type CampaignIoc, type IocSide, type TlpLevel } from '../state/store';
import { TLP_LEVELS, ADMIRALTY_RELIABILITY, ADMIRALTY_CREDIBILITY } from '../state/campaigns';
import { VerdictBadge } from './Badges';
import { Spark } from './Spark';
import { CountryChoropleth } from './CountryChoropleth';
import { MarkdownLite } from './MarkdownLite';
import { abuseOf, countryOf, cvesOf, detOf, diffParts, portsOf, rfOf } from '../lib/enrichTrend';

const UNGROUPED = '__ungrouped__';

/** Threat-relevance score so the most dangerous / info-rich IOCs sort to the top within a group. */
function threatScore(i: CampaignIoc): number {
  const r = i.result;
  if (!r) return -1;
  const sev = r.verdict === 'malicious' ? 1000 : r.verdict === 'suspicious' ? 400 : r.verdict === 'harmless' ? -50 : 0;
  return (
    sev + detOf(r) * 10 + (abuseOf(r) ?? 0) * 3 + (rfOf(r) ?? 0) * 2 + cvesOf(r) * 60 + portsOf(r) + (i.history?.length ?? 0) * 2
  );
}
const byThreat = (list: CampaignIoc[]) => [...list].sort((a, b) => threatScore(b) - threatScore(a));

const WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888];
/** OSINT exposure/attack-surface score for TARGET assets — ports, CVEs, web-facing, hostnames. */
function exposureScore(i: CampaignIoc): number {
  const r = i.result;
  if (!r) return -1;
  const ports = r.shodan?.ports ?? [];
  const web = ports.some((p) => WEB_PORTS.includes(p)) ? 120 : 0;
  return (
    cvesOf(r) * 50 + ports.length * 6 + web + (r.shodan?.hostnames?.length ?? 0) * 2 + (i.history?.length ?? 0)
  );
}
const byExposure = (list: CampaignIoc[]) => [...list].sort((a, b) => exposureScore(b) - exposureScore(a));

function tlpClass(t: TlpLevel): string {
  return `tlp-${t.toLowerCase().replace('+', '-')}`;
}

function Tile({ n, label, tone }: { n: number; label: string; tone?: 'bad' | 'warn' }) {
  return (
    <div className={`mon-stat${tone ? ` ${tone}` : ''}`}>
      <b>{n}</b>
      <span>{label}</span>
    </div>
  );
}
function Bars({ title, rows, hrefFor }: { title: string; rows: [string, number][]; hrefFor?: (k: string) => string }) {
  const max = rows[0]?.[1] ?? 1;
  return (
    <div className="mon-bars">
      <div className="mon-bars-title">{title}</div>
      {rows.length === 0 ? (
        <div className="hint">—</div>
      ) : (
        rows.map(([k, n]) => (
          <div key={k} className="mon-bar-row">
            <span className="mon-bar-label mono">
              {hrefFor ? (
                <a href={hrefFor(k)} target="_blank" rel="noreferrer">
                  {k}
                </a>
              ) : (
                k
              )}
            </span>
            <span className="mon-bar-track">
              <span className="mon-bar-fill" style={{ width: `${Math.max(6, (n / max) * 100)}%` }} />
            </span>
            <span className="mon-bar-n">{n}</span>
          </div>
        ))
      )}
    </div>
  );
}

/** Campaign analytics, scoped so Attack (threat) and Target (OSINT exposure) never mix — the map too. */
function CampaignDashboard({ iocs, onOpen }: { iocs: CampaignIoc[]; onOpen?: (v: string) => void }) {
  const attackN = iocs.filter((i) => (i.side ?? 'attack') === 'attack').length;
  const targetN = iocs.filter((i) => i.side === 'target').length;
  const [scope, setScope] = useState<'attack' | 'target' | 'all'>(() =>
    attackN > 0 ? 'attack' : targetN > 0 ? 'target' : 'all',
  );
  const [mapGroup, setMapGroup] = useState('');
  const scoped = useMemo(
    () => (scope === 'all' ? iocs : iocs.filter((i) => (i.side ?? 'attack') === scope)),
    [iocs, scope],
  );

  const map = useMemo(() => {
    const names = [...new Set(scoped.map((i) => i.group).filter((g): g is string => !!g))].sort((a, b) =>
      a.localeCompare(b),
    );
    const hasUngrouped = scoped.some((i) => !i.group);
    const entries =
      !mapGroup ? scoped : mapGroup === UNGROUPED ? scoped.filter((i) => !i.group) : scoped.filter((i) => i.group === mapGroup);
    const counts: Record<string, number> = {};
    const seen = new Set<string>();
    for (const i of entries) {
      const cc = i.result ? countryOf(i.result) : '';
      if (cc) {
        counts[cc] = (counts[cc] ?? 0) + 1;
        seen.add(cc);
      }
    }
    const countryRows = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10) as [string, number][];
    return { names, hasUngrouped, n: entries.length, countryN: seen.size, counts, countryRows };
  }, [scoped, mapGroup]);

  const d = useMemo(() => {
    const byType = new Map<string, number>();
    const byCve = new Map<string, number>();
    const byPort = new Map<number, number>();
    let hostsCve = 0;
    let hostsPorts = 0;
    let anon = 0;
    for (const i of scoped) {
      byType.set(i.type, (byType.get(i.type) ?? 0) + 1);
      const r = i.result;
      const v = r?.shodan?.vulns;
      if (v?.length) {
        hostsCve++;
        for (const c of v) byCve.set(c, (byCve.get(c) ?? 0) + 1);
      }
      const ports = r?.shodan?.ports ?? [];
      if (ports.length) {
        hostsPorts++;
        for (const p of ports) byPort.set(p, (byPort.get(p) ?? 0) + 1);
      }
      if (r?.maxmind?.anonymizerType?.length) anon++;
    }
    const recent: { value: string; at: number; changes: string[] }[] = [];
    for (const i of scoped) {
      const h = i.history?.length ? [...i.history].sort((a, b) => a.at - b.at) : [];
      if (h.length < 2) continue;
      const changes = diffParts(h[h.length - 1].result, h[h.length - 2].result);
      if (changes.length) recent.push({ value: i.value, at: h[h.length - 1].at, changes });
    }
    recent.sort((a, b) => b.at - a.at);
    return {
      total: scoped.length,
      withIntel: scoped.filter((i) => i.result).length,
      mal: scoped.filter((i) => i.result?.verdict === 'malicious').length,
      sus: scoped.filter((i) => i.result?.verdict === 'suspicious').length,
      highAbuse: scoped.filter((i) => (i.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
      auto: scoped.filter((i) => i.autoEnrich).length,
      byType: [...byType.entries()].sort((a, b) => b[1] - a[1]) as [string, number][],
      cves: [...byCve.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10) as [string, number][],
      ports: [...byPort.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([p, n]) => [String(p), n] as [string, number]),
      distinctCves: byCve.size,
      hostsCve,
      hostsPorts,
      anon,
      recent: recent.slice(0, 8),
    };
  }, [scoped]);

  const scopeBar = (
    <div className="cp-scope" role="tablist" aria-label="dashboard scope">
      <button
        role="tab"
        aria-selected={scope === 'attack'}
        className={`cp-scope-btn${scope === 'attack' ? ' active' : ''}`}
        onClick={() => {
          setScope('attack');
          setMapGroup('');
        }}
      >
        🗡 Attack ({attackN})
      </button>
      <button
        role="tab"
        aria-selected={scope === 'target'}
        className={`cp-scope-btn${scope === 'target' ? ' active' : ''}`}
        onClick={() => {
          setScope('target');
          setMapGroup('');
        }}
      >
        🎯 Target ({targetN})
      </button>
      <button
        role="tab"
        aria-selected={scope === 'all'}
        className={`cp-scope-btn${scope === 'all' ? ' active' : ''}`}
        onClick={() => {
          setScope('all');
          setMapGroup('');
        }}
      >
        All ({iocs.length})
      </button>
      <span className="cp-scope-note">
        {scope === 'attack'
          ? '攻撃側インフラ — 脅威の観点'
          : scope === 'target'
            ? '標的/被害側 — OSINT 露出・リスクの観点（Shodan/MaxMind）'
            : '攻撃＋標的の合算'}
      </span>
    </div>
  );

  if (scoped.length === 0) {
    return (
      <>
        {scopeBar}
        <div className="hint cp-scope-empty">
          このスコープに IoC はありません。
          {scope === 'target' ? 'Target Info タブで登録、または行の「→ Target」で移動できます。' : ''}
        </div>
      </>
    );
  }

  const target = scope === 'target';
  return (
    <>
      {scopeBar}
      <div className="mon-stats" role="group" aria-label="campaign overview">
        <Tile n={d.total} label={target ? 'assets' : 'IOCs'} />
        <Tile n={d.withIntel} label="with intel" />
        {target ? (
          <>
            {d.hostsPorts > 0 && <Tile n={d.hostsPorts} label="exposed hosts" tone="warn" />}
            {d.hostsCve > 0 && <Tile n={d.hostsCve} label="hosts w/ CVEs" tone="bad" />}
            {d.distinctCves > 0 && <Tile n={d.distinctCves} label="distinct CVEs" />}
            {d.anon > 0 && <Tile n={d.anon} label="anonymized" />}
          </>
        ) : (
          <>
            {d.mal > 0 && <Tile n={d.mal} label="malicious" tone="bad" />}
            {d.sus > 0 && <Tile n={d.sus} label="suspicious" tone="warn" />}
            {d.highAbuse > 0 && <Tile n={d.highAbuse} label="abuse ≥75" tone="bad" />}
            {d.distinctCves > 0 && <Tile n={d.distinctCves} label="distinct CVEs" />}
          </>
        )}
        <Tile n={d.auto} label="⚡ auto" />
      </div>
      <div className="mon-dash mon-dash-nomap">
        <Bars title="By IOC type" rows={d.byType} />
        <Bars
          title={target ? '露出脆弱性 Top CVEs' : 'Top CVEs'}
          rows={d.cves}
          hrefFor={(cve) => `https://nvd.nist.gov/vuln/detail/${cve}`}
        />
        {target && (
          <Bars
            title="露出ポート Top"
            rows={d.ports}
            hrefFor={(p) => `https://www.shodan.io/search?query=port%3A${p}`}
          />
        )}
      </div>
      <div className="mon-geo">
        <div className="mon-choro-head">
          <div className="mon-bars-title">
            {target ? '標的の所在地' : scope === 'attack' ? '攻撃インフラの所在地' : '国別'} — ヒートマップ（多いほど濃い）
          </div>
          {map.names.length > 0 && (
            <select
              className="filter mon-choro-group"
              value={mapGroup}
              onChange={(e) => setMapGroup(e.target.value)}
              aria-label="Group for the country stats + heatmap"
            >
              <option value="">All groups</option>
              {map.names.map((g) => (
                <option key={g} value={g}>
                  {g}
                </option>
              ))}
              {map.hasUngrouped && <option value={UNGROUPED}>Ungrouped</option>}
            </select>
          )}
          <span className="mon-choro-count">
            {map.n} {target ? 'asset' : 'IoC'}
            {map.n === 1 ? '' : 's'} · {map.countryN} countries
          </span>
        </div>
        <div className="mon-geo-body">
          <div className="mon-geo-stats">
            <Bars title="By country" rows={map.countryRows} />
          </div>
          <div className="mon-geo-map">
            <CountryChoropleth counts={map.counts} height={250} />
          </div>
        </div>
      </div>
      {d.recent.length > 0 && (
        <div className="cp-recent">
          <div className="mon-bars-title">Recent changes（直近のエンリッチ変化）</div>
          {d.recent.map((r) => (
            <div key={r.value} className="cp-recent-row">
              <button className="cp-recent-ioc mono" onClick={() => onOpen?.(r.value)} title="Open detail">
                {r.value}
              </button>
              <span className="cp-recent-when">{new Date(r.at).toLocaleDateString()}</span>
              <span className="hist-diff changed">▲ {r.changes.join(' · ')}</span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

type Tab = 'dashboard' | 'attack' | 'target' | 'assessment';

export function CampaignPage() {
  const id = useStore((s) => s.campaignId);
  const campaign = useStore((s) => (id ? s.campaigns[id] : undefined));
  const openCampaigns = useStore((s) => s.openCampaigns);
  const addIocs = useStore((s) => s.addCampaignIocs);
  const setGroup = useStore((s) => s.setCampaignIocGroup);
  const setSide = useStore((s) => s.setCampaignIocSide);
  const setTlp = useStore((s) => s.setCampaignTlp);
  const setAdmiralty = useStore((s) => s.setCampaignAdmiralty);
  const reorderGroup = useStore((s) => s.reorderCampaignGroup);
  const removeIocs = useStore((s) => s.removeCampaignIocs);
  const reEnrich = useStore((s) => s.reEnrichCampaignIoc);
  const reEnrichIocs = useStore((s) => s.reEnrichCampaignIocs);
  const setAuto = useStore((s) => s.setCampaignIocAuto);
  const rename = useStore((s) => s.renameCampaign);
  const removeCampaign = useStore((s) => s.removeCampaign);
  const showResult = useStore((s) => s.showResult);
  const summarize = useStore((s) => s.summarizeCampaign);
  const assess = useStore((s) => s.assessCampaign);
  const refreshCampaigns = useStore((s) => s.refreshCampaigns);
  const [text, setText] = useState('');
  const [groupInput, setGroupInput] = useState('');
  const [tab, setTab] = useState<Tab>('dashboard');
  const [summarizing, setSummarizing] = useState(false);
  const [assessing, setAssessing] = useState(false);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [admHelp, setAdmHelp] = useState(false);

  async function bulkReEnrich(values: string[]) {
    if (!values.length || bulkBusy) return;
    setBulkBusy(true);
    try {
      await reEnrichIocs(cid, values);
    } finally {
      setBulkBusy(false);
    }
  }
  const autoSummarized = useRef<string | null>(null);

  const iocCount = id ? Object.keys(campaign?.iocs ?? {}).length : 0;
  const hasSummary = Boolean(campaign?.summary);
  async function onSummarize() {
    if (!id) return;
    setSummarizing(true);
    try {
      await summarize(id);
    } finally {
      setSummarizing(false);
    }
  }
  useEffect(() => {
    if (!id || !iocCount || hasSummary || summarizing) return;
    if (autoSummarized.current === id) return;
    autoSummarized.current = id;
    void onSummarize();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, iocCount, hasSummary]);

  // Pull the latest shared campaigns when opening one, so cross-browser edits are reflected.
  useEffect(() => {
    if (id) void refreshCampaigns();
  }, [id, refreshCampaigns]);

  if (!id || !campaign) {
    return (
      <section className="panel monitor-page">
        <div className="panel-head">
          <button className="btn btn-sm" onClick={openCampaigns}>
            ← Back
          </button>
          <h2>Campaign</h2>
        </div>
        <div className="empty-state">キャンペーンが見つかりません。CP-Mon に戻ってください。</div>
      </section>
    );
  }

  const cid: string = id;
  const tlp: TlpLevel = campaign.tlp ?? 'AMBER';
  const admRel = campaign.admiraltyReliability ?? '';
  const admCred = campaign.admiraltyCredibility ?? '';
  const iocs = Object.values(campaign.iocs).sort((a, b) => b.updatedAt - a.updatedAt);
  const attackIocs = iocs.filter((i) => (i.side ?? 'attack') === 'attack');
  const targetIocs = iocs.filter((i) => i.side === 'target');
  const groupNames = [...new Set(iocs.map((i) => i.group).filter((g): g is string => !!g))];

  /** Order a side's groups by the campaign's saved order (fallback alphabetical); threat-sort within. */
  function bucketsFor(list: CampaignIoc[], side: IocSide) {
    // attack → threat-first; target → OSINT exposure-first (most exposed/at-risk on top).
    const sort = side === 'target' ? byExposure : byThreat;
    const order = campaign?.groupOrder ?? [];
    const names = [...new Set(list.map((i) => i.group).filter((g): g is string => !!g))].sort((a, b) => {
      const ia = order.indexOf(a);
      const ib = order.indexOf(b);
      if (ia >= 0 && ib >= 0) return ia - ib;
      if (ia >= 0) return -1;
      if (ib >= 0) return 1;
      return a.localeCompare(b);
    });
    const bs: { key: string; name: string | null; items: CampaignIoc[] }[] = names.map((g) => ({
      key: g,
      name: g,
      items: sort(list.filter((i) => i.group === g)),
    }));
    const ung = list.filter((i) => !i.group);
    if (ung.length) bs.push({ key: UNGROUPED, name: null, items: sort(ung) });
    return { bs, orderedNames: names };
  }

  function onAdd(side: IocSide) {
    const { indicators } = extractIndicators(text);
    const add = indicators
      .filter((i) => i.type !== 'unknown' && !i.private)
      .map((i) => ({ value: i.value, type: i.type as EnrichableType }));
    if (!add.length) return;
    void addIocs(cid, add, groupInput, side);
    setText('');
    setGroupInput(''); // reset to "new group" default so the next batch doesn't inherit the last name
  }

  function renameGroup(name: string) {
    const nn = window.prompt(`グループ名を変更 “${name}”:`, name);
    if (nn == null) return;
    const vals = iocs.filter((i) => i.group === name).map((i) => i.value);
    void setGroup(cid, vals, nn.trim() || undefined);
  }

  function renderIoc(i: CampaignIoc, side: IocSide) {
    const r = i.result;
    const histAsc = i.history?.length ? [...i.history].sort((a, b) => a.at - b.at) : [];
    const trendChanges =
      histAsc.length >= 2 ? diffParts(histAsc[histAsc.length - 1].result, histAsc[histAsc.length - 2].result) : [];
    const sparks =
      histAsc.length >= 2
        ? (
            [
              ['det', detOf],
              ['abuse', abuseOf],
              ['RF', rfOf],
              ['ports', portsOf],
              ['CVE', cvesOf],
            ] as const
          )
            .map(([k, f]) => ({ k, series: histAsc.map((s) => f(s.result)) }))
            .filter(({ series }) => {
              const nn = series.map((v) => v ?? 0);
              return Math.max(...nn) !== Math.min(...nn);
            })
        : [];
    return (
      <li key={i.value} className="monitor-row">
        <div className="mon-main">
          <div className="mon-top">
            <span className="mon-ip mono">{i.value}</span>
            <span className={`badge type type-${i.type}`}>{i.type}</span>
            {i.enriching && <span className="mon-badge">enriching…</span>}
            <span className="mon-when">
              added {new Date(i.addedAt).toLocaleDateString()}
              {i.addedBy ? ` · ${i.addedBy}` : ''}
            </span>
            <span className="mon-row-grouping">
              <span className="mon-row-group-label">group:</span>
              <select
                className="mon-row-group"
                value={i.group ?? ''}
                onChange={(ev) => {
                  const sel = ev.currentTarget;
                  const v = sel.value;
                  if (v === '__new__') {
                    const name = window.prompt(`New group for ${i.value}:`, '');
                    if (name != null) void setGroup(cid, [i.value], name);
                  } else {
                    void setGroup(cid, [i.value], v || undefined);
                  }
                  sel.value = i.group ?? '';
                }}
                title={i.group ? `Group: ${i.group}` : 'Put this IOC in a group'}
              >
                <option value="">— none —</option>
                {groupNames.map((g) => (
                  <option key={g} value={g}>
                    {g}
                  </option>
                ))}
                <option value="__new__">＋ New group…</option>
              </select>
            </span>
          </div>
          {r ? (
            side === 'target' ? (
              <span className="mon-summary">
                {/* Target = OSINT exposure/attack-surface (Shodan + MaxMind), not a threat verdict. */}
                {(() => {
                  const geo = [r.maxmind?.city, countryOf(r)].filter(Boolean).join(', ');
                  const net =
                    r.maxmind?.asn != null
                      ? `AS${r.maxmind.asn}${r.maxmind.organization ? ` ${r.maxmind.organization}` : ''}`
                      : (r.shodan?.org ?? r.ip?.asOwner ?? '');
                  return (
                    <>
                      {geo && <span className="mon-chip">📍 {geo}</span>}
                      {net && <span className="mon-chip" title="ASN / org">{net}</span>}
                      {r.maxmind?.isp && r.maxmind.isp !== r.maxmind.organization && (
                        <span className="mon-chip">ISP {r.maxmind.isp}</span>
                      )}
                    </>
                  );
                })()}
                {portsOf(r) > 0 && (
                  <span className="mon-chip mono sev-med" title={(r.shodan?.ports ?? []).join(', ')}>
                    {portsOf(r)} ports{r.shodan?.ports?.length ? `: ${r.shodan.ports.slice(0, 6).join(',')}${r.shodan.ports.length > 6 ? '…' : ''}` : ''}
                  </span>
                )}
                {cvesOf(r) > 0 && <span className="mon-chip sev-high">⚠ {cvesOf(r)} CVE 露出</span>}
                {r.shodan?.os && <span className="mon-chip">OS {r.shodan.os}</span>}
                {r.shodan?.hostnames?.length ? <span className="mon-chip mono">{r.shodan.hostnames[0]}</span> : null}
                {r.shodan?.tags?.length ? <span className="mon-chip">{r.shodan.tags.slice(0, 3).join(' · ')}</span> : null}
                {r.maxmind?.anonymizerType?.length ? (
                  <span className="mon-chip sev-med">{r.maxmind.anonymizerType.join('/')}</span>
                ) : null}
                {abuseOf(r) != null && abuseOf(r)! > 0 && <span className="mon-chip">abuse {abuseOf(r)}</span>}
              </span>
            ) : (
              <span className="mon-summary">
                <VerdictBadge verdict={r.verdict} status={r.status} />
                {r.detection && (
                  <span className="mon-chip">
                    det {detOf(r)}/{r.detection.total}
                  </span>
                )}
                {abuseOf(r) != null && <span className="mon-chip">abuse {abuseOf(r)}</span>}
                {rfOf(r) != null && <span className="mon-chip">RF {rfOf(r)}</span>}
                {portsOf(r) > 0 && <span className="mon-chip mono">{portsOf(r)} ports</span>}
                {cvesOf(r) > 0 && <span className="mon-chip sev-high">{cvesOf(r)} CVE</span>}
                {countryOf(r) && <span className="mon-chip">{countryOf(r)}</span>}
              </span>
            )
          ) : (
            <span className="mon-nointel">no enrichment yet — press “Re-enrich”</span>
          )}
          {histAsc.length >= 2 && (
            <div className="mon-trend">
              {sparks.length > 0 && (
                <span className="mon-sparks">
                  {sparks.map(({ k, series }) => (
                    <span key={k} className="mon-spark-item" title={`${k} · ${series.length} pts`}>
                      <span className="mon-spark-label">{k}</span>
                      <Spark className="mon-spark" values={series} w={46} h={16} />
                    </span>
                  ))}
                </span>
              )}
              {trendChanges.length > 0 && <span className="mon-trend-diff">↗ 前回比: {trendChanges.join(' · ')}</span>}
            </div>
          )}
          {i.error && <div className="mon-err">{i.error}</div>}
        </div>
        <div className="mon-actions">
          <button
            className="btn btn-sm"
            disabled={!r}
            onClick={() => r && showResult(r)}
            title={side === 'target' ? '詳細を開く（urlscan 魚拓・Live ports 等の露出調査）' : 'Open detail'}
          >
            {side === 'target' ? '🎣 詳細/魚拓' : 'Open'}
          </button>
          <button className="btn btn-sm" disabled={i.enriching} onClick={() => void reEnrich(cid, i.value)}>
            {i.enriching ? 'Enriching…' : 'Re-enrich'}
          </button>
          <button
            className={`btn btn-sm${i.autoEnrich ? ' btn-primary' : ''}`}
            onClick={() => void setAuto(cid, [i.value], !i.autoEnrich)}
            title="自動エンリッチ（サーバ側で毎日／開いている間はクライアントでも）"
          >
            ⚡ Auto{i.autoEnrich ? ' ✓' : ''}
          </button>
          <button
            className="btn btn-sm"
            onClick={() => void setSide(cid, [i.value], side === 'attack' ? 'target' : 'attack')}
            title={side === 'attack' ? 'Target Info へ移動（標的側）' : 'Attack Info へ移動（攻撃側）'}
          >
            {side === 'attack' ? '→ 🎯 Target' : '→ 🗡 Attack'}
          </button>
          {r?.links?.gui && (
            <a className="btn btn-sm" href={r.links.gui} target="_blank" rel="noreferrer">
              VT ↗
            </a>
          )}
          <button className="btn btn-sm btn-danger" onClick={() => void removeIocs(cid, [i.value])}>
            Remove
          </button>
        </div>
      </li>
    );
  }

  /** One IOC-management tab (Attack or Target): add box + threat-sorted, reorderable groups. */
  function SideView({ side }: { side: IocSide }) {
    const list = side === 'attack' ? attackIocs : targetIocs;
    const { bs, orderedNames } = bucketsFor(list, side);
    const sideLabel = side === 'attack' ? 'Attack' : 'Target';
    const unEnriched = list.filter((i) => !i.result);
    const enrichingN = list.filter((i) => i.enriching).length;
    return (
      <>
        <p className="hint mon-intro">
          {side === 'attack' ? (
            <>
              攻撃側インフラ（C2・マルウェア・フィッシング等）の IoC。任意の <b>Group 名</b>で整理でき、
              <b>各グループ内は脅威度順（悪性度・検知数・CVE等）</b>に自動整列します。
            </>
          ) : (
            <>
              標的/被害側（狙われた資産）の IoC。脅威判定より <b>OSINT 露出・リスク</b>の観点で、
              <b>Shodan（開放ポート・サービス・CVE・OS）＋ MaxMind（所在地・ASN/ISP・匿名化）</b>を表示。
              <b>各グループ内は露出度順</b>に整列し、行の <b>🎣 詳細/魚拓</b> で urlscan 魚拓・Live ports を確認できます。
            </>
          )}{' '}
          登録IoCは<b>サーバ側で毎日自動エンリッチ</b>・<b>履歴ごとチーム共有</b>されます。
        </p>

        <div className="cp-add">
          <div className="cp-add-group">
            <label className="cp-add-group-label" htmlFor={`cp-grp-${side}`}>
              Group（未入力＝グループなし・追加後は自動でクリア）
            </label>
            <div className="cp-add-group-row">
              <input
                id={`cp-grp-${side}`}
                className="filter cp-group-field"
                placeholder="新規グループ名を入力…"
                value={groupInput}
                onChange={(e) => setGroupInput(e.target.value)}
              />
              {groupNames.length > 0 && (
                <select
                  className="filter cp-group-pick"
                  value=""
                  onChange={(e) => {
                    if (e.target.value) setGroupInput(e.target.value);
                  }}
                  aria-label="既存グループから選択"
                  title="既存のグループから選ぶ（入力欄に反映されます）"
                >
                  <option value="">既存から選択…</option>
                  {groupNames.map((g) => (
                    <option key={g} value={g}>
                      {g}
                    </option>
                  ))}
                </select>
              )}
              {groupInput && (
                <button
                  className="btn btn-sm btn-ghost cp-group-clear"
                  onClick={() => setGroupInput('')}
                  title="グループ名をクリア"
                  aria-label="Clear group name"
                >
                  ✕
                </button>
              )}
            </div>
          </div>
          <textarea
            className="cp-add-text mono"
            placeholder="IoC を貼り付け（改行/カンマ区切り可・defang対応）: 1[.]1[.]1[.]1  hxxp://evil[.]com  44d88612fea8a8f36de82e1278abb02f …"
            rows={2}
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <button className="btn btn-primary" onClick={() => onAdd(side)} disabled={!text.trim()}>
            ＋ Add to {sideLabel}
          </button>
        </div>

        {list.length > 0 && (
          <div className="cp-side-toolbar">
            <button
              className="btn btn-sm"
              disabled={bulkBusy}
              onClick={() => void bulkReEnrich(list.map((i) => i.value))}
              title="この側の全 IoC を順次 Re-enrich（レート制限に配慮して1件ずつ）"
            >
              {bulkBusy ? `⟳ Re-enrich 中…${enrichingN ? ` (${enrichingN})` : ''}` : `⟳ Re-enrich all (${list.length})`}
            </button>
            {unEnriched.length > 0 && (
              <button
                className="btn btn-sm btn-primary"
                disabled={bulkBusy}
                onClick={() => void bulkReEnrich(unEnriched.map((i) => i.value))}
                title="エンリッチ結果が無い IoC だけを一括で取得"
              >
                未エンリッチのみ ({unEnriched.length})
              </button>
            )}
            <button
              className="btn btn-sm"
              disabled={bulkBusy}
              onClick={() => void setAuto(cid, list.map((i) => i.value), true)}
              title="この側の全 IoC の自動エンリッチを ON"
            >
              ⚡ Auto on all
            </button>
            {unEnriched.length > 0 && !bulkBusy && (
              <span className="cp-side-toolbar-note">
                ⚠ {unEnriched.length} 件が未エンリッチ（追加時の失敗/レート制限の可能性）。上のボタンで再取得できます。
              </span>
            )}
          </div>
        )}

        {list.length === 0 ? (
          <div className="empty-state">
            まだ {sideLabel} 側の IoC がありません。上の欄に貼り付けて <b>Add to {sideLabel}</b> で登録してください。
          </div>
        ) : (
          <div className="mon-groups">
            {bs.map((b) => {
              const oi = b.name ? orderedNames.indexOf(b.name) : -1;
              return (
                <div className="mon-group" key={b.key}>
                  <div className="mon-group-head">
                    {b.name ? (
                      <>
                        <button
                          className="mon-group-name mon-group-name-btn"
                          onClick={() => renameGroup(b.name!)}
                          title="クリックで名称変更"
                        >
                          {b.name} <span className="mon-group-edit" aria-hidden>✎</span>
                        </button>
                        <span className="cp-group-reorder">
                          <button
                            className="btn btn-sm btn-ghost"
                            disabled={oi <= 0}
                            onClick={() => void reorderGroup(cid, b.name!, 'up')}
                            title="上へ"
                            aria-label="Move group up"
                          >
                            ↑
                          </button>
                          <button
                            className="btn btn-sm btn-ghost"
                            disabled={oi < 0 || oi >= orderedNames.length - 1}
                            onClick={() => void reorderGroup(cid, b.name!, 'down')}
                            title="下へ"
                            aria-label="Move group down"
                          >
                            ↓
                          </button>
                        </span>
                      </>
                    ) : (
                      <span className="mon-group-name ungrouped">Ungrouped</span>
                    )}
                    <span className="mon-group-count">
                      {b.items.length} IoC{b.items.length === 1 ? '' : 's'}
                    </span>
                    <span className="cp-group-actions">
                      <button
                        className="btn btn-sm btn-ghost"
                        disabled={bulkBusy}
                        onClick={() => void bulkReEnrich(b.items.map((i) => i.value))}
                        title="このグループを一括 Re-enrich"
                      >
                        ⟳ Re-enrich
                      </button>
                    </span>
                  </div>
                  <ul className="monitor-list">{b.items.map((i) => renderIoc(i, side))}</ul>
                </div>
              );
            })}
          </div>
        )}
      </>
    );
  }

  function AssessmentView() {
    const a = campaign?.assessment;
    // Claude is told to lead with a TLP line; drop it since we render a TLP chip ourselves.
    const body = a ? a.text.replace(/^\s*TLP:[^\n]*\n?/i, '') : '';
    async function gen() {
      setAssessing(true);
      try {
        await assess(cid);
      } finally {
        setAssessing(false);
      }
    }
    return (
      <div className="cp-assess">
        <div className="cp-assess-head">
          <div className="cp-assess-title">
            <b>🧠 CTI アセスメントレポート</b>
            <span className="hint"> — エンリッチ情報・統計・時系列変化に基づく Claude の脅威分析（Insight）</span>
          </div>
          <span className="spacer" />
          {a && (
            <span className="cp-assess-when">
              最終: {new Date(a.at).toLocaleString()}
              {a.by ? ` · ${a.by}` : ''}
              {a.model ? ` · ${a.model}` : ''}
            </span>
          )}
          <button className="btn btn-primary btn-sm" onClick={() => void gen()} disabled={assessing || iocs.length === 0}>
            {assessing ? '生成中…（Claude）' : a ? '🔄 レポート更新' : '🧠 レポート生成'}
          </button>
        </div>
        {assessing && !a && (
          <div className="hint">Claude が {iocs.length} 件のIoC・統計・時系列を分析してレポートを作成中…（数十秒）</div>
        )}
        {a ? (
          <div className="cp-report">
            <div className={`cp-report-tlp ${tlpClass(a.tlp ?? tlp)}`}>TLP:{a.tlp ?? tlp}</div>
            <MarkdownLite className="cp-report-md" text={body} />
          </div>
        ) : (
          !assessing && (
            <div className="empty-state">
              まだレポートがありません。<b>レポート生成</b>で、現時点の攻撃キャンペーンの評価（要約・インフラ分析・TTPs・アトリビューション・推奨アクション等）を
              Claude が作成します（プロキシ＋ANTHROPIC_API_KEY 必要）。
            </div>
          )
        )}
      </div>
    );
  }

  const tabs: { key: Tab; label: string }[] = [
    { key: 'dashboard', label: '📊 Dashboard' },
    { key: 'attack', label: `🗡 Attack Info (${attackIocs.length})` },
    { key: 'target', label: `🎯 Target Info (${targetIocs.length})` },
    { key: 'assessment', label: '🧠 Assessment' },
  ];

  return (
    <section className="panel monitor-page">
      <div className="panel-head cp-head">
        <button className="btn btn-sm" onClick={openCampaigns} title="CP-Mon に戻る">
          ← Back
        </button>
        <button
          className="cp-title-btn"
          onClick={() => {
            const nn = window.prompt('Rename campaign:', campaign.name);
            if (nn != null) void rename(id, nn);
          }}
          title="クリックで名称変更"
        >
          <h2>
            {campaign.name} <span className="cp-title-edit">✎</span>
          </h2>
        </button>
        <label className={`cp-tlp ${tlpClass(tlp)}`} title="TLP（Traffic Light Protocol）取り扱い区分">
          <span className="cp-tlp-dot" aria-hidden />
          <select value={tlp} onChange={(e) => void setTlp(cid, e.target.value as TlpLevel)} aria-label="TLP">
            {TLP_LEVELS.map((l) => (
              <option key={l} value={l}>
                TLP:{l}
              </option>
            ))}
          </select>
        </label>
        <div className="cp-admiralty" title="Admiralty Code — 情報源の信頼性(A–F) ＋ 情報の確度(1–6)">
          <span className="cp-admiralty-label">Admiralty</span>
          <select
            className="cp-adm-sel"
            value={admRel}
            onChange={(e) => void setAdmiralty(cid, e.target.value, admCred)}
            aria-label="情報源の信頼性 (A–F)"
            title="情報源の信頼性 (A–F)"
          >
            <option value="">—</option>
            {ADMIRALTY_RELIABILITY.map(([k, desc]) => (
              <option key={k} value={k} title={desc}>
                {k}
              </option>
            ))}
          </select>
          <select
            className="cp-adm-sel"
            value={admCred}
            onChange={(e) => void setAdmiralty(cid, admRel, e.target.value)}
            aria-label="情報の確度 (1–6)"
            title="情報の確度 (1–6)"
          >
            <option value="">—</option>
            {ADMIRALTY_CREDIBILITY.map(([k, desc]) => (
              <option key={k} value={k} title={desc}>
                {k}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="cp-help-btn"
            onClick={() => setAdmHelp((v) => !v)}
            title="Admiralty Code とは？"
            aria-expanded={admHelp}
          >
            ❓
          </button>
          {admHelp && (
            <div className="cp-help-pop" role="dialog" aria-label="Admiralty Code の説明">
              <div className="cp-help-pop-head">
                <b>Admiralty Code（NATO 情報評価システム）</b>
                <button className="cp-help-close" onClick={() => setAdmHelp(false)} aria-label="閉じる">
                  ✕
                </button>
              </div>
              <p className="hint">
                情報源の<b>信頼性</b>（A–F）と情報自体の<b>確度</b>（1–6）を組み合わせて評価します。例:{' '}
                <b>B2</b>＝「通常信頼できる情報源」×「おそらく真」。2軸は独立に評価するのが原則です。
              </p>
              <div className="cp-help-cols">
                <div>
                  <div className="cp-help-col-title">情報源の信頼性 (Reliability)</div>
                  {ADMIRALTY_RELIABILITY.map(([k, desc]) => (
                    <div key={k} className="cp-help-row">
                      <b>{k}</b> {desc}
                    </div>
                  ))}
                </div>
                <div>
                  <div className="cp-help-col-title">情報の確度 (Credibility)</div>
                  {ADMIRALTY_CREDIBILITY.map(([k, desc]) => (
                    <div key={k} className="cp-help-row">
                      <b>{k}</b> {desc}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
        <span className="cp-title-meta">{iocs.length} IoCs</span>
        <div className="spacer" />
        <button
          className="btn btn-sm btn-danger"
          onClick={() => {
            if (window.confirm(`Delete campaign “${campaign.name}” and all its IOCs?`)) void removeCampaign(id);
          }}
        >
          Delete
        </button>
      </div>

      {(campaign.summary || summarizing) && (
        <div className="cp-marquee" role="status" aria-label="campaign key message">
          <span className="cp-marquee-tag">総括</span>
          <div className="cp-marquee-viewport">
            {campaign.summary ? (
              <div className="cp-marquee-track">
                <span className="cp-marquee-text">{campaign.summary.text}</span>
                <span className="cp-marquee-text" aria-hidden>
                  {campaign.summary.text}
                </span>
              </div>
            ) : (
              <span className="cp-marquee-pending">総括を生成中…（Claude）</span>
            )}
          </div>
          <button
            className="cp-marquee-refresh"
            onClick={() => void onSummarize()}
            disabled={summarizing || iocs.length === 0}
            title={campaign.summary ? `Claudeで総括を再生成 · 最終: ${new Date(campaign.summary.at).toLocaleString()}` : 'Claudeで総括を生成'}
          >
            {summarizing ? '…' : '🔄'}
          </button>
        </div>
      )}

      <div className="cp-tabs" role="tablist">
        {tabs.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={tab === t.key}
            className={`cp-tab${tab === t.key ? ' active' : ''}`}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="cp-tabpanel">
        {tab === 'dashboard' &&
          (iocs.length === 0 ? (
            <div className="empty-state">
              まだ IoC がありません。<b>Attack Info</b> / <b>Target Info</b> タブで登録してください。
            </div>
          ) : (
            <CampaignDashboard
              iocs={iocs}
              onOpen={(v) => {
                const ioc = campaign.iocs[v];
                if (ioc?.result) showResult(ioc.result);
              }}
            />
          ))}
        {tab === 'attack' && <SideView side="attack" />}
        {tab === 'target' && <SideView side="target" />}
        {tab === 'assessment' && <AssessmentView />}
      </div>
    </section>
  );
}
