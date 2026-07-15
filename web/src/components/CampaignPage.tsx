import { useEffect, useMemo, useRef, useState } from 'react';
import { extractIndicators, type EnrichableType, type NormalizedResult } from '@vteeee/shared';
import { useStore, type CampaignIoc, type IocSide, type TlpLevel } from '../state/store';
import {
  TLP_LEVELS,
  ADMIRALTY_RELIABILITY,
  ADMIRALTY_CREDIBILITY,
  type CampaignAssessment,
} from '../state/campaigns';
import { VerdictBadge } from './Badges';
import { Spark } from './Spark';
import { CountryChoropleth } from './CountryChoropleth';
import { MarkdownLite } from './MarkdownLite';
import { intelChips, countryFlag } from '../lib/iocChips';
import { copyText, copyElementImage, exportAssessmentPdf } from '../lib/assessment-export';
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

/** Compact completion time for a 魚拓 (e.g. "7/13 14:30"). */
function capTime(at: number): string {
  return new Date(at).toLocaleString(undefined, { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function tlpClass(t: TlpLevel): string {
  return `tlp-${t.toLowerCase().replace('+', '-')}`;
}

function Tile({ n, label, tone, onPick }: { n: number; label: string; tone?: 'bad' | 'warn'; onPick?: () => void }) {
  return (
    <div
      className={`mon-stat${tone ? ` ${tone}` : ''}${onPick ? ' pickable' : ''}`}
      onClick={onPick}
      role={onPick ? 'button' : undefined}
      title={onPick ? 'クリックで対象IoCを表示' : undefined}
    >
      <b>{n}</b>
      <span>{label}</span>
    </div>
  );
}
function Bars({
  title,
  rows,
  hrefFor,
  onPick,
}: {
  title: string;
  rows: [string, number][];
  hrefFor?: (k: string) => string;
  onPick?: (k: string) => void;
}) {
  const max = rows[0]?.[1] ?? 1;
  return (
    <div className="mon-bars">
      <div className="mon-bars-title">{title}</div>
      {rows.length === 0 ? (
        <div className="hint">—</div>
      ) : (
        rows.map(([k, n]) => (
          <div
            key={k}
            className={`mon-bar-row${onPick ? ' pickable' : ''}`}
            onClick={onPick ? () => onPick(k) : undefined}
            title={onPick ? 'クリックで対象IoCを表示' : undefined}
          >
            <span className="mon-bar-label mono">
              {hrefFor ? (
                <a href={hrefFor(k)} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>
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

/** A recent enrichment change plus the asset CONTEXT needed to read it at a glance. */
type RecentChange = {
  value: string;
  at: number;
  changes: string[];
  type: EnrichableType;
  side: IocSide;
  group?: string;
  country: string;
  org: string;
  verdict?: string;
};

/** Campaign analytics, scoped so Attack (threat) and Target (OSINT exposure) never mix — the map too. */
function CampaignDashboard({ iocs, onOpen }: { iocs: CampaignIoc[]; onOpen?: (v: string) => void }) {
  const attackN = iocs.filter((i) => (i.side ?? 'attack') === 'attack').length;
  const targetN = iocs.filter((i) => i.side === 'target').length;
  const [scope, setScope] = useState<'attack' | 'target' | 'all'>(() =>
    attackN > 0 ? 'attack' : targetN > 0 ? 'target' : 'all',
  );
  const [mapGroup, setMapGroup] = useState('');
  const [drill, setDrill] = useState<{ label: string; values: string[] } | null>(null);
  const scoped = useMemo(
    () => (scope === 'all' ? iocs : iocs.filter((i) => (i.side ?? 'attack') === scope)),
    [iocs, scope],
  );
  // Drill-down: "which IOCs are behind this stat?" — set the list from a predicate over the scoped set.
  const pick = (label: string, pred: (i: CampaignIoc) => boolean) =>
    setDrill({ label, values: scoped.filter(pred).map((i) => i.value) });
  const pickCountry = (raw: string) => pick(`国: ${raw}`, (i) => (i.result ? countryOf(i.result) : '') === raw);

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
    // Each recent change carries enough CONTEXT to read it without opening the IOC: which group, side,
    // country, network owner (ASN org / registrar) and current verdict — an IP + a delta alone is unreadable.
    const orgOf = (r?: NormalizedResult): string =>
      (r?.shodan?.org || r?.maxmind?.organization || r?.ip?.asOwner || r?.domaintools?.registrar || '').trim();
    const recent: RecentChange[] = [];
    for (const i of scoped) {
      const h = i.history?.length ? [...i.history].sort((a, b) => a.at - b.at) : [];
      if (h.length < 2) continue;
      const changes = diffParts(h[h.length - 1].result, h[h.length - 2].result);
      if (!changes.length) continue;
      const r = h[h.length - 1].result ?? i.result;
      recent.push({
        value: i.value,
        at: h[h.length - 1].at,
        changes,
        type: i.type,
        side: i.side ?? 'attack',
        group: i.group,
        country: r ? countryOf(r) : '',
        org: orgOf(r),
        verdict: r?.verdict,
      });
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
          setDrill(null);
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
          setDrill(null);
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
          setDrill(null);
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
      {drill && (
        <div className="cp-drill">
          <div className="cp-drill-head">
            <b>{drill.label}</b>
            <span className="cp-drill-n">{drill.values.length} 件</span>
            <span className="spacer" />
            <button className="cp-drill-close" onClick={() => setDrill(null)} aria-label="閉じる" title="閉じる">
              ✕
            </button>
          </div>
          {drill.values.length ? (
            <div className="cp-drill-list">
              {drill.values.map((v) => (
                <button key={v} className="cp-drill-ioc mono" onClick={() => onOpen?.(v)} title="詳細を開く">
                  {v}
                </button>
              ))}
            </div>
          ) : (
            <div className="hint">該当なし</div>
          )}
        </div>
      )}
      <div className="mon-stats" role="group" aria-label="campaign overview">
        <Tile n={d.total} label={target ? 'assets' : 'IOCs'} onPick={() => pick(target ? 'assets' : 'IOCs', () => true)} />
        <Tile n={d.withIntel} label="with intel" onPick={() => pick('with intel', (i) => !!i.result)} />
        {target ? (
          <>
            {d.hostsPorts > 0 && (
              <Tile n={d.hostsPorts} label="exposed hosts" tone="warn" onPick={() => pick('exposed hosts（開放ポートあり）', (i) => (i.result?.shodan?.ports?.length ?? 0) > 0)} />
            )}
            {d.hostsCve > 0 && (
              <Tile n={d.hostsCve} label="hosts w/ CVEs" tone="bad" onPick={() => pick('hosts w/ CVEs', (i) => (i.result?.shodan?.vulns?.length ?? 0) > 0)} />
            )}
            {d.distinctCves > 0 && <Tile n={d.distinctCves} label="distinct CVEs" />}
            {d.anon > 0 && (
              <Tile n={d.anon} label="anonymized" onPick={() => pick('anonymized（VPN/Tor/proxy）', (i) => (i.result?.maxmind?.anonymizerType?.length ?? 0) > 0)} />
            )}
          </>
        ) : (
          <>
            {d.mal > 0 && <Tile n={d.mal} label="malicious" tone="bad" onPick={() => pick('malicious', (i) => i.result?.verdict === 'malicious')} />}
            {d.sus > 0 && <Tile n={d.sus} label="suspicious" tone="warn" onPick={() => pick('suspicious', (i) => i.result?.verdict === 'suspicious')} />}
            {d.highAbuse > 0 && (
              <Tile n={d.highAbuse} label="abuse ≥75" tone="bad" onPick={() => pick('abuse ≥75', (i) => (i.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75)} />
            )}
            {d.distinctCves > 0 && <Tile n={d.distinctCves} label="distinct CVEs" />}
          </>
        )}
        <Tile n={d.auto} label="⚡ auto" onPick={() => pick('⚡ auto', (i) => !!i.autoEnrich)} />
      </div>
      <div className="mon-dash mon-dash-nomap">
        <Bars title="By IOC type" rows={d.byType} onPick={(t) => pick(`type: ${t}`, (i) => i.type === t)} />
        <Bars
          title={target ? '露出脆弱性 Top CVEs' : 'Top CVEs'}
          rows={d.cves}
          hrefFor={(cve) => `https://nvd.nist.gov/vuln/detail/${cve}`}
          onPick={(cve) => pick(`CVE ${cve}`, (i) => i.result?.shodan?.vulns?.includes(cve) ?? false)}
        />
        {target && (
          <Bars
            title="露出ポート Top"
            rows={d.ports}
            hrefFor={(p) => `https://www.shodan.io/search?query=port%3A${p}`}
            onPick={(p) => pick(`port ${p}`, (i) => i.result?.shodan?.ports?.includes(Number(p)) ?? false)}
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
            <Bars title="By country" rows={map.countryRows} onPick={pickCountry} />
          </div>
          <div className="mon-geo-map">
            <CountryChoropleth
              counts={map.counts}
              height={250}
              onPick={(iso, name) =>
                pick(`国: ${name} (${iso})`, (i) => {
                  const cc = i.result ? countryOf(i.result) : '';
                  if (!cc) return false;
                  const u = cc.toUpperCase();
                  return u === iso || u === name.toUpperCase();
                })
              }
            />
          </div>
        </div>
      </div>
      {d.recent.length > 0 && (
        <div className="cp-recent">
          <div className="mon-bars-title">Recent changes（直近のエンリッチ変化）</div>
          {d.recent.map((r) => {
            const flag = countryFlag(r.country);
            return (
              <div key={r.value} className="cp-recent-row">
                <div className="cp-recent-head">
                  <button className="cp-recent-ioc mono" onClick={() => onOpen?.(r.value)} title="詳細を開く">
                    {r.value}
                  </button>
                  <span className="cp-recent-when">{new Date(r.at).toLocaleDateString()}</span>
                </div>
                <div className="cp-recent-ctx">
                  <span className={`mon-chip cp-side cp-side-${r.side}`} title={r.side === 'target' ? '標的（自組織／守る側）' : '攻撃インフラ'}>
                    {r.side === 'target' ? '標的' : '攻撃'}
                  </span>
                  <span className="mon-chip" title="グループ">
                    📁 {r.group || '未分類'}
                  </span>
                  <span className="mon-chip mono" title="IoC種別">{r.type}</span>
                  {r.country && (
                    <span className="mon-chip" title={`国: ${r.country}`}>
                      {flag ? `${flag} ` : '📍 '}
                      {r.country}
                    </span>
                  )}
                  {r.org && (
                    <span className="mon-chip" title="ネットワーク所有者（ASN組織／レジストラ）">
                      🏢 {r.org.length > 28 ? `${r.org.slice(0, 28)}…` : r.org}
                    </span>
                  )}
                  {(r.verdict === 'malicious' || r.verdict === 'suspicious') && (
                    <span className={`mon-chip ${r.verdict === 'malicious' ? 'sev-high' : 'sev-med'}`} title="現在の判定">
                      {r.verdict === 'malicious' ? '悪性' : '疑わしい'}
                    </span>
                  )}
                </div>
                <span className="hist-diff changed cp-recent-diff">▲ {r.changes.join(' · ')}</span>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}

type Tab = 'dashboard' | 'attack' | 'target' | 'assessment';

/**
 * The urlscan 魚拓 target for an IOC, or null if it has no web surface. URLs/domains capture as-is;
 * IP assets (either side) capture their primary web endpoint (https://<ip>) so an analyst can snapshot
 * the current exposure in bulk. Hashes are never web-capturable.
 */
function captureKey(i: CampaignIoc): string | null {
  if (i.type === 'url' || i.type === 'domain') return i.value;
  if (i.type === 'ipv4') return `https://${i.value}`;
  if (i.type === 'ipv6') return `https://[${i.value}]`;
  return null;
}

export function CampaignPage() {
  const id = useStore((s) => s.campaignId);
  const campaign = useStore((s) => (id ? s.campaigns[id] : undefined));
  const openCampaigns = useStore((s) => s.openCampaigns);
  const addIocs = useStore((s) => s.addCampaignIocs);
  const setGroup = useStore((s) => s.setCampaignIocGroup);
  const setTlp = useStore((s) => s.setCampaignTlp);
  const setNote = useStore((s) => s.setCampaignNote);
  const setAdmiralty = useStore((s) => s.setCampaignAdmiralty);
  const reorderGroup = useStore((s) => s.reorderCampaignGroup);
  const removeIocs = useStore((s) => s.removeCampaignIocs);
  const reEnrich = useStore((s) => s.reEnrichCampaignIoc);
  const reEnrichIocs = useStore((s) => s.reEnrichCampaignIocs);
  const setAuto = useStore((s) => s.setCampaignIocAuto);
  const rename = useStore((s) => s.renameCampaign);
  const removeCampaign = useStore((s) => s.removeCampaign);
  const showResult = useStore((s) => s.showResult);
  const openCampaignAnalysis = useStore((s) => s.openCampaignAnalysis);
  const startWebCapture = useStore((s) => s.startWebCapture);
  const startWebCaptureBatch = useStore((s) => s.startWebCaptureBatch);
  const webCaptures = useStore((s) => s.webCaptures);
  const summarize = useStore((s) => s.summarizeCampaign);
  const assess = useStore((s) => s.assessCampaign);
  const refreshCampaigns = useStore((s) => s.refreshCampaigns);
  const refreshCaptures = useStore((s) => s.refreshCaptures);
  const syncNote = useStore((s) => s.campaignsSyncNote);
  const [text, setText] = useState('');
  const [groupInput, setGroupInput] = useState('');
  // Tab lives in the store so returning from the full-page Analysis lands back on the same tab.
  const tab = useStore((s) => s.campaignTab);
  const setTab = useStore((s) => s.setCampaignTab);
  const [summarizing, setSummarizing] = useState(false);
  const [assessing, setAssessing] = useState(false);
  const [assessSel, setAssessSel] = useState(0); // which past assessment is shown (0 = latest)
  const [reportMsg, setReportMsg] = useState<string | null>(null); // transient copy/export status
  const reportRef = useRef<HTMLDivElement>(null);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [admHelp, setAdmHelp] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [filter, setFilter] = useState('');

  async function onSync() {
    setSyncing(true);
    try {
      await refreshCampaigns();
    } finally {
      setSyncing(false);
    }
  }

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
  async function onSummarize() {
    if (!id) return;
    setSummarizing(true);
    try {
      await summarize(id);
    } finally {
      setSummarizing(false);
    }
  }
  // Auto-generate the 総括 on open when it's MISSING or STALE (campaign data changed since the last
  // summary), at most once per open — so the marquee is current without the analyst pressing 🔄.
  useEffect(() => {
    if (!id || !iocCount || summarizing) return;
    if (autoSummarized.current === id) return;
    const summaryAt = campaign?.summary?.at ?? 0;
    const lastDataAt = Object.values(campaign?.iocs ?? {}).reduce((m, i) => Math.max(m, i.updatedAt ?? 0), 0);
    const stale = !campaign?.summary || lastDataAt > summaryAt;
    autoSummarized.current = id;
    if (stale) void onSummarize();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, iocCount, campaign, summarizing]);

  // Pull the latest shared campaigns + 魚拓 history when opening one, so cross-browser edits are reflected.
  useEffect(() => {
    if (id) {
      void refreshCampaigns();
      void refreshCaptures();
    }
  }, [id, refreshCampaigns, refreshCaptures]);

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

  function renderIoc(i: CampaignIoc, side: IocSide, groups: string[]) {
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
                {groups.map((g) => (
                  <option key={g} value={g}>
                    {g}
                  </option>
                ))}
                {i.group && !groups.includes(i.group) && <option value={i.group}>{i.group}</option>}
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
                {/* Attack = threat verdict FIRST, then type-specific intel: IP→Shodan/MaxMind,
                    domain→DomainTools/DNSLytics/CTI, hash→malware family/labels. */}
                <VerdictBadge verdict={r.verdict} status={r.status} />
                {r.detection && (
                  <span className="mon-chip">
                    det {detOf(r)}/{r.detection.total}
                  </span>
                )}
                {abuseOf(r) != null && <span className="mon-chip">abuse {abuseOf(r)}</span>}
                {rfOf(r) != null && <span className="mon-chip">RF {rfOf(r)}</span>}
                {intelChips(r, i.type)}
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
            title={
              side === 'target'
                ? '詳細を開く（OSINT露出・Live ports・urlscan 魚拓 など）'
                : '詳細を開く'
            }
          >
            Details
          </button>
          <button
            className="btn btn-sm"
            disabled={!r && !(i.history?.length ?? 0)}
            onClick={() => openCampaignAnalysis(cid, i.value)}
            title="Tr-Analysis（Trend Analysis）— このIoCのエンリッチ履歴を時系列分析：トレンド（スパーク＋増減）／指標マトリクス／2点比較／タイムライン"
          >
            📈 Tr-Analysis{(i.history?.length ?? 0) > 1 ? ` (${i.history!.length})` : ''}
          </button>
          {(() => {
            const capKey = captureKey(i);
            if (!capKey) return null;
            const cap = webCaptures[capKey];
            const cp = cap?.phase;
            const running = cp === 'submitting' || cp === 'running';
            const history = cap?.history ?? [];
            if (running) {
              return (
                <button className="btn btn-sm" disabled title="urlscan でレンダリング中…（閉じても裏で継続）">
                  🎣 魚拓中…
                </button>
              );
            }
            if (cp === 'stalled' || cp === 'interrupted') {
              return (
                <button className="btn btn-sm" onClick={() => void startWebCapture(capKey)} title="同じスキャンの結果を再確認（継続）">
                  🎣 再確認
                </button>
              );
            }
            if (history.length > 0) {
              // Done: show WHEN it was captured (latest opens directly), a select to jump to past 魚拓
              // URLs, and a Re-魚拓 to take a fresh one — no longer a duplicate of "Details".
              const latest = history[0];
              return (
                <span className="cp-cap">
                  {latest.result?.resultUrl ? (
                    <a
                      className="cp-cap-open"
                      href={latest.result.resultUrl}
                      target="_blank"
                      rel="noreferrer"
                      title={`最新の魚拓（urlscan）を開く · ${new Date(latest.at).toLocaleString()}${latest.by ? ` · ${latest.by}` : ''}`}
                    >
                      🎣 済 {capTime(latest.at)} ↗
                    </a>
                  ) : (
                    <span className="cp-cap-open" title="魚拓 完了">🎣 済 {capTime(latest.at)}</span>
                  )}
                  {history.length >= 2 && (
                    <select
                      className="cp-cap-hist"
                      title="過去の魚拓を選んで開く（urlscan）"
                      value=""
                      onChange={(e) => {
                        const v = e.currentTarget.value;
                        if (v !== '') {
                          const u = history[Number(v)]?.result?.resultUrl;
                          if (u) window.open(u, '_blank', 'noopener');
                        }
                        e.currentTarget.value = '';
                      }}
                    >
                      <option value="">過去 ({history.length}) ▾</option>
                      {history.map((h, idx) => (
                        <option key={h.uuid} value={idx}>
                          {capTime(h.at)}
                          {h.by ? ` · ${h.by}` : ''}
                          {idx === 0 ? ' · 最新' : ''}
                        </option>
                      ))}
                    </select>
                  )}
                  <button
                    className="btn btn-sm"
                    onClick={() => void startWebCapture(capKey)}
                    title="魚拓を取り直す（最新状態を新たに保全して履歴に追加）"
                  >
                    🔄 Re-魚拓
                  </button>
                </span>
              );
            }
            // error or never captured → offer a fresh capture
            return (
              <button
                className="btn btn-sm"
                onClick={() => void startWebCapture(capKey)}
                title={
                  cp === 'error'
                    ? `再試行: ${cap?.error ?? ''}`
                    : i.type === 'ipv4' || i.type === 'ipv6'
                      ? `urlscan で ${capKey} を魚拓（Web面の現状を保全・裏で継続）`
                      : 'urlscan で今の状態を魚拓（裏で継続・後で確認可）'
                }
              >
                {cp === 'error' ? '🎣 再試行' : '🎣 魚拓'}
              </button>
            );
          })()}
          <button className="btn btn-sm" disabled={i.enriching} onClick={() => void reEnrich(cid, i.value)}>
            {i.enriching ? 'Enriching…' : 'Re-enrich'}
          </button>
          <button
            className={`btn btn-sm${i.autoEnrich ? ' btn-primary' : ''}`}
            onClick={() => void setAuto(cid, [i.value], !i.autoEnrich)}
            title="⚡自動処理 ON/OFF — この IoC のエンリッチ＋魚拓は【ともにサーバ側で毎日自動】（ブラウザを閉じていても定点観測・スナップショット保存、どの端末も同一状態）。意図的な再取得(Re-魚拓)は選んだ対象だけ即時実行。実行は🔔通知/実行ログ(⚡auto)に記録。詳細は Docs → ⚡自動処理"
          >
            ⚡ Auto{i.autoEnrich ? ' ✓' : ''}
          </button>
          {r?.links?.gui && (
            <a className="btn btn-sm" href={r.links.gui} target="_blank" rel="noreferrer">
              VT ↗
            </a>
          )}
          <button
            className="btn btn-sm btn-danger"
            onClick={() => {
              if (window.confirm(`IoC「${i.value}」をこのキャンペーンから削除しますか？\nエンリッチ履歴・魚拓の記録も失われ、チーム共有からも消えます。`))
                void removeIocs(cid, [i.value]);
            }}
          >
            Remove
          </button>
        </div>
      </li>
    );
  }

  /** One IOC-management tab (Attack or Target): add box + threat-sorted, reorderable groups. */
  function SideView({ side }: { side: IocSide }) {
    const allList = side === 'attack' ? attackIocs : targetIocs;
    const sideLabel = side === 'attack' ? 'Attack' : 'Target';
    // Group names scoped to THIS side only — Attack never lists Target's groups and vice versa.
    const sideGroupNames = [...new Set(allList.map((i) => i.group).filter((g): g is string => !!g))].sort((a, b) =>
      a.localeCompare(b),
    );
    // Free-text filter over value / group / country / verdict / org.
    const q = filter.trim().toLowerCase();
    const list = q
      ? allList.filter((i) => {
          const r = i.result;
          return (
            i.value.toLowerCase().includes(q) ||
            (i.group ?? '').toLowerCase().includes(q) ||
            (r ? countryOf(r).toLowerCase().includes(q) : false) ||
            (r?.verdict ?? '').toLowerCase().includes(q) ||
            (r?.shodan?.org ?? r?.maxmind?.organization ?? r?.ip?.asOwner ?? '').toLowerCase().includes(q)
          );
        })
      : allList;
    const { bs, orderedNames } = bucketsFor(list, side);
    const unEnriched = list.filter((i) => !i.result);
    const enrichingN = list.filter((i) => i.enriching).length;
    // Web-capturable IOCs in range (urlscan 魚拓): URL/domain always; on Target, IP assets too.
    const capturable = list.filter((i) => captureKey(i) !== null);
    const capRunningN = capturable.filter((i) => {
      const p = webCaptures[captureKey(i)!]?.phase;
      return p === 'submitting' || p === 'running';
    }).length;
    const capDoneN = capturable.filter((i) => webCaptures[captureKey(i)!]?.phase === 'done').length;
    // Once any target in range has a 魚拓, the bulk action is really a RE-capture — label it so.
    const capAnyHistory = capturable.some((i) => (webCaptures[captureKey(i)!]?.history?.length ?? 0) > 0);
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
              標的/被害側（狙われた資産）の情報。IoC とは限らず、監視対象の資産・アカウント・ドメイン等を含みます。脅威判定より <b>OSINT 露出・リスク</b>の観点で、
              <b>Shodan（開放ポート・サービス・CVE・OS）＋ MaxMind（所在地・ASN/ISP・匿名化）</b>を表示。
              <b>各グループ内は露出度順</b>に整列。行の <b>Details</b> で詳細（Live ports・urlscan 魚拓 など）、<b>🎣 魚拓</b> で即時に魚拓できます。
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
              {sideGroupNames.length > 0 && (
                <select
                  className="filter cp-group-pick"
                  value=""
                  onChange={(e) => {
                    if (e.target.value) setGroupInput(e.target.value);
                  }}
                  aria-label="既存グループから選択"
                  title={`${sideLabel} の既存グループから選ぶ（入力欄に反映されます）`}
                >
                  <option value="">既存から選択…</option>
                  {sideGroupNames.map((g) => (
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
          <div className="cp-add-paste">
            <label className="cp-add-group-label" htmlFor={`cp-paste-${side}`}>
              {side === 'target' ? '標的の情報を貼り付け' : '攻撃側の IoC を貼り付け'}（IP / ドメイン / URL / ハッシュ・改行/カンマ区切り・defang対応）
            </label>
            <textarea
              id={`cp-paste-${side}`}
              className="cp-add-text mono"
              placeholder="例: 1[.]1[.]1[.]1  hxxp://evil[.]com  44d88612fea8a8f36de82e1278abb02f …"
              rows={3}
              value={text}
              onChange={(e) => setText(e.target.value)}
            />
          </div>
          <button className="btn btn-primary cp-add-btn" onClick={() => onAdd(side)} disabled={!text.trim()}>
            ＋ Add to {sideLabel}
          </button>
        </div>

        {allList.length > 0 && (
          <div className="cp-filter-row">
            <input
              className="filter cp-filter-input"
              placeholder={`🔎 ${sideLabel} を絞り込み（IP/ドメイン/グループ/国/判定/組織…）`}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              aria-label={`Filter ${sideLabel} IOCs`}
            />
            {filter && (
              <button className="btn btn-sm btn-ghost" onClick={() => setFilter('')} title="絞り込みをクリア">
                ✕
              </button>
            )}
            <span className="cp-filter-count">
              {list.length}/{allList.length} 件
            </span>
          </div>
        )}

        {list.length > 0 && (
          <div className="cp-side-toolbar">
            <button
              className="btn btn-sm"
              disabled={bulkBusy}
              onClick={() => void bulkReEnrich(list.map((i) => i.value))}
              title={filter ? '絞り込み結果を順次 Re-enrich' : 'この側の全 IoC を順次 Re-enrich（1件ずつ）'}
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
              title="この側の全 IoC の⚡自動処理を ON（エンリッチ＋魚拓とも【サーバ側で毎日自動】＝ブラウザ不要の定点観測、どの端末も同一状態）。実行は🔔通知/実行ログに記録。詳細は Docs → ⚡自動処理"
            >
              ⚡ Auto on all
            </button>
            {capturable.length > 0 && (
              <button
                className="btn btn-sm"
                disabled={capRunningN > 0}
                onClick={() =>
                  void startWebCaptureBatch(
                    capturable.map((i) => captureKey(i)!),
                    undefined,
                    `${campaign?.name ?? 'Campaign'} · ${side === 'attack' ? '🗡Attack' : '🎯Target'}`,
                  )
                }
                title={
                  side === 'target'
                    ? '標的資産（URL/ドメイン + IPのWeb面 https://）を一括で urlscan 魚拓 — 各ジョブは裏で継続・完了時に🔔'
                    : '攻撃側インフラ（URL/ドメイン + IPのWeb面 https://）を一括で urlscan 魚拓 — 各ジョブは裏で継続・完了時に🔔'
                }
              >
                {capRunningN > 0
                  ? `🎣 魚拓 実行中… (${capRunningN})`
                  : capAnyHistory
                    ? `🔄 Re-魚拓 all (${capturable.length})`
                    : `🎣 魚拓 all (${capturable.length})`}
              </button>
            )}
            {(capRunningN > 0 || capDoneN > 0) && (
              <span className="cp-side-toolbar-note">
                🎣 魚拓 {capRunningN > 0 ? `実行中 ${capRunningN}` : ''}
                {capRunningN > 0 && capDoneN > 0 ? ' · ' : ''}
                {capDoneN > 0 ? `完了 ${capDoneN}/${capturable.length}` : ''}
              </span>
            )}
            {unEnriched.length > 0 && !bulkBusy && (
              <span className="cp-side-toolbar-note">
                ⚠ {unEnriched.length} 件が未エンリッチ（追加時の失敗/レート制限の可能性）。上のボタンで再取得できます。
              </span>
            )}
          </div>
        )}

        {allList.length === 0 ? (
          <div className="empty-state">
            まだ {sideLabel} 側の IoC がありません。上の欄に貼り付けて <b>Add to {sideLabel}</b> で登録してください。
          </div>
        ) : list.length === 0 ? (
          <div className="empty-state">「{filter}」に一致する IoC はありません。</div>
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
                      {b.name && (
                        <button
                          className="btn btn-sm btn-ghost"
                          onClick={() => {
                            if (window.confirm(`グループ「${b.name}」を解除しますか？（${b.items.length} 件の IoC はグループなしに戻ります・IoC自体は残ります）`))
                              void setGroup(cid, b.items.map((i) => i.value), undefined);
                          }}
                          title="このグループを解除（IoC はグループなしに戻す・削除はしない）"
                        >
                          ⊘ Ungroup
                        </button>
                      )}
                    </span>
                  </div>
                  <ul className="monitor-list">{b.items.map((i) => renderIoc(i, side, sideGroupNames))}</ul>
                </div>
              );
            })}
          </div>
        )}
      </>
    );
  }

  function AssessmentView() {
    // Full assessment history, newest first (continuous monitoring — keep every past report).
    const history: CampaignAssessment[] =
      campaign?.assessments ?? (campaign?.assessment ? [campaign.assessment] : []);
    const selIdx = history.length ? Math.min(assessSel, history.length - 1) : 0;
    const a = history[selIdx];
    // Claude is told to lead with a TLP line; drop it since we render a TLP chip ourselves.
    const body = a ? a.text.replace(/^\s*TLP:[^\n]*\n?/i, '') : '';
    async function gen() {
      setAssessing(true);
      try {
        await assess(cid);
        setAssessSel(0);
      } finally {
        setAssessing(false);
      }
    }
    const flash = (m: string, ms = 1800) => {
      setReportMsg(m);
      window.setTimeout(() => setReportMsg(null), ms);
    };
    async function copyReport() {
      if (!a) return;
      try {
        await copyText(a.text);
        flash('📋 テキストをコピーしました');
      } catch {
        flash('コピーに失敗しました');
      }
    }
    async function imageReport() {
      if (!a || !reportRef.current) return;
      setReportMsg('🖼 画像を生成中…');
      try {
        await copyElementImage(reportRef.current);
        flash('🖼 画像をコピーしました', 2200);
      } catch {
        flash('画像コピーに失敗（ブラウザ非対応の可能性）', 2600);
      }
    }
    async function pdfReport() {
      if (!a) return;
      setReportMsg('📄 PDFを生成中…');
      try {
        await exportAssessmentPdf(body, { title: campaign?.name ?? 'campaign', tlp: a.tlp ?? tlp, model: a.model, at: a.at });
        flash('📄 PDFを保存しました', 2200);
      } catch {
        flash('PDF生成に失敗しました', 2600);
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
          {history.length >= 2 && (
            <label className="urlscan-hist" title="過去のアセスメントを選択（継続モニタリング）">
              🕓 過去
              <select
                className="urlscan-hist-sel"
                value={selIdx}
                onChange={(e) => setAssessSel(Number(e.currentTarget.value))}
              >
                {history.map((h, i) => (
                  <option key={h.at} value={i}>
                    {i === 0 ? '最新' : `#${history.length - i}`} · {new Date(h.at).toLocaleString()}
                    {h.by ? ` · ${h.by}` : ''}
                  </option>
                ))}
              </select>
              <span className="hint">{history.length} 版</span>
            </label>
          )}
          <button className="btn btn-primary btn-sm" onClick={() => void gen()} disabled={assessing || iocs.length === 0}>
            {assessing ? '生成中…（Claude）' : history.length ? '🔄 レポート更新' : '🧠 レポート生成'}
          </button>
        </div>
        {assessing && (
          <div className="hint">Claude が {iocs.length} 件の情報・統計・時系列を分析してレポートを作成中…（数十秒／長い場合は自動継続）</div>
        )}
        {a ? (
          <>
            <div className="cp-assess-actions">
              <span className="cp-assess-when">
                {selIdx === 0 ? '最新' : '過去版'}: {new Date(a.at).toLocaleString()}
                {a.by ? ` · ${a.by}` : ''}
                {a.model ? ` · ${a.model}` : ''}
              </span>
              <span className="spacer" />
              <button className="btn btn-sm" onClick={() => void copyReport()} title="レポート本文（Markdown）をコピー">
                📋 テキスト
              </button>
              <button className="btn btn-sm" onClick={() => void imageReport()} title="レポートを画像としてクリップボードにコピー">
                🖼 画像
              </button>
              <button className="btn btn-sm" onClick={() => void pdfReport()} title="レポートをPDFで保存（選択可能テキスト・TLP付き）">
                📄 PDF
              </button>
              {reportMsg && <span className="hint cp-assess-msg">{reportMsg}</span>}
            </div>
            <div className="cp-report" ref={reportRef}>
              <div className={`cp-report-tlp ${tlpClass(a.tlp ?? tlp)}`}>TLP:{a.tlp ?? tlp}</div>
              <MarkdownLite className="cp-report-md" text={body} />
            </div>
          </>
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
        <span className="cp-title-meta" title="攻撃側インフラ（IoC）／標的側の監視資産">
          🗡 Attack {attackIocs.length} · 🎯 Target {targetIocs.length}
        </span>
        <div className="spacer" />
        <button className="btn btn-sm" onClick={() => void onSync()} disabled={syncing} title="共有と同期（双方向・非破壊）">
          {syncing ? '⇪ 同期中…' : '⇪ Sync'}
        </button>
        <button
          className="btn btn-sm btn-danger"
          onClick={() => {
            if (window.confirm(`Delete campaign “${campaign.name}” and all its IOCs?`)) void removeCampaign(id);
          }}
        >
          Delete
        </button>
      </div>
      {syncNote && <p className={`hint cp-sync-note${syncNote.startsWith('⚠') ? ' err' : ''}`}>{syncNote}</p>}

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
            aria-label="総括を再生成"
            title={
              campaign.summary
                ? `🔄 総括を今すぐ再生成 — Claude が最新データでキーメッセージを書き直します。\n（開くたびにデータ変更があれば自動更新されます）\n最終更新: ${new Date(campaign.summary.at).toLocaleString()}`
                : '🔄 総括を生成 — Claude が最新データからキーメッセージを作成します。'
            }
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
            onClick={() => {
              setTab(t.key);
              setFilter('');
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="cp-tabpanel">
        {tab === 'dashboard' && (
          <>
            <div className="cp-note">
              <label className="cp-note-label" htmlFor="cp-note-field">
                📝 背景・アナリストコメント
                <span className="hint">
                  {' '}
                  （自由記述。記入するとアセスメントレポート生成時の文脈として考慮されます。空欄でも構いません）
                </span>
              </label>
              <textarea
                id="cp-note-field"
                key={cid}
                className="cp-note-field"
                defaultValue={campaign.note ?? ''}
                placeholder="例: 特定業種を狙った資格情報窃取と推定。◯◯社の報告（2026-07）と関連の可能性。△△.example は誤検知の疑い。次は登録者情報のピボットを予定…"
                rows={3}
                onBlur={(e) => {
                  const v = e.currentTarget.value;
                  if ((campaign.note ?? '') !== v) void setNote(cid, v);
                }}
              />
            </div>
            {iocs.length === 0 ? (
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
            )}
          </>
        )}
        {/* Called as a function (not <SideView/>) so it inlines into this component's tree — the filter
            input then keeps focus across re-renders instead of remounting on every keystroke. */}
        {tab === 'attack' && SideView({ side: 'attack' })}
        {tab === 'target' && SideView({ side: 'target' })}
        {tab === 'assessment' && AssessmentView()}
      </div>
    </section>
  );
}
