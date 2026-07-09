import { useEffect, useMemo, useRef, useState } from 'react';
import { extractIndicators, type EnrichableType } from '@vteeee/shared';
import { useStore, type CampaignIoc } from '../state/store';
import { VerdictBadge } from './Badges';
import { Spark } from './Spark';
import { CountryChoropleth } from './CountryChoropleth';
import { abuseOf, countryOf, cvesOf, detOf, diffParts, portsOf, rfOf } from '../lib/enrichTrend';

const UNGROUPED = '__ungrouped__';

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

/** Campaign analytics — the dashboard is analysis, not just a list: roll-up, distributions, and the
 *  recent enrichment CHANGES across the campaign's IOCs (its evolving picture). */
function CampaignDashboard({ iocs, onOpen }: { iocs: CampaignIoc[]; onOpen?: (v: string) => void }) {
  const [mapGroup, setMapGroup] = useState('');
  // Country heatmap for a chosen group within the campaign (darker = more IOCs in that country).
  const map = useMemo(() => {
    const names = [...new Set(iocs.map((i) => i.group).filter((g): g is string => !!g))].sort((a, b) =>
      a.localeCompare(b),
    );
    const hasUngrouped = iocs.some((i) => !i.group);
    const entries =
      !mapGroup ? iocs : mapGroup === UNGROUPED ? iocs.filter((i) => !i.group) : iocs.filter((i) => i.group === mapGroup);
    const counts: Record<string, number> = {};
    const seen = new Set<string>();
    for (const i of entries) {
      const cc = i.result ? countryOf(i.result) : '';
      if (cc) {
        counts[cc] = (counts[cc] ?? 0) + 1;
        seen.add(cc);
      }
    }
    return { names, hasUngrouped, n: entries.length, countryN: seen.size, counts };
  }, [iocs, mapGroup]);

  const d = useMemo(() => {
    const byType = new Map<string, number>();
    for (const i of iocs) byType.set(i.type, (byType.get(i.type) ?? 0) + 1);
    const byCve = new Map<string, number>();
    const byCountry = new Map<string, number>();
    let hostsCve = 0;
    for (const i of iocs) {
      const r = i.result;
      const v = r?.shodan?.vulns;
      if (v?.length) {
        hostsCve++;
        for (const c of v) byCve.set(c, (byCve.get(c) ?? 0) + 1);
      }
      const cc = r ? countryOf(r) : '';
      if (cc) byCountry.set(cc, (byCountry.get(cc) ?? 0) + 1);
    }
    const recent: { value: string; at: number; changes: string[] }[] = [];
    for (const i of iocs) {
      const h = i.history?.length ? [...i.history].sort((a, b) => a.at - b.at) : [];
      if (h.length < 2) continue;
      const changes = diffParts(h[h.length - 1].result, h[h.length - 2].result);
      if (changes.length) recent.push({ value: i.value, at: h[h.length - 1].at, changes });
    }
    recent.sort((a, b) => b.at - a.at);
    return {
      total: iocs.length,
      withIntel: iocs.filter((i) => i.result).length,
      mal: iocs.filter((i) => i.result?.verdict === 'malicious').length,
      sus: iocs.filter((i) => i.result?.verdict === 'suspicious').length,
      highAbuse: iocs.filter((i) => (i.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length,
      auto: iocs.filter((i) => i.autoEnrich).length,
      byType: [...byType.entries()].sort((a, b) => b[1] - a[1]) as [string, number][],
      cves: [...byCve.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10) as [string, number][],
      countries: [...byCountry.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10) as [string, number][],
      distinctCves: byCve.size,
      hostsCve,
      recent: recent.slice(0, 8),
    };
  }, [iocs]);

  if (d.total === 0) return null;

  return (
    <>
      <div className="mon-stats" role="group" aria-label="campaign overview">
        <Tile n={d.total} label="IOCs" />
        <Tile n={d.withIntel} label="with intel" />
        {d.mal > 0 && <Tile n={d.mal} label="malicious" tone="bad" />}
        {d.sus > 0 && <Tile n={d.sus} label="suspicious" tone="warn" />}
        {d.highAbuse > 0 && <Tile n={d.highAbuse} label="abuse ≥75" tone="bad" />}
        {d.hostsCve > 0 && <Tile n={d.hostsCve} label="hosts w/ CVEs" tone="warn" />}
        {d.distinctCves > 0 && <Tile n={d.distinctCves} label="distinct CVEs" />}
        <Tile n={d.auto} label="⚡ auto" />
      </div>
      <div className="mon-dash mon-dash-nomap">
        <Bars title="By IOC type" rows={d.byType} />
        <Bars title="By country" rows={d.countries} />
        <Bars title="Top CVEs" rows={d.cves} hrefFor={(cve) => `https://nvd.nist.gov/vuln/detail/${cve}`} />
      </div>
      <div className="mon-choro">
        <div className="mon-choro-head">
          <div className="mon-bars-title">国別ヒートマップ — 多いほど濃い</div>
          {map.names.length > 0 && (
            <select
              className="filter mon-choro-group"
              value={mapGroup}
              onChange={(e) => setMapGroup(e.target.value)}
              aria-label="Group for the country heatmap"
              title="ヒートマップに集計するグループを選択"
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
            {map.n} IoC{map.n === 1 ? '' : 's'} · {map.countryN} countries
          </span>
        </div>
        <CountryChoropleth counts={map.counts} />
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

export function CampaignPage() {
  const id = useStore((s) => s.campaignId);
  const campaign = useStore((s) => (id ? s.campaigns[id] : undefined));
  const openCampaigns = useStore((s) => s.openCampaigns);
  const addIocs = useStore((s) => s.addCampaignIocs);
  const setGroup = useStore((s) => s.setCampaignIocGroup);
  const removeIocs = useStore((s) => s.removeCampaignIocs);
  const reEnrich = useStore((s) => s.reEnrichCampaignIoc);
  const setAuto = useStore((s) => s.setCampaignIocAuto);
  const rename = useStore((s) => s.renameCampaign);
  const removeCampaign = useStore((s) => s.removeCampaign);
  const showResult = useStore((s) => s.showResult);
  const summarize = useStore((s) => s.summarizeCampaign);
  const [text, setText] = useState('');
  const [groupInput, setGroupInput] = useState('');
  const [summarizing, setSummarizing] = useState(false);
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
  // Auto-write the key message once when a campaign with IOCs is opened and has none yet — so it
  // "appears" (電光掲示板) without the analyst clicking. The button refreshes it thereafter.
  useEffect(() => {
    if (!id || !iocCount || hasSummary || summarizing) return;
    if (autoSummarized.current === id) return;
    autoSummarized.current = id;
    void onSummarize();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, iocCount, hasSummary]);

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

  const cid: string = id; // narrowed non-null id for use inside nested closures/renderIoc
  const iocs = Object.values(campaign.iocs).sort((a, b) => b.updatedAt - a.updatedAt);
  const groupNames = [...new Set(iocs.map((i) => i.group).filter((g): g is string => !!g))].sort((a, b) =>
    a.localeCompare(b),
  );
  const buckets: { key: string; name: string | null; items: CampaignIoc[] }[] = groupNames.map((g) => ({
    key: g,
    name: g,
    items: iocs.filter((i) => i.group === g),
  }));
  const ungrouped = iocs.filter((i) => !i.group);
  if (ungrouped.length) buckets.push({ key: UNGROUPED, name: null, items: ungrouped });

  function onAdd() {
    const { indicators } = extractIndicators(text);
    const add = indicators
      .filter((i) => i.type !== 'unknown' && !i.private)
      .map((i) => ({ value: i.value, type: i.type as EnrichableType }));
    if (!add.length) return;
    void addIocs(cid, add, groupInput);
    setText('');
  }

  function renderIoc(i: CampaignIoc) {
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
            </span>
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
          <button className="btn btn-sm" disabled={!r} onClick={() => r && showResult(r)}>
            Open
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

  return (
    <section className="panel monitor-page">
      <div className="panel-head">
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
        <span className="cp-title-meta">{iocs.length} IoCs</span>
        <div className="spacer" />
        <button
          className="btn btn-sm btn-danger"
          onClick={() => {
            if (window.confirm(`Delete campaign “${campaign.name}” and all its IOCs?`)) void removeCampaign(id);
          }}
        >
          Delete campaign
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
            title={
              campaign.summary
                ? `Claudeで総括を再生成 · 最終: ${new Date(campaign.summary.at).toLocaleString()}${
                    campaign.summary.by ? ` · ${campaign.summary.by}` : ''
                  }`
                : 'Claudeで総括を生成'
            }
          >
            {summarizing ? '…' : '🔄'}
          </button>
        </div>
      )}

      <p className="hint mon-intro">
        任意の <b>Group 名</b>を付けて IoC を登録できます。登録した IoC は<b>サーバ側で毎日自動エンリッチ</b>され、各行に
        <b>傾向スパークライン＋前回比</b>を表示、<b>履歴ごとチーム共有</b>されます（無駄打ち回避）。
      </p>

      <CampaignDashboard
        iocs={iocs}
        onOpen={(v) => {
          const ioc = campaign.iocs[v];
          if (ioc?.result) showResult(ioc.result);
        }}
      />

      <div className="cp-add">
        <input
          className="filter mon-group-input"
          list="cp-group-names"
          placeholder="group name…（任意）"
          value={groupInput}
          onChange={(e) => setGroupInput(e.target.value)}
          aria-label="Group for the added IOCs"
        />
        <datalist id="cp-group-names">
          {groupNames.map((g) => (
            <option key={g} value={g} />
          ))}
        </datalist>
        <textarea
          className="cp-add-text mono"
          placeholder="IoC を貼り付け（改行/カンマ区切り可・defang対応）: 1[.]1[.]1[.]1  hxxp://evil[.]com  44d88612fea8a8f36de82e1278abb02f …"
          rows={2}
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <button className="btn btn-primary" onClick={onAdd} disabled={!text.trim()}>
          ＋ Add IOCs
        </button>
      </div>

      {iocs.length === 0 ? (
        <div className="empty-state">
          まだ IoC がありません。上の欄に貼り付けて <b>Add IOCs</b> で登録してください（IP/ドメイン/URL/ハッシュ）。
        </div>
      ) : (
        <div className="mon-groups">
          {buckets.map((b) => (
            <div className="mon-group" key={b.key}>
              <div className="mon-group-head">
                <span className={`mon-group-name${b.name ? '' : ' ungrouped'}`}>{b.name ?? 'Ungrouped'}</span>
                <span className="mon-group-count">
                  {b.items.length} IoC{b.items.length === 1 ? '' : 's'}
                </span>
              </div>
              <ul className="monitor-list">{b.items.map(renderIoc)}</ul>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
