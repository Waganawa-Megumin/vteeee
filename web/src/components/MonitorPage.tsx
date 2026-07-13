import { useEffect, useRef, useState } from 'react';
import { useStore, type MonitorEntry } from '../state/store';
import { VerdictBadge } from './Badges';
import { detectionRatio } from '../lib/verdict';
import { Spark } from './Spark';
import { CountryChoropleth } from './CountryChoropleth';
import { abuseOf, cvesOf, detOf, diffParts, portsOf, rfOf } from '../lib/enrichTrend';

// Minimal Leaflet surface (dynamic import keeps it lazy) — mirrors the detail-panel map shim.
interface LMap {
  setView(c: [number, number], z: number): LMap;
  fitBounds(b: [number, number][], o?: Record<string, unknown>): void;
  invalidateSize(): void;
  remove(): void;
}
interface LLayer {
  addTo(m: LMap): LLayer;
  bindPopup(html: string): LLayer;
}
interface LApi {
  map(el: HTMLElement, o?: Record<string, unknown>): LMap;
  tileLayer(url: string, o?: Record<string, unknown>): LLayer;
  circleMarker(c: [number, number], o?: Record<string, unknown>): LLayer;
}

const verdictColor = (v?: string): string =>
  v === 'malicious' ? '#dc2626' : v === 'suspicious' ? '#f59e0b' : v === 'harmless' ? '#3aa981' : '#8b5cf6';

/** World map with a marker per monitored IP that has coordinates (from MaxMind), coloured by verdict. */
function MonitorMap({ points }: { points: { lat: number; lon: number; ip: string; verdict?: string }[] }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let map: LMap | null = null;
    let cancelled = false;
    void (async () => {
      const el = ref.current;
      if (!el) return;
      try {
        await import('leaflet/dist/leaflet.css');
        const mod = await import('leaflet');
        const L = ((mod as { default?: unknown }).default ?? mod) as unknown as LApi;
        if (cancelled || !ref.current) return;
        map = L.map(el, { scrollWheelZoom: false, worldCopyJump: true, attributionControl: true }).setView([25, 5], 1);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          maxZoom: 19,
          attribution: '© OpenStreetMap contributors',
        }).addTo(map);
        const bounds: [number, number][] = [];
        for (const p of points) {
          L.circleMarker([p.lat, p.lon], {
            radius: 6,
            color: '#ffffff',
            weight: 1.5,
            fillColor: verdictColor(p.verdict),
            fillOpacity: 0.9,
          })
            .addTo(map)
            .bindPopup(`${p.ip}${p.verdict ? ` · ${p.verdict}` : ''}`);
          bounds.push([p.lat, p.lon]);
        }
        if (bounds.length >= 2) {
          try {
            map.fitBounds(bounds, { padding: [30, 30], maxZoom: 6 });
          } catch {
            /* ignore */
          }
        } else if (bounds.length === 1) {
          map.setView(bounds[0], 4);
        }
        const settle = () => map && !cancelled && map.invalidateSize();
        setTimeout(settle, 100);
        setTimeout(settle, 400);
      } catch {
        /* offline / Leaflet failed — the country stats still convey the spread */
      }
    })();
    return () => {
      cancelled = true;
      map?.remove();
    };
  }, [points]);
  return <div className="monitor-map" ref={ref} />;
}

/** Country of a monitored entry, best-effort across the enrichers. */
function countryOf(e: MonitorEntry): string | undefined {
  const r = e.result;
  return r?.maxmind?.countryCode ?? r?.abuseipdb?.countryCode ?? r?.shodan?.country ?? r?.ip?.country;
}

function StatTile({ n, label, tone, onPick }: { n: number; label: string; tone?: 'bad' | 'warn'; onPick?: () => void }) {
  return (
    <div
      className={`mon-stat${tone ? ` ${tone}` : ''}${onPick ? ' pickable' : ''}`}
      onClick={onPick}
      role={onPick ? 'button' : undefined}
      title={onPick ? 'クリックで対象IPを表示' : undefined}
    >
      <b>{n}</b>
      <span>{label}</span>
    </div>
  );
}

/** Horizontal bar list (country / CVE breakdowns). Rows are clickable when onPick is given. */
function BarList({
  title,
  rows,
  max,
  hrefFor,
  onPick,
}: {
  title: string;
  rows: [string, number][];
  max: number;
  hrefFor?: (k: string) => string;
  onPick?: (k: string) => void;
}) {
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
            title={onPick ? 'クリックで対象IPを表示' : undefined}
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

export function MonitorPage() {
  const monitors = useStore((s) => s.monitors);
  const mode = useStore((s) => s.mode);
  const setView = useStore((s) => s.setView);
  const refresh = useStore((s) => s.refreshMonitors);
  const reEnrich = useStore((s) => s.reEnrichMonitor);
  const remove = useStore((s) => s.removeMonitor);
  const check = useStore((s) => s.checkMonitor);
  const showResult = useStore((s) => s.showResult);
  const setGroup = useStore((s) => s.setMonitorGroup);
  const openAnalysis = useStore((s) => s.openAnalysis);
  const setAutoEnrich = useStore((s) => s.setAutoEnrich);
  const [drill, setDrill] = useState<{ label: string; values: string[] } | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [groupInput, setGroupInput] = useState('');
  const [mapGroup, setMapGroup] = useState('');
  const [collapsed, setCollapsed] = useState<Set<string>>(() => {
    try {
      const raw = localStorage.getItem('vteeee.monGroupsCollapsed');
      return new Set(raw ? (JSON.parse(raw) as string[]) : []);
    } catch {
      return new Set();
    }
  });
  function toggleCollapse(key: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      try {
        localStorage.setItem('vteeee.monGroupsCollapsed', JSON.stringify([...next]));
      } catch {
        /* ignore */
      }
      return next;
    });
  }

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const list = Object.values(monitors).sort((a, b) => b.addedAt - a.addedAt);
  // Drill-down: "which IPs are behind this stat?" — list them from a predicate over the watchlist.
  const pick = (label: string, pred: (e: MonitorEntry) => boolean) =>
    setDrill({ label, values: list.filter(pred).map((e) => e.ip) });

  // Overview roll-up.
  const total = list.length;
  const live = list.filter((e) => e.live).length;
  const withIntel = list.filter((e) => e.result).length;
  const malicious = list.filter((e) => e.result?.verdict === 'malicious').length;
  const suspicious = list.filter((e) => e.result?.verdict === 'suspicious').length;
  const highAbuse = list.filter((e) => (e.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length;
  const changedCount = list.filter((e) => e.check?.changed).length;

  // Country breakdown (for the "countries" stat tile; the grouped bars/heatmap use mapCounts below).
  const byCountry = new Map<string, number>();
  for (const e of list) {
    const cc = countryOf(e);
    if (cc) byCountry.set(cc, (byCountry.get(cc) ?? 0) + 1);
  }

  // Vulnerability breakdown (Shodan CVEs across the monitored hosts).
  const byCve = new Map<string, number>();
  let hostsWithCves = 0;
  for (const e of list) {
    const vulns = e.result?.shodan?.vulns;
    if (vulns && vulns.length) {
      hostsWithCves++;
      for (const cve of vulns) byCve.set(cve, (byCve.get(cve) ?? 0) + 1);
    }
  }
  const cves = [...byCve.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  const maxCve = cves[0]?.[1] ?? 1;

  // Map points (need coordinates → MaxMind).
  const points = list.flatMap((e) => {
    const m = e.result?.maxmind;
    return m?.latitude != null && m?.longitude != null
      ? [{ lat: m.latitude, lon: m.longitude, ip: e.ip, verdict: e.result?.verdict }]
      : [];
  });

  const checkedList = list.filter((e) => checked.has(e.ip));
  const allChecked = list.length > 0 && list.every((e) => checked.has(e.ip));
  function toggle(ip: string) {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip);
      else next.add(ip);
      return next;
    });
  }
  function toggleAll() {
    setChecked((prev) => (list.every((e) => prev.has(e.ip)) ? new Set() : new Set(list.map((e) => e.ip))));
  }
  function bulkRemove() {
    if (!checkedList.length) return;
    if (!window.confirm(`Stop monitoring ${checkedList.length} IP(s)?`)) return;
    checkedList.forEach((e) => void remove(e.ip));
    setChecked(new Set());
  }
  function bulkReEnrich() {
    checkedList.forEach((e) => void reEnrich(e.ip));
  }
  function bulkCheck() {
    checkedList.forEach((e) => void check(e.ip));
  }

  // --- Grouping: named groups become top-level sections with the IPs nested underneath. ----------
  const UNGROUPED = '__vteeee_ungrouped__';
  const groupNames = [...new Set(list.map((e) => e.group).filter((g): g is string => !!g))].sort((a, b) =>
    a.localeCompare(b),
  );
  const hasGroups = groupNames.length > 0;
  const buckets: { key: string; name: string | null; entries: MonitorEntry[] }[] = groupNames.map((g) => ({
    key: g,
    name: g,
    entries: list.filter((e) => e.group === g),
  }));
  const ungrouped = list.filter((e) => !e.group);
  if (ungrouped.length) buckets.push({ key: UNGROUPED, name: null, entries: ungrouped });

  // Country heatmap: aggregate a chosen group's IPs by country (darker = more) for the choropleth.
  const mapEntries =
    !mapGroup ? list : mapGroup === UNGROUPED ? ungrouped : list.filter((e) => e.group === mapGroup);
  const mapCounts: Record<string, number> = {};
  for (const e of mapEntries) {
    const cc = countryOf(e);
    if (cc) mapCounts[cc] = (mapCounts[cc] ?? 0) + 1;
  }
  const mapCountryN = Object.keys(mapCounts).length;
  const mapCountryRows = Object.entries(mapCounts).sort((a, b) => b[1] - a[1]).slice(0, 10) as [string, number][];
  const mapCountryMax = mapCountryRows[0]?.[1] ?? 1;

  /** Select / deselect every IP in one group at once (drives the per-group checkbox). */
  function groupToggle(entries: MonitorEntry[]) {
    setChecked((prev) => {
      const next = new Set(prev);
      const all = entries.length > 0 && entries.every((e) => next.has(e.ip));
      entries.forEach((e) => (all ? next.delete(e.ip) : next.add(e.ip)));
      return next;
    });
  }
  /** Assign the checked IPs to the typed group (blank = ungroup). */
  function assignGroup() {
    if (!checkedList.length) return;
    void setGroup(
      checkedList.map((e) => e.ip),
      groupInput,
    );
    setGroupInput('');
    setChecked(new Set());
  }
  function renameGroup(name: string) {
    const nn = window.prompt(`Rename group “${name}” → (blank = ungroup):`, name);
    if (nn == null) return;
    void setGroup(
      list.filter((e) => e.group === name).map((e) => e.ip),
      nn,
    );
  }
  function ungroupAll(name: string) {
    void setGroup(
      list.filter((e) => e.group === name).map((e) => e.ip),
      undefined,
    );
  }

  function renderRow(e: MonitorEntry) {
    const r = e.result;
    const abuse = r?.abuseipdb?.abuseConfidenceScore;
    const abuseCls = abuse == null ? '' : abuse >= 75 ? 'sev-high' : abuse >= 25 ? 'sev-med' : 'sev-low';
    const cc = countryOf(e);
    // Row-level enrichment trend: mini sparklines for metrics that vary + the "vs previous" diff.
    const histAsc = e.history && e.history.length ? [...e.history].sort((a, b) => a.at - b.at) : [];
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
      <li key={e.ip} className="monitor-row">
        <input
          type="checkbox"
          className="mon-cb"
          checked={checked.has(e.ip)}
          onChange={() => toggle(e.ip)}
          aria-label={`Select ${e.ip}`}
        />
        <div className="mon-main">
          <div className="mon-top">
            <span className="mon-ip mono">{e.ip}</span>
            {e.live ? (
              <span className="mon-badge live">● monitoring</span>
            ) : e.error ? (
              <span className="mon-badge err" title={e.error}>
                ⚠ not registered
              </span>
            ) : (
              <span className="mon-badge">…</span>
            )}
            {e.triggers?.length ? <span className="mon-trig">triggers: {e.triggers.join(', ')}</span> : null}
            <span className="mon-when">added {new Date(e.addedAt).toLocaleDateString()}</span>
            <span className="mon-row-grouping">
              <span className="mon-row-group-label">group:</span>
              <select
                className="mon-row-group"
                value={e.group ?? ''}
                onChange={(ev) => {
                  const sel = ev.currentTarget;
                  const v = sel.value;
                  if (v === '__new__') {
                    const name = window.prompt(`New group name for ${e.ip}:`, '');
                    if (name != null) void setGroup([e.ip], name);
                  } else {
                    void setGroup([e.ip], v || undefined);
                  }
                  // Resync the control to the source of truth so a cancelled "＋ New group…" doesn't stick.
                  sel.value = e.group ?? '';
                }}
                title={e.group ? `Group: ${e.group}` : 'Put this IP in a group (＋ New group… to create one)'}
                aria-label={`Group for ${e.ip}`}
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
              {r.detection && <span className="mon-chip">det {detectionRatio(r)}</span>}
              {r.shodan?.ports?.length ? <span className="mon-chip mono">{r.shodan.ports.length} ports</span> : null}
              {r.shodan?.vulns?.length ? <span className="mon-chip sev-high">{r.shodan.vulns.length} CVE</span> : null}
              {abuse != null && <span className={`mon-chip ${abuseCls}`}>abuse {abuse}</span>}
              {r.recordedfuture?.riskScore != null && <span className="mon-chip">RF {r.recordedfuture.riskScore}</span>}
              {cc && <span className="mon-chip">{cc}</span>}
            </span>
          ) : (
            <span className="mon-nointel">no enrichment yet — press “Re-enrich”</span>
          )}
          {histAsc.length >= 2 && (
            <div className="mon-trend">
              {sparks.length > 0 && (
                <span className="mon-sparks">
                  {sparks.map(({ k, series }) => (
                    <span key={k} className="mon-spark-item" title={`${k} trend · ${series.length} pts`}>
                      <span className="mon-spark-label">{k}</span>
                      <Spark className="mon-spark" values={series} w={46} h={16} />
                    </span>
                  ))}
                </span>
              )}
              {trendChanges.length > 0 && <span className="mon-trend-diff">↗ 前回比: {trendChanges.join(' · ')}</span>}
            </div>
          )}
          {e.check && (
            <div className={`mon-check${e.check.changed ? ' changed' : ''}`}>
              {e.check.error
                ? `check failed: ${e.check.error}`
                : e.check.changed
                  ? `▲ change — ${[
                      e.check.newPorts.length ? `+ports ${e.check.newPorts.join(', ')}` : '',
                      e.check.gonePorts.length ? `−ports ${e.check.gonePorts.join(', ')}` : '',
                      e.check.newVulns.length
                        ? `+CVE ${e.check.newVulns.slice(0, 4).join(', ')}${e.check.newVulns.length > 4 ? '…' : ''}`
                        : '',
                    ]
                      .filter(Boolean)
                      .join(' · ')}`
                  : '✓ no change since baseline'}
              <span className="mon-check-when"> · checked {new Date(e.check.at).toLocaleString()}</span>
            </div>
          )}
          {e.error && <div className="mon-err">{e.error}</div>}
        </div>
        <div className="mon-actions">
          <button className="btn btn-sm" disabled={!r} onClick={() => r && showResult(r)}>
            Open
          </button>
          {((e.history?.length ?? 0) > 0 || !!e.result) && (
            <button
              className="btn btn-sm"
              onClick={() => openAnalysis(e.ip)}
              title="Enrichment analysis — トレンド・指標マトリクス・2点比較・タイムライン"
            >
              📈 Analysis{(e.history?.length ?? 0) > 1 ? ` (${e.history!.length})` : ''}
            </button>
          )}
          <button
            className="btn btn-sm"
            disabled={e.checking}
            onClick={() => void check(e.ip)}
            title="Re-observe on Shodan now and diff vs. baseline (the monitoring result)"
          >
            {e.checking ? 'Checking…' : 'Check'}
          </button>
          <button className="btn btn-sm" disabled={e.enriching} onClick={() => void reEnrich(e.ip)}>
            {e.enriching ? 'Enriching…' : 'Re-enrich'}
          </button>
          <button
            className={`btn btn-sm${e.autoEnrich ? ' btn-primary' : ''}`}
            onClick={() => void setAutoEnrich([e.ip], !e.autoEnrich)}
            title={
              e.autoEnrich
                ? '自動エンリッチ ON（週1→2週→月次…と年代連動の間隔で自動Re-enrich・vteeeeを開いている間）— クリックでOFF'
                : '自動エンリッチ OFF — クリックでON（監視期間に応じた間隔で定点観測）'
            }
          >
            ⚡ Auto{e.autoEnrich ? ' ✓' : ''}
          </button>
          <a
            className="btn btn-sm"
            href={`https://www.shodan.io/host/${encodeURIComponent(e.ip)}`}
            target="_blank"
            rel="noreferrer"
          >
            Shodan ↗
          </a>
          <button className="btn btn-sm btn-danger" onClick={() => void remove(e.ip)}>
            Remove
          </button>
        </div>
      </li>
    );
  }

  /** One group section: a collapsible header (checkbox · name · roll-up) with the IP rows nested. */
  function renderGroup(b: { key: string; name: string | null; entries: MonitorEntry[] }) {
    const all = b.entries.length > 0 && b.entries.every((e) => checked.has(e.ip));
    const some = b.entries.some((e) => checked.has(e.ip));
    const isCol = collapsed.has(b.key);
    const mal = b.entries.filter((e) => e.result?.verdict === 'malicious').length;
    const sus = b.entries.filter((e) => e.result?.verdict === 'suspicious').length;
    const chg = b.entries.filter((e) => e.check?.changed).length;
    return (
      <div className="mon-group" key={b.key}>
        <div className="mon-group-head">
          <input
            type="checkbox"
            className="mon-cb"
            checked={all}
            ref={(el) => {
              if (el) el.indeterminate = some && !all;
            }}
            onChange={() => groupToggle(b.entries)}
            aria-label={b.name ? `Select all in ${b.name}` : 'Select all ungrouped'}
          />
          <button
            className="mon-group-toggle"
            onClick={() => toggleCollapse(b.key)}
            aria-label={isCol ? 'Expand group' : 'Collapse group'}
            title={isCol ? 'Expand' : 'Collapse'}
          >
            {isCol ? '▸' : '▾'}
          </button>
          {b.name ? (
            <button
              className="mon-group-name mon-group-name-btn"
              onClick={() => renameGroup(b.name!)}
              title="クリックで名称変更 / rename this group"
            >
              {b.name} <span className="mon-group-edit" aria-hidden>✎</span>
            </button>
          ) : (
            <span className="mon-group-name ungrouped">Ungrouped</span>
          )}
          <span className="mon-group-count">{b.entries.length} IP{b.entries.length === 1 ? '' : 's'}</span>
          <span className="mon-group-sum">
            {mal > 0 && <span className="mon-chip sev-high">{mal} mal</span>}
            {sus > 0 && <span className="mon-chip sev-med">{sus} susp</span>}
            {chg > 0 && <span className="mon-chip sev-med">{chg} changed</span>}
          </span>
          {b.name && (
            <span className="mon-group-actions">
              <button
                className="btn btn-sm btn-ghost"
                onClick={() => ungroupAll(b.name!)}
                title="Remove every IP from this group"
              >
                Ungroup
              </button>
            </span>
          )}
        </div>
        {!isCol && <ul className="monitor-list">{b.entries.map(renderRow)}</ul>}
      </div>
    );
  }

  return (
    <section className="panel monitor-page">
      <div className="panel-head">
        <button className="btn btn-sm" onClick={() => setView('app')} title="Back to search">
          ← Back
        </button>
        <h2>IP-Mon — dashboard</h2>
        <div className="spacer" />
        <a className="btn btn-sm" href="https://monitor.shodan.io/dashboard" target="_blank" rel="noreferrer">
          Shodan Monitor ↗
        </a>
        <button
          className="btn btn-sm"
          onClick={() => void refresh()}
          title="Two-way sync: upload THIS browser's saved intel to the shared team watchlist + pull the team's"
        >
          ⇪ Sync / Share all
        </button>
      </div>

      <p className="hint mon-intro">
        監視IPは Shodan の<b>ネットワークアラート（サーバ側）</b>として登録され、Shodan が変化を監視し続けます。ここには
        <b>各IPの最新 vteeee エンリッチ結果</b>も保存されるので、<b>翌日でも intel ごと</b>確認できます（地図・国別・脆弱性の集計付き）。
        各行の <b>Check</b>（または一括）で、<b>監視開始時からの Shodan の変化</b>（新規ポート／閉じたポート／新規CVE）＝<b>監視結果</b>を表示します。
        IPが増えたら<b>任意の名称でグループ分け</b>できます。各行の <b>group:</b> セレクトで1件ずつ割当／移動／解除（<b>＋ New group…</b> で新規作成）、
        または複数行をチェックして下の <b>Set group</b> で一括。グループ見出しは<b>名前クリックで改名</b>、見出しのチェックで<b>グループ単位の選択</b>・折りたたみ・Ungroup。グループはチームにも共有されます。
        各行の <b>📈 Analysis</b> でエンリッチ履歴のトレンド・指標マトリクス・2点比較。各行の <b>⚡ Auto</b>（複数は <b>⚡ Auto on</b>）で
        <b>自動エンリッチ</b>＝監視期間に応じた間隔（直近1週≒日次→2週→3–4週→5–6週→以降は月次の定点観測）で自動Re-enrich（<b>Liveモードで vteeee を開いている間</b>）。
        {mode !== 'demo' && (
          <>
            {' '}
            共有ON時は<b>このページを開く／⇪ Sync で双方向同期</b>され、<b>この端末に保存済みの intel がチームへ共有</b>されます
            （intel を持つ端末で一度開いてください）。
          </>
        )}
        {mode === 'demo' && (
          <>
            {' '}
            <b>（この端末はプロキシ未接続＝demo表示です）</b> 別端末で共有中の監視リストがここに出ない場合、この端末が未接続です。
            設定済みの端末で <b>Settings →「Connect another device」→ Copy setup link</b> を押し、そのリンクを<b>この端末で開く</b>と
            接続が引き継がれて共有リストが表示されます（または Settings にプロキシURL＋アクセストークンを入力）。
          </>
        )}
      </p>

      {total === 0 ? (
        <div className="empty-state">
          まだ監視IPはありません。検索結果テーブルの <b>Monitor</b> か、詳細ページの <b>☆ Monitor</b> で登録してください。
          <br />
          No monitored IPs yet — tick “Monitor” in the results table, or ☆ Monitor from an IP's detail.
        </div>
      ) : (
        <>
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
                  {drill.values.map((ip) => (
                    <button
                      key={ip}
                      className="cp-drill-ioc mono"
                      onClick={() => {
                        const e = monitors[ip];
                        if (e?.result) showResult(e.result);
                      }}
                      title="詳細を開く"
                    >
                      {ip}
                    </button>
                  ))}
                </div>
              ) : (
                <div className="hint">該当なし</div>
              )}
            </div>
          )}
          <div className="mon-stats" role="group" aria-label="overview">
            <StatTile n={total} label="monitored" onPick={() => pick('monitored', () => true)} />
            <StatTile n={live} label="live on Shodan" onPick={() => pick('live on Shodan', (e) => !!e.live)} />
            <StatTile n={withIntel} label="with intel" onPick={() => pick('with intel', (e) => !!e.result)} />
            {malicious > 0 && (
              <StatTile n={malicious} label="malicious" tone="bad" onPick={() => pick('malicious', (e) => e.result?.verdict === 'malicious')} />
            )}
            {suspicious > 0 && (
              <StatTile n={suspicious} label="suspicious" tone="warn" onPick={() => pick('suspicious', (e) => e.result?.verdict === 'suspicious')} />
            )}
            {highAbuse > 0 && (
              <StatTile n={highAbuse} label="abuse ≥75" tone="bad" onPick={() => pick('abuse ≥75', (e) => (e.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75)} />
            )}
            {hostsWithCves > 0 && (
              <StatTile n={hostsWithCves} label="hosts w/ CVEs" tone="warn" onPick={() => pick('hosts w/ CVEs', (e) => (e.result?.shodan?.vulns?.length ?? 0) > 0)} />
            )}
            {byCve.size > 0 && <StatTile n={byCve.size} label="distinct CVEs" />}
            {changedCount > 0 && (
              <StatTile n={changedCount} label="changed since baseline" tone="warn" onPick={() => pick('changed since baseline', (e) => !!e.check?.changed)} />
            )}
            <StatTile n={byCountry.size} label="countries" />
          </div>

          {/* Two map panels side by side on desktop (stacked on mobile): host overview (top CVEs +
              location map) and the country stats + heatmap. */}
          <div className="mon-geo-row">
          <div className="mon-geo">
            <div className="mon-choro-head">
              <div className="mon-bars-title">監視ホスト — 上位CVE ＆ ロケーション</div>
            </div>
            <div className="mon-geo-body">
              <div className="mon-geo-stats">
                <BarList
                  title="Top vulnerabilities (CVE)"
                  rows={cves}
                  max={maxCve}
                  hrefFor={(cve) => `https://nvd.nist.gov/vuln/detail/${cve}`}
                  onPick={(cve) => pick(`CVE ${cve}`, (e) => e.result?.shodan?.vulns?.includes(cve) ?? false)}
                />
              </div>
              <div className="mon-geo-map">
                {points.length > 0 ? (
                  <>
                    <div className="mon-geo-maplabel">Monitored locations</div>
                    <MonitorMap points={points} />
                  </>
                ) : (
                  <div className="hint mon-nomap-note">
                    🗺 監視地図は MaxMind の座標が必要です（各IPを <b>Re-enrich</b> するか MaxMind 有効化で表示）。
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="mon-geo">
            <div className="mon-choro-head">
              <div className="mon-bars-title">国別 — 統計 ＋ ヒートマップ（多いほど濃い）</div>
              {hasGroups && (
                <select
                  className="filter mon-choro-group"
                  value={mapGroup}
                  onChange={(e) => setMapGroup(e.target.value)}
                  aria-label="Group for the country stats + heatmap"
                  title="集計するグループを選択"
                >
                  <option value="">All groups</option>
                  {groupNames.map((g) => (
                    <option key={g} value={g}>
                      {g}
                    </option>
                  ))}
                  {ungrouped.length > 0 && <option value={UNGROUPED}>Ungrouped</option>}
                </select>
              )}
              <span className="mon-choro-count">
                {mapEntries.length} IP{mapEntries.length === 1 ? '' : 's'} · {mapCountryN} countries
              </span>
            </div>
            <div className="mon-geo-body">
              <div className="mon-geo-stats">
                <BarList
                  title="By country"
                  rows={mapCountryRows}
                  max={mapCountryMax}
                  onPick={(cc) => pick(`国: ${cc}`, (e) => countryOf(e) === cc)}
                />
              </div>
              <div className="mon-geo-map">
                <CountryChoropleth
                  counts={mapCounts}
                  height={250}
                  onPick={(iso, name) =>
                    pick(`国: ${name} (${iso})`, (e) => {
                      const cc = countryOf(e);
                      if (!cc) return false;
                      const u = cc.toUpperCase();
                      return u === iso || u === name.toUpperCase();
                    })
                  }
                />
              </div>
            </div>
          </div>
          </div>

          <div className="mon-bulkbar">
            <label className="mon-selall">
              <input type="checkbox" checked={allChecked} onChange={toggleAll} />
              select all
            </label>
            <div className="mon-group-assign">
              <input
                className="filter mon-group-input"
                list="mon-group-names"
                placeholder="group name…"
                value={groupInput}
                onChange={(e) => setGroupInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && assignGroup()}
                aria-label="Group name for the checked IPs"
              />
              <datalist id="mon-group-names">
                {groupNames.map((g) => (
                  <option key={g} value={g} />
                ))}
              </datalist>
              <button
                className="btn btn-sm"
                disabled={!checkedList.length}
                onClick={assignGroup}
                title={
                  checkedList.length
                    ? 'Assign the checked IP(s) to this group (blank = ungroup)'
                    : 'Tick IP rows first, then group them'
                }
              >
                Set group{checkedList.length ? ` (${checkedList.length})` : ''}
              </button>
            </div>
            <span className="spacer" />
            <button
              className="btn btn-sm"
              disabled={!checkedList.length}
              onClick={bulkCheck}
              title="Re-observe on Shodan and diff vs. baseline (uses 1 query credit each)"
            >
              Check selected{checkedList.length ? ` (${checkedList.length})` : ''}
            </button>
            <button className="btn btn-sm" disabled={!checkedList.length} onClick={bulkReEnrich}>
              Re-enrich selected{checkedList.length ? ` (${checkedList.length})` : ''}
            </button>
            <button
              className="btn btn-sm"
              disabled={!checkedList.length}
              onClick={() => void setAutoEnrich(checkedList.map((e) => e.ip), true)}
              title="選択IPの自動エンリッチをON（年代連動の間隔で自動Re-enrich）"
            >
              ⚡ Auto on{checkedList.length ? ` (${checkedList.length})` : ''}
            </button>
            <button
              className="btn btn-sm"
              disabled={!checkedList.length}
              onClick={() => void setAutoEnrich(checkedList.map((e) => e.ip), false)}
              title="選択IPの自動エンリッチをOFF"
            >
              Auto off
            </button>
            <button className="btn btn-sm btn-danger" disabled={!checkedList.length} onClick={bulkRemove}>
              Remove selected{checkedList.length ? ` (${checkedList.length})` : ''}
            </button>
          </div>

          {hasGroups ? (
            <div className="mon-groups">{buckets.map(renderGroup)}</div>
          ) : (
            <ul className="monitor-list">{list.map(renderRow)}</ul>
          )}
        </>
      )}
    </section>
  );
}
