import { Fragment, useEffect, useMemo, useState } from 'react';
import type { NormalizedResult } from '@vteeee/shared';
import { useStore } from '../state/store';
import { VerdictBadge } from './Badges';

function countryOf(r: NormalizedResult): string {
  return r.maxmind?.countryCode ?? r.abuseipdb?.countryCode ?? r.shodan?.country ?? r.ip?.country ?? '';
}
const detOf = (r: NormalizedResult) => (r.detection?.malicious ?? 0) + (r.detection?.suspicious ?? 0);
const abuseOf = (r: NormalizedResult) => r.abuseipdb?.abuseConfidenceScore ?? null;
const rfOf = (r: NormalizedResult) => r.recordedfuture?.riskScore ?? null;
const portsOf = (r: NormalizedResult) => r.shodan?.ports?.length ?? 0;
const cvesOf = (r: NormalizedResult) => r.shodan?.vulns?.length ?? 0;

/** Tiny inline SVG sparkline for a numeric series over time. */
function Spark({ values }: { values: (number | null)[] }) {
  const w = 128;
  const h = 30;
  const pad = 3;
  const nums = values.map((v) => (v == null ? 0 : v));
  const max = Math.max(1, ...nums);
  const min = Math.min(0, ...nums);
  const range = max - min || 1;
  const n = nums.length;
  const pt = (v: number, i: number): [number, number] => {
    const x = n <= 1 ? w / 2 : pad + (i / (n - 1)) * (w - 2 * pad);
    const y = pad + (1 - (v - min) / range) * (h - 2 * pad);
    return [x, y];
  };
  const line = nums.map((v, i) => pt(v, i).join(',')).join(' ');
  const [lx, ly] = pt(nums[n - 1] ?? 0, n - 1);
  return (
    <svg className="ana-spark" width={w} height={h} viewBox={`0 0 ${w} ${h}`} aria-hidden>
      {n > 1 && <polyline points={line} fill="none" stroke="currentColor" strokeWidth="1.5" />}
      <circle cx={lx} cy={ly} r="2.5" fill="currentColor" />
    </svg>
  );
}

/** Human-readable "what changed" between two snapshots (cur vs prev). */
function diffParts(cur: NormalizedResult, prev: NormalizedResult): string[] {
  const parts: string[] = [];
  if (prev.verdict !== cur.verdict) parts.push(`verdict ${prev.verdict}→${cur.verdict}`);
  if (detOf(prev) !== detOf(cur) || (prev.detection?.total ?? 0) !== (cur.detection?.total ?? 0))
    parts.push(`det ${detOf(prev)}/${prev.detection?.total ?? 0}→${detOf(cur)}/${cur.detection?.total ?? 0}`);
  if (abuseOf(prev) !== abuseOf(cur)) parts.push(`abuse ${abuseOf(prev) ?? '—'}→${abuseOf(cur) ?? '—'}`);
  if (rfOf(prev) !== rfOf(cur)) parts.push(`RF ${rfOf(prev) ?? '—'}→${rfOf(cur) ?? '—'}`);
  const setD = (prevArr?: (number | string)[], curArr?: (number | string)[], label = '') => {
    const p = new Set(prevArr ?? []);
    const c = new Set(curArr ?? []);
    const add = [...c].filter((x) => !p.has(x));
    const gone = [...p].filter((x) => !c.has(x));
    if (add.length) parts.push(`+${label} ${add.slice(0, 5).join(',')}${add.length > 5 ? '…' : ''}`);
    if (gone.length) parts.push(`−${label} ${gone.slice(0, 5).join(',')}${gone.length > 5 ? '…' : ''}`);
  };
  setD(prev.shodan?.ports, cur.shodan?.ports, 'ports');
  setD(prev.shodan?.vulns, cur.shodan?.vulns, 'CVE');
  if (countryOf(prev) !== countryOf(cur)) parts.push(`country ${countryOf(prev) || '—'}→${countryOf(cur) || '—'}`);
  return parts;
}

interface MatrixRow {
  label: string;
  get: (r: NormalizedResult) => string;
  num?: (r: NormalizedResult) => number | null;
}
const MATRIX: MatrixRow[] = [
  { label: 'Verdict', get: (r) => r.verdict },
  { label: 'Detections', get: (r) => `${detOf(r)}/${r.detection?.total ?? 0}`, num: detOf },
  { label: 'Reputation', get: (r) => (r.reputation != null ? String(r.reputation) : '—'), num: (r) => r.reputation ?? null },
  { label: 'GTI', get: (r) => [r.gti?.verdict, r.gti?.threatScore].filter((x) => x != null).join(' ') || '—' },
  { label: 'Abuse', get: (r) => (abuseOf(r) != null ? String(abuseOf(r)) : '—'), num: abuseOf },
  { label: 'RF risk', get: (r) => (rfOf(r) != null ? String(rfOf(r)) : '—'), num: rfOf },
  { label: 'Open ports', get: (r) => String(portsOf(r)), num: portsOf },
  { label: 'CVEs', get: (r) => String(cvesOf(r)), num: cvesOf },
  { label: 'Country', get: (r) => countryOf(r) || '—' },
];

interface FieldDef {
  label: string;
  get: (r: NormalizedResult) => string;
}
const FIELD_GROUPS: { group: string; fields: FieldDef[] }[] = [
  {
    group: 'VirusTotal',
    fields: [
      { label: 'Verdict', get: (r) => r.verdict },
      { label: 'Status', get: (r) => r.status },
      {
        label: 'Detections (mal/susp/harm/undet of total)',
        get: (r) =>
          r.detection
            ? `${r.detection.malicious}/${r.detection.suspicious}/${r.detection.harmless}/${r.detection.undetected} of ${r.detection.total}`
            : '',
      },
      { label: 'Reputation', get: (r) => (r.reputation != null ? String(r.reputation) : '') },
      { label: 'Tags', get: (r) => (r.tags ?? []).join(', ') },
    ],
  },
  {
    group: 'GTI',
    fields: [
      { label: 'Verdict', get: (r) => r.gti?.verdict ?? '' },
      { label: 'Severity', get: (r) => r.gti?.severity ?? '' },
      { label: 'Threat score', get: (r) => (r.gti?.threatScore != null ? String(r.gti.threatScore) : '') },
    ],
  },
  {
    group: 'AbuseIPDB',
    fields: [
      { label: 'Abuse score', get: (r) => (r.abuseipdb?.abuseConfidenceScore != null ? `${r.abuseipdb.abuseConfidenceScore}/100` : '') },
      { label: 'Reports', get: (r) => (r.abuseipdb?.totalReports != null ? String(r.abuseipdb.totalReports) : '') },
      { label: 'Reporters', get: (r) => (r.abuseipdb?.numDistinctUsers != null ? String(r.abuseipdb.numDistinctUsers) : '') },
      { label: 'Usage type', get: (r) => r.abuseipdb?.usageType ?? '' },
      { label: 'Categories', get: (r) => (r.abuseipdb?.categories ?? []).join(', ') },
    ],
  },
  {
    group: 'Shodan',
    fields: [
      { label: 'Open ports', get: (r) => (r.shodan?.ports ?? []).join(', ') },
      { label: 'CVEs', get: (r) => (r.shodan?.vulns ?? []).join(', ') },
      { label: 'Org', get: (r) => r.shodan?.org ?? '' },
      { label: 'OS', get: (r) => r.shodan?.os ?? '' },
      { label: 'Hostnames', get: (r) => (r.shodan?.hostnames ?? []).join(', ') },
    ],
  },
  { group: 'Recorded Future', fields: [{ label: 'Risk score', get: (r) => (r.recordedfuture?.riskScore != null ? String(r.recordedfuture.riskScore) : '') }] },
  {
    group: 'Geo / Network',
    fields: [
      { label: 'Country', get: (r) => countryOf(r) },
      { label: 'City', get: (r) => r.maxmind?.city ?? '' },
      { label: 'ASN', get: (r) => (r.maxmind?.asn != null ? `AS${r.maxmind.asn}` : r.ip?.asn ? String(r.ip.asn) : '') },
      { label: 'Org / owner', get: (r) => r.maxmind?.organization ?? r.shodan?.org ?? r.ip?.asOwner ?? '' },
      { label: 'Anonymizer (VPN/Tor/proxy)', get: (r) => (r.maxmind?.anonymizerType ?? []).join(', ') },
    ],
  },
];

export function MonitorAnalysisPage() {
  const ip = useStore((s) => s.analysisIp);
  const entry = useStore((s) => (ip ? s.monitors[ip] : undefined));
  const setView = useStore((s) => s.setView);
  const showResult = useStore((s) => s.showResult);
  const reEnrich = useStore((s) => s.reEnrichMonitor);

  // Ascending timeline (oldest → newest); seed the current result as a single point if no history yet.
  const points = useMemo(() => {
    const raw = entry?.history?.length
      ? entry.history
      : entry?.result
        ? [{ at: entry.updatedAt, by: undefined as string | undefined, result: entry.result }]
        : [];
    return [...raw].sort((a, b) => a.at - b.at);
  }, [entry]);
  const n = points.length;

  // Compare selectors: default previous vs latest.
  const [ai, setAi] = useState(0);
  const [bi, setBi] = useState(0);
  useEffect(() => {
    setBi(n > 0 ? n - 1 : 0);
    setAi(n > 1 ? n - 2 : 0);
  }, [ip, n]);

  if (!ip || !entry) {
    return (
      <section className="panel monitor-page">
        <div className="panel-head">
          <button className="btn btn-sm" onClick={() => setView('monitor')}>
            ← Back
          </button>
          <h2>Enrichment analysis</h2>
        </div>
        <div className="empty-state">この監視IPは見つかりませんでした。IP-Mon に戻ってください。</div>
      </section>
    );
  }

  const contributors = [...new Set(points.map((p) => p.by).filter((x): x is string => !!x))];
  const A = points[Math.min(ai, n - 1)]?.result;
  const B = points[Math.min(bi, n - 1)]?.result;

  return (
    <section className="panel monitor-page ana-page">
      <div className="panel-head">
        <button className="btn btn-sm" onClick={() => setView('monitor')} title="Back to IP-Mon">
          ← Back
        </button>
        <h2>
          Enrichment analysis · <span className="mono">{ip}</span>
        </h2>
        <div className="spacer" />
        <button className="btn btn-sm" disabled={entry.enriching} onClick={() => void reEnrich(ip)}>
          {entry.enriching ? 'Enriching…' : 'Re-enrich now'}
        </button>
      </div>

      <p className="hint mon-intro">
        Re-enrich は過去を捨てず、<b>状態が変化した地点</b>をタイムラインに蓄積します（{entry.group ? `group: ${entry.group} · ` : ''}
        <b>{n}</b> 地点{contributors.length ? ` · by ${contributors.join(', ')}` : ''}
        {n > 0 ? ` · ${new Date(points[0].at).toLocaleDateString()} 〜 ${new Date(points[n - 1].at).toLocaleDateString()}` : ''}）。
        古い点は年代間引き（直近1週≒日次→以降は月次まで）。
      </p>

      {n === 0 ? (
        <div className="empty-state">
          まだエンリッチ結果がありません。<b>Re-enrich now</b> で最初のスナップショットを取得してください。
        </div>
      ) : (
        <>
          {/* ---- Trends ---- */}
          <div className="ana-section-title">Trends</div>
          <div className="ana-trends">
            {(
              [
                { k: 'Detections', num: detOf, fmt: (v: number | null) => `${v ?? 0}` },
                { k: 'Abuse', num: abuseOf, fmt: (v: number | null) => (v == null ? '—' : `${v}/100`) },
                { k: 'RF risk', num: rfOf, fmt: (v: number | null) => (v == null ? '—' : `${v}`) },
                { k: 'Open ports', num: portsOf, fmt: (v: number | null) => `${v ?? 0}` },
                { k: 'CVEs', num: cvesOf, fmt: (v: number | null) => `${v ?? 0}` },
              ] as const
            ).map((m) => {
              const series = points.map((p) => m.num(p.result));
              const first = series[0];
              const last = series[n - 1];
              const delta = last != null && first != null ? last - first : null;
              return (
                <div key={m.k} className="ana-trend">
                  <div className="ana-trend-top">
                    <span className="ana-trend-label">{m.k}</span>
                    <b className="ana-trend-val">{m.fmt(last)}</b>
                  </div>
                  <Spark values={series} />
                  {delta != null && delta !== 0 && (
                    <span className={`ana-trend-delta ${delta > 0 ? 'up' : 'down'}`}>
                      {delta > 0 ? '▲' : '▼'} {Math.abs(delta)} since first
                    </span>
                  )}
                </div>
              );
            })}
          </div>

          {/* ---- Metrics over time (matrix) ---- */}
          <div className="ana-section-title">Metrics over time</div>
          <div className="ana-matrix-wrap">
            <table className="ana-matrix">
              <thead>
                <tr>
                  <th className="ana-metric-col">metric</th>
                  <th className="ana-spark-col">trend</th>
                  {points.map((p, i) => (
                    <th key={p.at} className={i === n - 1 ? 'ana-latest-col' : undefined}>
                      {new Date(p.at).toLocaleDateString()}
                      {i === n - 1 ? ' ·now' : ''}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {MATRIX.map((row) => (
                  <tr key={row.label}>
                    <td className="ana-metric-col">{row.label}</td>
                    <td className="ana-spark-col">{row.num && <Spark values={points.map((p) => row.num!(p.result))} />}</td>
                    {points.map((p, i) => {
                      const v = row.get(p.result);
                      const prev = i > 0 ? row.get(points[i - 1].result) : v;
                      return (
                        <td key={p.at} className={i > 0 && v !== prev ? 'ana-changed mono' : 'mono'}>
                          {v}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* ---- Compare two points ---- */}
          <div className="ana-section-title">Compare two points</div>
          {n < 2 ? (
            <div className="hint">スナップショットが1点のみです。<b>Re-enrich</b> を重ねると差分比較できます。</div>
          ) : (
            <>
              <div className="ana-compare-controls">
                <label>
                  A{' '}
                  <select value={ai} onChange={(e) => setAi(Number(e.target.value))}>
                    {points.map((p, i) => (
                      <option key={p.at} value={i}>
                        {new Date(p.at).toLocaleString()}
                        {p.by ? ` · ${p.by}` : ''}
                      </option>
                    ))}
                  </select>
                </label>
                <span className="ana-arrow">→</span>
                <label>
                  B{' '}
                  <select value={bi} onChange={(e) => setBi(Number(e.target.value))}>
                    {points.map((p, i) => (
                      <option key={p.at} value={i}>
                        {new Date(p.at).toLocaleString()}
                        {p.by ? ` · ${p.by}` : ''}
                        {i === n - 1 ? ' · now' : ''}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              {A && B && (
                <table className="ana-compare">
                  <thead>
                    <tr>
                      <th>field</th>
                      <th>A · {new Date(points[Math.min(ai, n - 1)].at).toLocaleString()}</th>
                      <th>B · {new Date(points[Math.min(bi, n - 1)].at).toLocaleString()}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {FIELD_GROUPS.map((grp) => {
                      const rows = grp.fields
                        .map((f) => ({ label: f.label, a: f.get(A), b: f.get(B) }))
                        .filter((r) => r.a !== '' || r.b !== '');
                      if (rows.length === 0) return null;
                      return (
                        <Fragment key={grp.group}>
                          <tr className="ana-compare-group">
                            <td colSpan={3}>{grp.group}</td>
                          </tr>
                          {rows.map((r) => {
                            const changed = r.a !== r.b;
                            return (
                              <tr key={grp.group + r.label} className={changed ? 'ana-changed-row' : undefined}>
                                <td>{r.label}</td>
                                <td className="mono">{r.a || '—'}</td>
                                <td className="mono">
                                  {r.b || '—'}
                                  {changed && <span className="ana-chg-dot" title="changed" />}
                                </td>
                              </tr>
                            );
                          })}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </>
          )}

          {/* ---- Timeline ---- */}
          <div className="ana-section-title">Timeline</div>
          <ol className="hist-timeline">
            {[...points].reverse().map((h, i, arr) => {
              const older = arr[i + 1];
              const changes = older ? diffParts(h.result, older.result) : [];
              const isLatest = i === 0;
              return (
                <li key={h.at} className={`hist-item${isLatest ? ' latest' : ''}`}>
                  <div className="hist-when">
                    <span className="hist-dot" aria-hidden />
                    <b>{new Date(h.at).toLocaleString()}</b>
                    {isLatest && <span className="hist-badge">current</span>}
                    {h.by && <span className="hist-by">by {h.by}</span>}
                    <span className="spacer" />
                    <button className="btn btn-sm" onClick={() => showResult(h.result)} title="Open this snapshot's full detail">
                      Open
                    </button>
                  </div>
                  <div className="hist-metrics">
                    <VerdictBadge verdict={h.result.verdict} status={h.result.status} />
                    <span className="mon-chip">
                      det {detOf(h.result)}/{h.result.detection?.total ?? 0}
                    </span>
                    {abuseOf(h.result) != null && <span className="mon-chip">abuse {abuseOf(h.result)}</span>}
                    {rfOf(h.result) != null && <span className="mon-chip">RF {rfOf(h.result)}</span>}
                    {portsOf(h.result) > 0 && <span className="mon-chip mono">{portsOf(h.result)} ports</span>}
                    {cvesOf(h.result) > 0 && <span className="mon-chip sev-high">{cvesOf(h.result)} CVE</span>}
                    {countryOf(h.result) && <span className="mon-chip">{countryOf(h.result)}</span>}
                  </div>
                  {changes.length > 0 && <div className="hist-diff changed">▲ vs 前回: {changes.join(' · ')}</div>}
                </li>
              );
            })}
          </ol>
        </>
      )}
    </section>
  );
}
