import { Fragment, useEffect, useMemo, useState } from 'react';
import type { NormalizedResult } from '@vteeee/shared';
import { VerdictBadge } from './Badges';
import { Spark } from './Spark';
import { abuseOf, countryOf, cvesOf, detOf, diffParts, portsOf, rfOf } from '../lib/enrichTrend';

/** One point on an enrichment timeline (an IP-Mon or CP-Mon IOC snapshot). */
export interface AnalysisPoint {
  at: number;
  by?: string;
  result: NormalizedResult;
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

/**
 * The reusable enrichment time-series analysis (Trends · Metrics-over-time matrix · A↔B compare ·
 * Timeline) over a list of {at, by, result} snapshots — shared by IP-Mon and CP-Mon. `resetKey`
 * identifies the subject (IP / IOC value) so the compare selectors reset when it changes.
 */
export function EnrichmentAnalysis({
  points,
  resetKey,
  showResult,
}: {
  points: AnalysisPoint[];
  resetKey: string;
  showResult: (r: NormalizedResult) => void;
}) {
  const asc = useMemo(() => [...points].sort((a, b) => a.at - b.at), [points]);
  const n = asc.length;
  const [ai, setAi] = useState(0);
  const [bi, setBi] = useState(0);
  useEffect(() => {
    setBi(n > 0 ? n - 1 : 0);
    setAi(n > 1 ? n - 2 : 0);
  }, [resetKey, n]);

  if (n === 0) {
    return (
      <div className="empty-state">
        まだエンリッチ結果がありません。<b>Re-enrich</b> を実行すると最初のスナップショットが記録されます。
      </div>
    );
  }
  const A = asc[Math.min(ai, n - 1)]?.result;
  const B = asc[Math.min(bi, n - 1)]?.result;

  return (
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
          const series = asc.map((p) => m.num(p.result));
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
              {asc.map((p, i) => (
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
                <td className="ana-spark-col">{row.num && <Spark values={asc.map((p) => row.num!(p.result))} />}</td>
                {asc.map((p, i) => {
                  const v = row.get(p.result);
                  const prev = i > 0 ? row.get(asc[i - 1].result) : v;
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
        <div className="hint">
          スナップショットが1点のみです。<b>Re-enrich</b> を重ねると差分比較できます。
        </div>
      ) : (
        <>
          <div className="ana-compare-controls">
            <label>
              A{' '}
              <select value={ai} onChange={(e) => setAi(Number(e.target.value))}>
                {asc.map((p, i) => (
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
                {asc.map((p, i) => (
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
            <div className="ana-compare-wrap">
              <table className="ana-compare">
                <thead>
                  <tr>
                    <th>field</th>
                    <th>A · {new Date(asc[Math.min(ai, n - 1)].at).toLocaleString()}</th>
                    <th>B · {new Date(asc[Math.min(bi, n - 1)].at).toLocaleString()}</th>
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
            </div>
          )}
        </>
      )}

      {/* ---- Timeline ---- */}
      <div className="ana-section-title">Timeline</div>
      <ol className="hist-timeline">
        {[...asc].reverse().map((h, i, arr) => {
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
                <button className="btn btn-sm" onClick={() => showResult(h.result)} title="このスナップショットの詳細を開く">
                  Details
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
  );
}
