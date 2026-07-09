import type { NormalizedResult } from '@vteeee/shared';
import { useStore, type MonitorEntry } from '../state/store';
import { VerdictBadge } from './Badges';

function countryOf(r: NormalizedResult): string {
  return r.maxmind?.countryCode ?? r.abuseipdb?.countryCode ?? r.shodan?.country ?? r.ip?.country ?? '';
}

interface Metrics {
  verdict: string;
  det: number;
  detTotal: number;
  abuse: number | null;
  rf: number | null;
  ports: number;
  cves: number;
  country: string;
}
function metrics(r: NormalizedResult): Metrics {
  const d = r.detection;
  return {
    verdict: r.verdict,
    det: (d?.malicious ?? 0) + (d?.suspicious ?? 0),
    detTotal: d?.total ?? 0,
    abuse: r.abuseipdb?.abuseConfidenceScore ?? null,
    rf: r.recordedfuture?.riskScore ?? null,
    ports: r.shodan?.ports?.length ?? 0,
    cves: r.shodan?.vulns?.length ?? 0,
    country: countryOf(r),
  };
}

/** Human-readable "what changed" between a snapshot and the one before it. */
function diffParts(cur: NormalizedResult, prev: NormalizedResult): string[] {
  const a = metrics(prev);
  const b = metrics(cur);
  const parts: string[] = [];
  if (a.verdict !== b.verdict) parts.push(`verdict ${a.verdict}→${b.verdict}`);
  if (a.det !== b.det || a.detTotal !== b.detTotal) parts.push(`det ${a.det}/${a.detTotal}→${b.det}/${b.detTotal}`);
  if (a.abuse !== b.abuse) parts.push(`abuse ${a.abuse ?? '—'}→${b.abuse ?? '—'}`);
  if (a.rf !== b.rf) parts.push(`RF ${a.rf ?? '—'}→${b.rf ?? '—'}`);
  const pPrev = new Set(prev.shodan?.ports ?? []);
  const pCur = new Set(cur.shodan?.ports ?? []);
  const newP = [...pCur].filter((x) => !pPrev.has(x));
  const goneP = [...pPrev].filter((x) => !pCur.has(x));
  if (newP.length) parts.push(`+ports ${newP.join(',')}`);
  if (goneP.length) parts.push(`−ports ${goneP.join(',')}`);
  const vPrev = new Set(prev.shodan?.vulns ?? []);
  const vCur = new Set(cur.shodan?.vulns ?? []);
  const newV = [...vCur].filter((x) => !vPrev.has(x));
  const goneV = [...vPrev].filter((x) => !vCur.has(x));
  if (newV.length) parts.push(`+CVE ${newV.slice(0, 4).join(',')}${newV.length > 4 ? '…' : ''}`);
  if (goneV.length) parts.push(`−CVE ${goneV.slice(0, 4).join(',')}${goneV.length > 4 ? '…' : ''}`);
  if (a.country !== b.country) parts.push(`country ${a.country || '—'}→${b.country || '—'}`);
  return parts;
}

/**
 * Enrichment history & change analysis for one monitored IP. Re-enrich no longer discards the past:
 * each state change is kept as a point-in-time snapshot (older ones auto-thinned by age). Shows the
 * timeline newest-first with "what changed vs the previous point", and Open re-opens any past snapshot.
 */
export function MonitorHistoryDialog({ entry, onClose }: { entry: MonitorEntry; onClose: () => void }) {
  const showResult = useStore((s) => s.showResult);
  // Existing entries may have a current snapshot but no accumulated timeline yet — seed the current
  // result as the first point so the timeline is never empty when there's intel to show.
  const raw =
    entry.history && entry.history.length
      ? entry.history
      : entry.result
        ? [{ at: entry.updatedAt, by: undefined, result: entry.result }]
        : [];
  const hist = [...raw].sort((a, b) => b.at - a.at); // newest first
  const contributors = [...new Set(hist.map((h) => h.by).filter((x): x is string => !!x))];

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal history-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>
            Enrichment history · analysis — <span className="mono">{entry.ip}</span>
          </h2>
          <button className="btn btn-ghost" onClick={onClose}>
            ✕
          </button>
        </div>
        <div className="modal-body">
          {hist.length === 0 ? (
            <div className="hint">
              まだ履歴がありません。<b>Re-enrich</b> するたびに、その時点のスナップショットが時系列で蓄積されます
              （状態が変化した地点のみ・古いものは自動間引き）。
            </div>
          ) : (
            <>
              <div className="hist-summary hint">
                <b>{hist.length}</b> 地点
                {contributors.length ? (
                  <>
                    {' '}
                    · by <b>{contributors.join(', ')}</b>
                  </>
                ) : null}{' '}
                · {new Date(hist[hist.length - 1].at).toLocaleDateString()} 〜{' '}
                {new Date(hist[0].at).toLocaleDateString()}
                。変化のあった地点のみ（直近1週≒日次／以降は自動間引き）。
              </div>
              <ol className="hist-timeline">
                {hist.map((h, i) => {
                  const older = hist[i + 1];
                  const m = metrics(h.result);
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
                        <button
                          className="btn btn-sm"
                          onClick={() => {
                            onClose();
                            showResult(h.result);
                          }}
                          title="Open this snapshot's full detail (this point in time)"
                        >
                          Open
                        </button>
                      </div>
                      <div className="hist-metrics">
                        <VerdictBadge verdict={h.result.verdict} status={h.result.status} />
                        <span className="mon-chip">
                          det {m.det}/{m.detTotal}
                        </span>
                        {m.abuse != null && <span className="mon-chip">abuse {m.abuse}</span>}
                        {m.rf != null && <span className="mon-chip">RF {m.rf}</span>}
                        {m.ports > 0 && <span className="mon-chip mono">{m.ports} ports</span>}
                        {m.cves > 0 && <span className="mon-chip sev-high">{m.cves} CVE</span>}
                        {m.country && <span className="mon-chip">{m.country}</span>}
                      </div>
                      {changes.length > 0 && (
                        <div className="hist-diff changed">▲ vs 前回: {changes.join(' · ')}</div>
                      )}
                    </li>
                  );
                })}
              </ol>
            </>
          )}
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
