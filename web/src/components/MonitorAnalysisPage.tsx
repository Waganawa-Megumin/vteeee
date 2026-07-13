import { useMemo } from 'react';
import { useStore } from '../state/store';
import { EnrichmentAnalysis, type AnalysisPoint } from './EnrichmentAnalysis';

export function MonitorAnalysisPage() {
  const ip = useStore((s) => s.analysisIp);
  const entry = useStore((s) => (ip ? s.monitors[ip] : undefined));
  const setView = useStore((s) => s.setView);
  const showResult = useStore((s) => s.showResult);
  const reEnrich = useStore((s) => s.reEnrichMonitor);

  // Ascending timeline (oldest → newest); seed the current result as a single point if no history yet.
  const points = useMemo<AnalysisPoint[]>(() => {
    const raw = entry?.history?.length
      ? entry.history
      : entry?.result
        ? [{ at: entry.updatedAt, by: undefined as string | undefined, result: entry.result }]
        : [];
    return [...raw].sort((a, b) => a.at - b.at);
  }, [entry]);
  const n = points.length;

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
        <EnrichmentAnalysis points={points} resetKey={ip} showResult={showResult} />
      )}
    </section>
  );
}
