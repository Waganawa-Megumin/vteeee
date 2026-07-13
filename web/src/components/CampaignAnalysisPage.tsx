import { useMemo } from 'react';
import { useStore } from '../state/store';
import { EnrichmentAnalysis, type AnalysisPoint } from './EnrichmentAnalysis';

/** CP-Mon per-IOC time-series analysis — same Trends/Matrix/Compare/Timeline as IP-Mon, over a
 *  campaign IOC's enrichment history. */
export function CampaignAnalysisPage() {
  const target = useStore((s) => s.analysisCampaign);
  const campaign = useStore((s) => (target ? s.campaigns[target.id] : undefined));
  const setView = useStore((s) => s.setView);
  const showResult = useStore((s) => s.showResult);
  const reEnrich = useStore((s) => s.reEnrichCampaignIoc);

  const ioc = target && campaign ? campaign.iocs[target.value] : undefined;
  const points = useMemo<AnalysisPoint[]>(() => {
    const raw = ioc?.history?.length
      ? ioc.history
      : ioc?.result
        ? [{ at: ioc.updatedAt, by: undefined as string | undefined, result: ioc.result }]
        : [];
    return [...raw].sort((a, b) => a.at - b.at);
  }, [ioc]);
  const n = points.length;

  if (!target || !campaign || !ioc) {
    return (
      <section className="panel monitor-page">
        <div className="panel-head">
          <button className="btn btn-sm" onClick={() => setView('campaign')}>
            ← Back
          </button>
          <h2>Trend analysis</h2>
        </div>
        <div className="empty-state">この IoC は見つかりませんでした。CP-Mon に戻ってください。</div>
      </section>
    );
  }

  const contributors = [...new Set(points.map((p) => p.by).filter((x): x is string => !!x))];

  return (
    <section className="panel monitor-page ana-page">
      <div className="panel-head">
        <button className="btn btn-sm" onClick={() => setView('campaign')} title="キャンペーンに戻る">
          ← Back
        </button>
        <h2 title="Tr-Analysis（Trend Analysis）— エンリッチ履歴の時系列分析：トレンド／指標マトリクス／2点比較／タイムライン">
          Trend analysis · <span className="mono">{ioc.value}</span>
        </h2>
        <div className="spacer" />
        <button className="btn btn-sm" disabled={ioc.enriching} onClick={() => void reEnrich(target.id, ioc.value)}>
          {ioc.enriching ? 'Enriching…' : 'Re-enrich now'}
        </button>
      </div>

      <p className="hint mon-intro">
        <b>{campaign.name}</b> の IoC <span className="mono">{ioc.value}</span> のエンリッチ履歴（
        {ioc.group ? `group: ${ioc.group} · ` : ''}
        <b>{n}</b> 地点{contributors.length ? ` · by ${contributors.join(', ')}` : ''}
        {n > 0 ? ` · ${new Date(points[0].at).toLocaleDateString()} 〜 ${new Date(points[n - 1].at).toLocaleDateString()}` : ''}
        ）。Re-enrich は過去を捨てず、状態が変化した地点をタイムラインに蓄積します。
      </p>

      {n === 0 ? (
        <div className="empty-state">
          まだエンリッチ結果がありません。<b>Re-enrich now</b> で最初のスナップショットを取得してください。
        </div>
      ) : (
        <EnrichmentAnalysis points={points} resetKey={ioc.value} showResult={showResult} />
      )}
    </section>
  );
}
