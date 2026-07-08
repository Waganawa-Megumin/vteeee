import { useEffect } from 'react';
import { useStore, type MonitorEntry } from '../state/store';
import { VerdictBadge } from './Badges';
import { detectionRatio } from '../lib/verdict';

/** Compact vteeee-enrichment summary chips for a monitored IP's last snapshot. */
function Summary({ e }: { e: MonitorEntry }) {
  const r = e.result;
  if (!r) return <span className="mon-nointel">no enrichment yet — press “Re-enrich”</span>;
  const abuse = r.abuseipdb?.abuseConfidenceScore;
  const abuseCls = abuse == null ? '' : abuse >= 75 ? 'sev-high' : abuse >= 25 ? 'sev-med' : 'sev-low';
  return (
    <span className="mon-summary">
      <VerdictBadge verdict={r.verdict} status={r.status} />
      {r.detection && <span className="mon-chip">det {detectionRatio(r)}</span>}
      {r.gti?.verdict && <span className="mon-chip">{r.gti.verdict.replace('VERDICT_', '')}</span>}
      {r.shodan?.ports?.length ? <span className="mon-chip mono">{r.shodan.ports.length} ports</span> : null}
      {r.shodan?.vulns?.length ? <span className="mon-chip sev-high">{r.shodan.vulns.length} CVE</span> : null}
      {abuse != null && <span className={`mon-chip ${abuseCls}`}>abuse {abuse}</span>}
      {r.recordedfuture?.riskScore != null && <span className="mon-chip">RF {r.recordedfuture.riskScore}</span>}
      {r.maxmind?.countryCode || r.ip?.country ? (
        <span className="mon-chip">{r.maxmind?.countryCode ?? r.ip?.country}</span>
      ) : null}
    </span>
  );
}

export function MonitorDialog({ onClose }: { onClose: () => void }) {
  const monitors = useStore((s) => s.monitors);
  const mode = useStore((s) => s.mode);
  const refresh = useStore((s) => s.refreshMonitors);
  const reEnrich = useStore((s) => s.reEnrichMonitor);
  const remove = useStore((s) => s.removeMonitor);
  const showResult = useStore((s) => s.showResult);

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const list = Object.values(monitors).sort((a, b) => b.addedAt - a.addedAt);

  // Dashboard roll-up across the watchlist's saved enrichment snapshots.
  const total = list.length;
  const live = list.filter((e) => e.live).length;
  const withIntel = list.filter((e) => e.result).length;
  const malicious = list.filter((e) => e.result?.verdict === 'malicious').length;
  const suspicious = list.filter((e) => e.result?.verdict === 'suspicious').length;
  const highAbuse = list.filter((e) => (e.result?.abuseipdb?.abuseConfidenceScore ?? -1) >= 75).length;
  const withCves = list.filter((e) => (e.result?.shodan?.vulns?.length ?? 0) > 0).length;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal help-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>📡 Shodan Monitor — watchlist</h2>
          <button className="btn btn-ghost" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-body help-body">
          <p className="hint">
            監視IPは Shodan の<b>ネットワークアラート（サーバ側）</b>として登録され、Shodan が変化を監視し続けます。ここには
            <b>各IPの最新 vteeee エンリッチ結果</b>も一緒に保存されるので、<b>翌日でも intel ごと確認</b>できます。
            {mode === 'demo' && ' （デモ：サンプル表示）'}
          </p>

          {total > 0 && (
            <div className="mon-stats" role="group" aria-label="watchlist summary">
              <div className="mon-stat">
                <b>{total}</b>
                <span>monitored</span>
              </div>
              <div className="mon-stat">
                <b>{live}</b>
                <span>live on Shodan</span>
              </div>
              <div className="mon-stat">
                <b>{withIntel}</b>
                <span>with intel</span>
              </div>
              {malicious > 0 && (
                <div className="mon-stat bad">
                  <b>{malicious}</b>
                  <span>malicious</span>
                </div>
              )}
              {suspicious > 0 && (
                <div className="mon-stat warn">
                  <b>{suspicious}</b>
                  <span>suspicious</span>
                </div>
              )}
              {highAbuse > 0 && (
                <div className="mon-stat bad">
                  <b>{highAbuse}</b>
                  <span>abuse ≥75</span>
                </div>
              )}
              {withCves > 0 && (
                <div className="mon-stat warn">
                  <b>{withCves}</b>
                  <span>with CVEs</span>
                </div>
              )}
            </div>
          )}

          {list.length === 0 ? (
            <p className="hint">
              まだ監視IPはありません。IP の詳細を開いて <b>☆ Monitor</b> を押してください。／ No monitored IPs yet — open an
              IP's detail and press ☆ Monitor.
            </p>
          ) : (
            <ul className="monitor-list">
              {list.map((e) => (
                <li key={e.ip} className="monitor-row">
                  <div className="mon-main">
                    <div className="mon-top">
                      <span className="mon-ip mono">{e.ip}</span>
                      {e.live ? (
                        <span className="mon-badge live" title="Registered as a Shodan network alert">
                          ● monitoring
                        </span>
                      ) : e.error ? (
                        <span className="mon-badge err" title={e.error}>
                          ⚠ not registered
                        </span>
                      ) : (
                        <span className="mon-badge">…</span>
                      )}
                      {e.triggers?.length ? <span className="mon-trig">triggers: {e.triggers.join(', ')}</span> : null}
                      <span className="mon-when">added {new Date(e.addedAt).toLocaleDateString()}</span>
                    </div>
                    <Summary e={e} />
                    {e.error && <div className="mon-err">{e.error}</div>}
                  </div>
                  <div className="mon-actions">
                    <button
                      className="btn btn-sm"
                      disabled={!e.result}
                      title={e.result ? 'Open the enrichment detail' : 'Re-enrich first'}
                      onClick={() => {
                        if (e.result) {
                          showResult(e.result);
                          onClose();
                        }
                      }}
                    >
                      Open
                    </button>
                    <button className="btn btn-sm" disabled={e.enriching} onClick={() => void reEnrich(e.ip)}>
                      {e.enriching ? 'Enriching…' : 'Re-enrich'}
                    </button>
                    <a
                      className="btn btn-sm"
                      href={`https://www.shodan.io/host/${encodeURIComponent(e.ip ?? '')}`}
                      target="_blank"
                      rel="noreferrer"
                      title="Open this host on Shodan"
                    >
                      Shodan ↗
                    </a>
                    <button className="btn btn-sm btn-danger" onClick={() => void remove(e.ip)}>
                      Remove
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="modal-foot">
          <span className="hint" style={{ marginRight: 'auto' }}>
            {list.length} monitored · 監視は Shodan 側で継続、intel は端末内に保存
          </span>
          <a
            className="btn"
            href="https://monitor.shodan.io/dashboard"
            target="_blank"
            rel="noreferrer"
            title="Open the Shodan Monitor dashboard"
          >
            Shodan Monitor ↗
          </a>
          <button className="btn" onClick={() => void refresh()}>
            Refresh
          </button>
          <button className="btn btn-primary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
