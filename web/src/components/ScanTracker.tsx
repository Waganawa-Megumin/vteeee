import { useState } from 'react';
import { useStore, isActiveScan, isActiveCapture } from '../state/store';

/**
 * Header readout of background jobs — Shodan re-scans AND urlscan 魚拓 captures. Because both run in
 * the store (not the detail panel), you can close the panel (or the CP-Mon page) and still see
 * progress here, get a browser notification on completion, and reopen the result later. Hidden when
 * there are no jobs of either kind.
 */
export function ScanTracker() {
  const jobs = useStore((s) => s.scanJobs);
  const captures = useStore((s) => s.webCaptures);
  const select = useStore((s) => s.select);
  const results = useStore((s) => s.results);
  const recheck = useStore((s) => s.recheckShodanHost);
  const dismiss = useStore((s) => s.dismissScan);
  const markSeen = useStore((s) => s.markScanSeen);
  const clearFinished = useStore((s) => s.clearFinishedScans);
  const startCapture = useStore((s) => s.startWebCapture);
  const markCapSeen = useStore((s) => s.markCaptureSeen);
  const dismissCap = useStore((s) => s.dismissWebCapture);
  const clearFinishedCaps = useStore((s) => s.clearFinishedWebCaptures);
  const [open, setOpen] = useState(false);

  const list = Object.values(jobs).sort((a, b) => b.updatedAt - a.updatedAt);
  const caps = Object.values(captures).sort((a, b) => b.updatedAt - a.updatedAt);
  if (list.length === 0 && caps.length === 0) return null;

  const active = list.filter(isActiveScan).length + caps.filter(isActiveCapture).length;
  const unseen =
    list.filter((j) => !isActiveScan(j) && !j.seen).length + caps.filter((j) => !isActiveCapture(j) && !j.seen).length;
  const label = active > 0 ? `${active} 実行中` : unseen > 0 ? `${unseen} done` : 'Jobs';
  const cls = active > 0 ? 'scan-tracker active' : unseen > 0 ? 'scan-tracker done' : 'scan-tracker';
  const icon = list.length > 0 && caps.length > 0 ? '📡🎣' : caps.length > 0 ? '🎣' : '📡';

  function openIp(ip: string) {
    markSeen(ip);
    if (results[ip]) select(ip);
    setOpen(false);
  }

  function openCap(target: string) {
    markCapSeen(target);
    const cap = captures[target];
    if (results[target]) select(target);
    else if (cap?.result?.resultUrl) window.open(cap.result.resultUrl, '_blank', 'noopener');
    setOpen(false);
  }

  return (
    <div className="scan-tracker-wrap">
      <button
        className={`btn btn-sm ${cls}`}
        onClick={() => setOpen((o) => !o)}
        title="バックグラウンドのジョブ（Shodan 再スキャン・urlscan 魚拓）— 詳細やページを閉じても継続します"
      >
        {active > 0 && <span className="live-dot" aria-hidden />}
        {icon} {label}
      </button>
      {open && (
        <>
          <div className="scan-tracker-backdrop" onClick={() => setOpen(false)} />
          <div className="scan-tracker-menu" role="menu">
            {list.length > 0 && (
              <>
                <div className="stm-head">
                  <span>Shodan re-scans</span>
                  <button className="btn btn-ghost btn-sm" onClick={clearFinished}>
                    Clear finished
                  </button>
                </div>
                {list.map((j) => {
                  const canOpen = Boolean(results[j.ip]);
                  const statusText =
                    j.phase === 'done'
                      ? `✓ done${j.host?.ports?.length ? ` · ${j.host.ports.length} ports` : ''}`
                      : j.phase === 'error'
                        ? `⚠ ${j.error ?? j.msg ?? 'error'}`
                        : j.phase === 'timeout'
                          ? 'still running at Shodan…'
                          : j.phase === 'interrupted'
                            ? 'interrupted by reload'
                            : (j.msg ?? j.phase);
                  return (
                    <div key={j.ip} className={`stm-row phase-${j.phase}${!isActiveScan(j) && !j.seen ? ' unseen' : ''}`}>
                      <div className="stm-main">
                        <span className="stm-ip mono">{j.ip}</span>
                        <span className="stm-status">
                          {isActiveScan(j) && <span className="live-dot" aria-hidden />}
                          {statusText}
                        </span>
                      </div>
                      <div className="stm-actions">
                        {canOpen && (
                          <button className="btn btn-ghost btn-sm" onClick={() => openIp(j.ip)}>
                            Open
                          </button>
                        )}
                        {(j.phase === 'timeout' || j.phase === 'interrupted') && (
                          <button className="btn btn-ghost btn-sm" onClick={() => recheck(j.ip)}>
                            Re-check
                          </button>
                        )}
                        <button className="btn btn-ghost btn-sm" onClick={() => dismiss(j.ip)} title="Remove from tracker">
                          ✕
                        </button>
                      </div>
                    </div>
                  );
                })}
              </>
            )}

            {caps.length > 0 && (
              <>
                <div className="stm-head">
                  <span>urlscan 魚拓</span>
                  <button className="btn btn-ghost btn-sm" onClick={clearFinishedCaps}>
                    Clear finished
                  </button>
                </div>
                {caps.map((c) => {
                  const canOpen = Boolean(results[c.target]) || Boolean(c.result?.resultUrl);
                  const resumable = c.phase === 'stalled' || c.phase === 'interrupted';
                  const statusText =
                    c.phase === 'done'
                      ? `✓ done${c.result?.malicious ? ' · ⚠ malicious' : ''}`
                      : c.phase === 'error'
                        ? `⚠ ${c.error ?? c.msg ?? 'error'}`
                        : c.phase === 'stalled'
                          ? 'still rendering…'
                          : c.phase === 'interrupted'
                            ? 'interrupted by reload'
                            : (c.msg ?? c.phase);
                  return (
                    <div
                      key={c.target}
                      className={`stm-row phase-${c.phase}${!isActiveCapture(c) && !c.seen ? ' unseen' : ''}`}
                    >
                      <div className="stm-main">
                        <span className="stm-ip mono">{c.target}</span>
                        <span className="stm-status">
                          {isActiveCapture(c) && <span className="live-dot" aria-hidden />}
                          {statusText}
                        </span>
                      </div>
                      <div className="stm-actions">
                        {canOpen && (
                          <button className="btn btn-ghost btn-sm" onClick={() => openCap(c.target)}>
                            Open
                          </button>
                        )}
                        {resumable && (
                          <button className="btn btn-ghost btn-sm" onClick={() => void startCapture(c.target)}>
                            Re-check
                          </button>
                        )}
                        <button
                          className="btn btn-ghost btn-sm"
                          onClick={() => dismissCap(c.target)}
                          title="Remove from tracker"
                        >
                          ✕
                        </button>
                      </div>
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </>
      )}
    </div>
  );
}
