import { useState } from 'react';
import { useStore, isActiveScan } from '../state/store';

/**
 * Header readout of background Shodan re-scans. Because the scans run in the store (not the detail
 * panel), you can close the panel and still see progress here, get a browser notification on
 * completion, and reopen the result later. Hidden when there are no jobs.
 */
export function ScanTracker() {
  const jobs = useStore((s) => s.scanJobs);
  const select = useStore((s) => s.select);
  const results = useStore((s) => s.results);
  const recheck = useStore((s) => s.recheckShodanHost);
  const dismiss = useStore((s) => s.dismissScan);
  const markSeen = useStore((s) => s.markScanSeen);
  const clearFinished = useStore((s) => s.clearFinishedScans);
  const [open, setOpen] = useState(false);

  const list = Object.values(jobs).sort((a, b) => b.updatedAt - a.updatedAt);
  if (list.length === 0) return null;

  const active = list.filter(isActiveScan).length;
  const unseen = list.filter((j) => !isActiveScan(j) && !j.seen).length;
  const label = active > 0 ? `${active} scanning` : unseen > 0 ? `${unseen} done` : 'Scans';
  const cls = active > 0 ? 'scan-tracker active' : unseen > 0 ? 'scan-tracker done' : 'scan-tracker';

  function openIp(ip: string) {
    markSeen(ip);
    if (results[ip]) select(ip);
    setOpen(false);
  }

  return (
    <div className="scan-tracker-wrap">
      <button
        className={`btn btn-sm ${cls}`}
        onClick={() => setOpen((o) => !o)}
        title="Background Shodan re-scans — keep running even if you close the detail panel"
      >
        {active > 0 && <span className="live-dot" aria-hidden />}📡 {label}
      </button>
      {open && (
        <>
          <div className="scan-tracker-backdrop" onClick={() => setOpen(false)} />
          <div className="scan-tracker-menu" role="menu">
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
          </div>
        </>
      )}
    </div>
  );
}
