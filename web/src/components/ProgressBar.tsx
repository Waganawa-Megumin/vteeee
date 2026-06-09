import { useEffect, useState } from 'react';
import { useStore } from '../state/store';

export function ProgressBar() {
  const progress = useStore((s) => s.progress);
  const running = useStore((s) => s.running);
  const stop = useStore((s) => s.stop);
  const [, force] = useState(0);

  // Tick once a second so the rate-limit countdown updates.
  useEffect(() => {
    if (!progress?.rateLimitedUntil) return;
    const t = setInterval(() => force((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [progress?.rateLimitedUntil]);

  if (!progress) return null;
  const pct = progress.total ? Math.round((progress.done / progress.total) * 100) : 0;
  const waitMs = progress.rateLimitedUntil ? progress.rateLimitedUntil - Date.now() : 0;
  const waitS = waitMs > 0 ? Math.ceil(waitMs / 1000) : 0;

  return (
    <div className="progress">
      <div className="progress-bar">
        <div className="progress-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="progress-meta">
        <span>
          {progress.done}/{progress.total} ({pct}%)
        </span>
        {progress.inflight > 0 && <span>· {progress.inflight} in flight</span>}
        {waitS > 0 && <span className="rl">· rate-limited, retrying in {waitS}s</span>}
        {running && (
          <button className="btn btn-stop" onClick={stop}>
            Stop
          </button>
        )}
      </div>
    </div>
  );
}
