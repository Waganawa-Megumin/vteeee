import { useState } from 'react';
import type { AppSettings } from '@vteeee/shared';
import { useStore } from '../state/store';

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const settings = useStore((s) => s.settings);
  const applySettings = useStore((s) => s.applySettings);
  const [draft, setDraft] = useState<AppSettings>(settings);

  function up<K extends keyof AppSettings>(k: K, v: AppSettings[K]) {
    setDraft((d) => ({ ...d, [k]: v }));
  }

  const live = !!draft.proxyBaseUrl;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>Settings</h2>
          <button className="btn btn-ghost" onClick={onClose}>
            ✕
          </button>
        </div>
        <div className="modal-body">
          <div className={`mode-pill ${live ? 'live' : 'demo'}`}>
            {live ? 'LIVE — real VT lookups via proxy' : 'DEMO — bundled sample data only'}
          </div>

          <label className="fld">
            Proxy base URL
            <input
              placeholder="https://your-proxy.workers.dev  (empty = demo)"
              value={draft.proxyBaseUrl ?? ''}
              onChange={(e) => up('proxyBaseUrl', e.target.value.trim() || null)}
            />
          </label>
          <label className="fld">
            Access token (sent to your proxy only)
            <input
              type="password"
              value={draft.accessToken ?? ''}
              onChange={(e) => up('accessToken', e.target.value || null)}
            />
          </label>
          <div className="fld-row">
            <label className="fld">
              Requests / min
              <input
                type="number"
                min={1}
                value={draft.rpm}
                onChange={(e) => up('rpm', Number(e.target.value) || 1)}
              />
            </label>
            <label className="fld">
              Concurrency
              <input
                type="number"
                min={1}
                value={draft.concurrency}
                onChange={(e) => up('concurrency', Number(e.target.value) || 1)}
              />
            </label>
          </div>
          <label className="chk">
            <input type="checkbox" checked={draft.gti} onChange={(e) => up('gti', e.target.checked)} />
            Request GTI fields (gti_assessment)
          </label>
          <label className="chk">
            <input
              type="checkbox"
              checked={draft.submitUnknown}
              onChange={(e) => up('submitUnknown', e.target.checked)}
            />
            Submit never-analyzed URLs/files (consumes quota)
          </label>

          <p className="hint">
            Free VT tier ≈ 4 req/min, 500/day — keep rpm low to avoid 429s. The access token is
            stored only in this browser and sent only to your proxy.
          </p>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            onClick={() => {
              applySettings(draft);
              onClose();
            }}
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
