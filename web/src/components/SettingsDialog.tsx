import { useState } from 'react';
import type { AppSettings } from '@vteeee/shared';
import { useStore } from '../state/store';
import { InfoTip } from './InfoTip';

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
            {live ? 'LIVE — real VT lookups via proxy' : 'Not connected — add a proxy URL to go live'}
          </div>

          <label className="fld">
            <span className="fld-label">
              Proxy base URL
              <InfoTip
                ja="実データ検索の中継サーバーのURL。空ならデモ（サンプル）動作。"
                en="URL of the server-side proxy that does real lookups. Empty = demo mode."
              />
            </span>
            <input
              placeholder="https://your-proxy.workers.dev  (empty = demo)"
              value={draft.proxyBaseUrl ?? ''}
              onChange={(e) => up('proxyBaseUrl', e.target.value.trim() || null)}
            />
          </label>

          <label className="fld">
            <span className="fld-label">
              Access token
              <InfoTip
                ja="プロキシへ送る合言葉。プロキシの ACCESS_TOKEN と同じ値。ブラウザ内にのみ保存され、あなたのプロキシにだけ送られます。"
                en="Shared secret sent to your proxy; must match its ACCESS_TOKEN. Stored only in this browser."
              />
            </span>
            <input
              type="password"
              value={draft.accessToken ?? ''}
              onChange={(e) => up('accessToken', e.target.value || null)}
            />
          </label>

          <div className="fld-row">
            <label className="fld">
              <span className="fld-label">
                Requests / min
                <InfoTip
                  ja="1分あたりVirusTotalへ送る検索数の上限＝速度制限。無料キーは約4。超えると429エラー。"
                  en="Per-minute lookup cap (a speed limit). Free keys ≈ 4; going higher triggers HTTP 429 errors."
                />
              </span>
              <input
                type="number"
                min={1}
                value={draft.rpm}
                onChange={(e) => up('rpm', Number(e.target.value) || 1)}
              />
            </label>
            <label className="fld">
              <span className="fld-label">
                Concurrency
                <InfoTip
                  ja="同時に並行して走らせる検索数。無料(4/分)なら1で十分。高レート/GTIキーなら増やすと大量リストが速い。"
                  en="How many lookups run in parallel. Keep 1 on a free key; raise it for high-limit/GTI keys."
                />
              </span>
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
            <InfoTip
              ja="Google Threat Intelligence の評価(verdict/severity/threat score)も取得。GTIキー使用時のみ有効。"
              en="Also fetch GTI assessment (verdict/severity/score). Only useful with a GTI key."
            />
          </label>
          <label className="chk">
            <input
              type="checkbox"
              checked={draft.submitUnknown}
              onChange={(e) => up('submitUnknown', e.target.checked)}
            />
            Submit never-analyzed URLs/files
            <InfoTip
              ja="VT未登録(404)のURL/ファイルを解析に提出する。クォータを消費するため既定はオフ。"
              en="Submit never-analyzed (404) URLs/files for analysis. Consumes quota, so off by default."
            />
          </label>

          <p className="hint">
            Free VT tier ≈ 4 req/min, 500/day — keep rpm low to avoid 429s. The access token is stored
            only in this browser and sent only to your proxy.
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
