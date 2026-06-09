import { useState } from 'react';
import { useStore } from '../state/store';
import { clearHistory, deleteHistory, loadHistory, type HistoryEntry } from '../lib/history';

function summarize(e: HistoryEntry) {
  let mal = 0;
  let sus = 0;
  for (const r of e.results) {
    if (r.verdict === 'malicious') mal++;
    else if (r.verdict === 'suspicious') sus++;
  }
  return { mal, sus, total: e.results.length };
}

export function HistoryDialog({ onClose }: { onClose: () => void }) {
  const retention = useStore((s) => s.settings.historyRetentionDays ?? 30);
  const restore = useStore((s) => s.restore);
  const [entries, setEntries] = useState<HistoryEntry[]>(() => loadHistory(retention));

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal help-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>History · 検索履歴</h2>
          <button className="btn btn-ghost" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-body help-body">
          {retention <= 0 && (
            <p className="hint">
              History is off. Enable it in Settings (retention &gt; 0). ／ 設定で保持日数を1以上にすると有効になります。
            </p>
          )}
          {entries.length === 0 ? (
            <p className="hint">
              No saved searches yet — run an enrichment and it will be saved here. ／ まだ履歴はありません。Enrich すると保存されます。
            </p>
          ) : (
            <ul className="history-list">
              {entries.map((e) => {
                const s = summarize(e);
                return (
                  <li key={e.id} className="history-row">
                    <button
                      className="history-main"
                      onClick={() => {
                        restore(e.results, e.input);
                        onClose();
                      }}
                      title="Restore this search / この検索を復元"
                    >
                      <span className="h-top">
                        <span className="h-date">{new Date(e.createdAt).toLocaleString()}</span>
                        <span className={`mode-pill ${e.mode}`}>{e.mode.toUpperCase()}</span>
                        <span className="h-sum">
                          {s.total} indicators
                          {s.mal ? ` · ${s.mal} malicious` : ''}
                          {s.sus ? ` · ${s.sus} suspicious` : ''}
                        </span>
                      </span>
                      <span className="h-input">{e.input.replace(/\s+/g, ' ').trim().slice(0, 90) || '—'}</span>
                    </button>
                    <button
                      className="btn btn-sm btn-danger"
                      onClick={() => setEntries(deleteHistory(e.id, retention))}
                    >
                      Delete
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <div className="modal-foot">
          <span className="hint" style={{ marginRight: 'auto' }}>
            保持 {retention} 日 · 端末内 (localStorage)
          </span>
          <button
            className="btn"
            disabled={!entries.length}
            onClick={() => {
              if (!window.confirm('Clear all saved history? / 履歴をすべて消去しますか？')) return;
              clearHistory();
              setEntries([]);
            }}
          >
            Clear all
          </button>
          <button className="btn btn-primary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
