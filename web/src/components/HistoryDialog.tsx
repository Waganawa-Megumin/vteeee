import { useEffect, useMemo, useState } from 'react';
import type { HistorySummary } from '@vteeee/shared';
import { useStore } from '../state/store';
import { historySource } from '../lib/historySource';
import { downloadCsv, resultsToCsv } from '../lib/csv-export';

export function HistoryDialog({ onClose }: { onClose: () => void }) {
  const settings = useStore((s) => s.settings);
  const session = useStore((s) => s.session);
  const restore = useStore((s) => s.restore);
  const source = useMemo(() => historySource(settings, session), [settings, session]);
  const retention = settings.historyRetentionDays ?? 30;
  const isAdmin = session?.role === 'admin';

  const [entries, setEntries] = useState<HistorySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [tagsDraft, setTagsDraft] = useState('');
  const [noteDraft, setNoteDraft] = useState('');

  async function reload() {
    setLoading(true);
    try {
      setEntries(await source.list());
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function withBusy(id: string, fn: () => Promise<void>) {
    setBusy(id);
    try {
      await fn();
    } finally {
      setBusy(null);
    }
  }

  function startEdit(e: HistorySummary) {
    setEditing(e.id);
    setTagsDraft((e.tags ?? []).join(', '));
    setNoteDraft(e.note ?? '');
  }

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
          <div className={`mode-pill ${source.shared ? 'live' : 'demo'}`}>
            {source.shared ? 'SHARED — stored on the proxy (KV)' : 'LOCAL — this browser only'}
          </div>

          {loading ? (
            <p className="hint">Loading…</p>
          ) : entries.length === 0 ? (
            <p className="hint">
              No saved searches yet — run an enrichment and it will be saved here. ／ まだ履歴はありません。
            </p>
          ) : (
            <ul className="history-list">
              {entries.map((e) => (
                <li key={e.id} className="history-row-wrap">
                  <div className="history-row">
                    <button
                      className="history-main"
                      disabled={busy === e.id}
                      onClick={() =>
                        void withBusy(e.id, async () => {
                          const rec = await source.get(e.id);
                          if (rec) {
                            restore(rec.results, rec.input);
                            onClose();
                          }
                        })
                      }
                      title="Restore this search / この検索を復元"
                    >
                      <span className="h-top">
                        <span className="h-date">{new Date(e.createdAt).toLocaleString()}</span>
                        <span className={`mode-pill ${e.mode}`}>{e.mode.toUpperCase()}</span>
                        <span className="h-sum">
                          {e.total} indicators
                          {e.malicious ? ` · ${e.malicious} malicious` : ''}
                          {e.suspicious ? ` · ${e.suspicious} suspicious` : ''}
                        </span>
                        {(e.owner || e.ip) && (
                          <span className="h-owner">
                            👤 {e.owner ?? '—'}
                            {isAdmin && e.ip ? ` · ${e.ip}` : ''}
                          </span>
                        )}
                      </span>
                      <span className="h-input">{e.inputPreview || '—'}</span>
                      {(e.tags?.length || e.note) && (
                        <span className="h-meta">
                          {e.tags?.map((t) => (
                            <span key={t} className="h-tag">
                              {t}
                            </span>
                          ))}
                          {e.note && <span className="h-note">📝 {e.note}</span>}
                        </span>
                      )}
                    </button>
                    <div className="history-actions">
                      <button
                        className="btn btn-sm"
                        disabled={busy === e.id}
                        onClick={() =>
                          void withBusy(e.id, async () => {
                            const rec = await source.get(e.id);
                            if (rec) downloadCsv(`vteeee-history-${e.id}.csv`, resultsToCsv(rec.results));
                          })
                        }
                      >
                        CSV
                      </button>
                      <button className="btn btn-sm" onClick={() => startEdit(e)}>
                        Tag/Note
                      </button>
                      <button
                        className="btn btn-sm btn-danger"
                        onClick={() => void withBusy(e.id, async () => {
                          await source.del(e.id);
                          await reload();
                        })}
                      >
                        Delete
                      </button>
                    </div>
                  </div>

                  {editing === e.id && (
                    <div className="history-editor">
                      <input
                        placeholder="tags (comma-separated)  例: c2, phishing"
                        value={tagsDraft}
                        onChange={(ev) => setTagsDraft(ev.target.value)}
                      />
                      <textarea
                        placeholder="note / メモ"
                        rows={2}
                        value={noteDraft}
                        onChange={(ev) => setNoteDraft(ev.target.value)}
                      />
                      <div className="panel-actions">
                        <button
                          className="btn btn-sm btn-primary"
                          onClick={() =>
                            void (async () => {
                              const tags = tagsDraft
                                .split(',')
                                .map((t) => t.trim())
                                .filter(Boolean);
                              await source.update(e.id, { tags, note: noteDraft });
                              setEditing(null);
                              await reload();
                            })()
                          }
                        >
                          Save
                        </button>
                        <button className="btn btn-sm" onClick={() => setEditing(null)}>
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="modal-foot">
          <span className="hint" style={{ marginRight: 'auto' }}>
            保持 {retention} 日 · {source.shared ? 'KV(共有)' : '端末内'}
          </span>
          <button
            className="btn"
            disabled={!entries.length}
            onClick={() =>
              void (async () => {
                if (!window.confirm('Clear all history? / 履歴を全消去しますか？')) return;
                await source.clear();
                await reload();
              })()
            }
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
