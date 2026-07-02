import { useState } from 'react';
import type { SocPrimeRuleSearchParams, SocPrimeRuleSearchResult } from '@vteeee/shared';
import { useStore } from '../state/store';
import { SIEM_FORMATS } from '../lib/siemFormats';
import { RuleCard } from './RuleCard';

const LEVELS = ['', 'low', 'medium', 'high', 'critical'];

/**
 * SOC Prime detection-rule search — find Sigma rules by free text / ATT&CK actor / tool / technique /
 * severity, translated into the chosen SIEM format. Prefill props let the detail panel pivot from an
 * attributed adversary or malware family straight into matching detections.
 */
export function RuleSearchDialog({
  onClose,
  prefillActor,
  prefillTool,
  prefillQuery,
}: {
  onClose: () => void;
  prefillActor?: string;
  prefillTool?: string;
  prefillQuery?: string;
}) {
  const search = useStore((s) => s.socprimeRules);
  const [siemType, setSiemType] = useState('splunk');
  const [query, setQuery] = useState(prefillQuery ?? '');
  const [actor, setActor] = useState(prefillActor ?? '');
  const [tool, setTool] = useState(prefillTool ?? '');
  const [techniqueId, setTechniqueId] = useState('');
  const [level, setLevel] = useState('');
  const [page, setPage] = useState(1);
  const [state, setState] = useState<{ loading: boolean; data?: SocPrimeRuleSearchResult }>({ loading: false });

  async function runSearch(pageNumber = 1): Promise<void> {
    setPage(pageNumber);
    setState({ loading: true });
    const params: SocPrimeRuleSearchParams = {
      siemType,
      query: query.trim() || undefined,
      actor: actor.trim() || undefined,
      tool: tool.trim() || undefined,
      techniqueId: techniqueId.trim() || undefined,
      sigmaLevel: level || undefined,
      pageSize: 25,
      pageNumber,
    };
    setState({ loading: false, data: await search(params) });
  }

  const rules = state.data?.rules ?? [];
  const canSearch = Boolean(query.trim() || actor.trim() || tool.trim() || techniqueId.trim() || level);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>Detection rules · SOC Prime</h2>
          <button className="btn btn-ghost" onClick={onClose}>
            ✕
          </button>
        </div>
        <div className="modal-body">
          <p className="hint">
            Search SOC Prime's Sigma detection rules by keyword, ATT&amp;CK actor / tool / technique or severity —
            translated into your SIEM format.
          </p>

          <div className="fld-row">
            <label className="fld">
              <span className="fld-label">Keyword / Lucene query</span>
              <input
                placeholder="e.g. cobalt strike beacon"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && canSearch && runSearch(1)}
              />
            </label>
            <label className="fld">
              <span className="fld-label">Target SIEM</span>
              <select value={siemType} onChange={(e) => setSiemType(e.target.value)}>
                {SIEM_FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>
                    {f.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <div className="fld-row">
            <label className="fld">
              <span className="fld-label">ATT&amp;CK actor</span>
              <input placeholder="e.g. APT28" value={actor} onChange={(e) => setActor(e.target.value)} />
            </label>
            <label className="fld">
              <span className="fld-label">Tool / malware</span>
              <input placeholder="e.g. Mimikatz" value={tool} onChange={(e) => setTool(e.target.value)} />
            </label>
          </div>
          <div className="fld-row">
            <label className="fld">
              <span className="fld-label">Technique ID</span>
              <input placeholder="e.g. T1055" value={techniqueId} onChange={(e) => setTechniqueId(e.target.value)} />
            </label>
            <label className="fld">
              <span className="fld-label">Severity</span>
              <select value={level} onChange={(e) => setLevel(e.target.value)}>
                {LEVELS.map((l) => (
                  <option key={l} value={l}>
                    {l || 'any'}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className="siem-actions">
            <button className="btn btn-primary" onClick={() => runSearch(1)} disabled={state.loading || !canSearch}>
              {state.loading ? 'Searching…' : 'Search rules'}
            </button>
            {state.data?.total != null && !state.data.error && (
              <span className="hint">{state.data.total} match(es)</span>
            )}
          </div>

          {state.data?.error && <div className="detail-note">{state.data.error}</div>}
          {state.data && !state.data.error && rules.length === 0 && (
            <div className="detail-note">No detection rules matched.</div>
          )}

          {rules.length > 0 && (
            <>
              <div className="rule-list">
                {rules.map((r, i) => (
                  <RuleCard key={r.id ?? i} r={r} />
                ))}
              </div>
              <div className="siem-actions">
                <button className="btn btn-sm" onClick={() => runSearch(Math.max(1, page - 1))} disabled={page <= 1 || state.loading}>
                  ← Prev
                </button>
                <span className="hint">Page {page}</span>
                <button className="btn btn-sm" onClick={() => runSearch(page + 1)} disabled={rules.length < 25 || state.loading}>
                  Next →
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
