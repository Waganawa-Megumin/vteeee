import { indKey, useStore } from '../state/store';
import { TypeBadge } from './Badges';

export function ParsePreview() {
  const parsed = useStore((s) => s.parsed);
  const stats = useStore((s) => s.stats);
  const includeMap = useStore((s) => s.includeMap);
  const toggleInclude = useStore((s) => s.toggleInclude);
  const setAllIncluded = useStore((s) => s.setAllIncluded);
  const enrich = useStore((s) => s.enrich);
  const running = useStore((s) => s.running);

  if (!stats) return null;
  const selectedCount = parsed.filter((i) => includeMap[indKey(i)]).length;

  return (
    <section className="panel preview-panel">
      <div className="panel-head">
        <h2>Parsed indicators</h2>
        <div className="spacer" />
        <button className="btn btn-sm" onClick={() => setAllIncluded(true)}>
          All
        </button>
        <button className="btn btn-sm" onClick={() => setAllIncluded(false)}>
          None
        </button>
      </div>

      <div className="stat-row">
        <span className="stat strong">
          <b>{stats.enrichable}</b> enrichable
        </span>
        <span className="stat">{stats.unique} unique</span>
        <span className="stat">{stats.duplicates} dup</span>
        <span className="stat">{stats.private} private</span>
        <span className="stat">{stats.unknown} unknown</span>
      </div>

      <div className="preview-list">
        {parsed.map((i) => {
          const k = indKey(i);
          const disabled = i.type === 'unknown';
          return (
            <label key={k} className={`preview-row${i.excludedReason ? ' excluded' : ''}`}>
              <input
                type="checkbox"
                disabled={disabled}
                checked={!!includeMap[k]}
                onChange={() => toggleInclude(k)}
              />
              <TypeBadge type={i.type} />
              <span className="pv-value">{i.value || i.input}</span>
              {i.private && <span className="flag flag-private">private · not sent</span>}
              {i.type === 'unknown' && <span className="flag flag-unknown">unrecognized</span>}
              {i.input !== i.value && i.type !== 'unknown' && (
                <span className="pv-raw" title="original input">← {i.input}</span>
              )}
            </label>
          );
        })}
      </div>

      <div className="panel-actions">
        <button
          className="btn btn-primary"
          onClick={() => void enrich()}
          disabled={running || selectedCount === 0}
        >
          {running ? 'Enriching…' : `Enrich ${selectedCount} selected`}
        </button>
      </div>
    </section>
  );
}
