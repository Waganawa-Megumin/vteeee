import { useState } from 'react';
import type { SocPrimeRule } from '@vteeee/shared';

/** One SOC Prime detection rule — severity chip, metadata, expandable translation + copy, TDM link. */
export function RuleCard({ r }: { r: SocPrimeRule }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  async function copy() {
    if (!r.translation) return;
    try {
      await navigator.clipboard.writeText(r.translation);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked */
    }
  }
  const meta = [
    r.techniques?.length ? r.techniques.join(', ') : '',
    r.tactics?.length ? r.tactics.join(', ') : '',
  ]
    .filter(Boolean)
    .join(' · ');
  return (
    <div className="rule-card">
      <div className="rule-card-head">
        <span className={`chip level-${(r.level ?? '').toLowerCase()}`}>{r.level ?? '—'}</span>
        <span className="rule-name">{r.name ?? r.id ?? 'Untitled rule'}</span>
      </div>
      {r.description && <div className="rule-desc">{r.description}</div>}
      <div className="rule-meta">
        {r.actors?.length ? <span>👤 {r.actors.join(', ')}</span> : null}
        {meta ? <span>🎯 {meta}</span> : null}
        {r.author ? <span>✍ {r.author}</span> : null}
        {r.status ? <span>· {r.status}</span> : null}
      </div>
      <div className="rule-actions">
        {r.translation && (
          <button className="btn btn-sm btn-ghost" onClick={() => setOpen((o) => !o)}>
            {open ? 'Hide query ▾' : 'Show query ▸'}
          </button>
        )}
        {r.translation && (
          <button className="btn btn-sm btn-ghost" onClick={copy}>
            {copied ? '✓ Copied' : 'Copy'}
          </button>
        )}
        {r.url && (
          <a className="btn btn-sm btn-ghost" href={r.url} target="_blank" rel="noreferrer">
            Open in TDM ↗
          </a>
        )}
      </div>
      {open && r.translation && <textarea className="siem-output mono" readOnly rows={8} value={r.translation} />}
    </div>
  );
}
