export function EmptyState() {
  return (
    <div className="empty-state">
      <svg className="es-mark" viewBox="0 0 64 64" aria-hidden="true">
        <rect width="64" height="64" rx="14" style={{ fill: 'var(--bg3)', stroke: 'var(--line)' }} />
        <path
          d="M15 19 L32 47 L49 19"
          fill="none"
          strokeWidth={7}
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{ stroke: 'var(--accent)' }}
        />
        <circle cx="32" cy="51" r="3.6" style={{ fill: 'var(--text)' }} />
      </svg>
      <h3>Ready when you are</h3>
      <p>
        Paste indicators on the left, then <b>Parse</b> → <b>Enrich</b>. Results appear here —
        sortable, with per-row detail and links straight to VirusTotal.
      </p>
      <div className="empty-chips">
        <span className="badge type type-ipv4">IP</span>
        <span className="badge type type-domain">domain</span>
        <span className="badge type type-url">URL</span>
        <span className="badge type type-sha256">hash</span>
      </div>
    </div>
  );
}
