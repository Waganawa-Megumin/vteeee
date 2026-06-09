import { useStore } from '../state/store';
import { GtiBadge, VerdictBadge } from './Badges';
import { detectionRatio } from '../lib/verdict';

function Field({ k, v, mono }: { k: string; v?: string; mono?: boolean }) {
  if (!v) return null;
  return (
    <div className="field">
      <div className="fk">{k}</div>
      <div className={`fv${mono ? ' mono' : ''}`}>{v}</div>
    </div>
  );
}

export function DetailPanel() {
  const selected = useStore((s) => s.selected);
  const results = useStore((s) => s.results);
  const select = useStore((s) => s.select);
  const r = selected ? results[selected] : null;
  if (!r) return null;

  return (
    <div className="detail-overlay" onClick={() => select(null)}>
      <aside className="detail-panel" onClick={(e) => e.stopPropagation()}>
        <div className="detail-head">
          <div>
            <div className="detail-title mono">{r.value}</div>
            <div className="detail-sub">
              <span className={`badge type type-${r.type}`}>{r.type}</span>{' '}
              <VerdictBadge verdict={r.verdict} status={r.status} /> <GtiBadge r={r} />
            </div>
          </div>
          <button className="btn btn-ghost" onClick={() => select(null)}>
            ✕
          </button>
        </div>

        {r.status !== 'success' && (
          <div className="detail-note">{r.errorMessage ?? `Status: ${r.status}`}</div>
        )}

        <div className="detail-grid">
          {r.detection && (
            <Field
              k="Detections"
              v={`${detectionRatio(r)}  ·  mal ${r.detection.malicious} · sus ${r.detection.suspicious} · harmless ${r.detection.harmless} · undet ${r.detection.undetected}`}
            />
          )}
          {r.reputation != null && <Field k="Reputation" v={String(r.reputation)} />}
          {r.totalVotes && (
            <Field
              k="Community votes"
              v={`harmless ${r.totalVotes.harmless} · malicious ${r.totalVotes.malicious}`}
            />
          )}
          {r.lastAnalysisDate && (
            <Field k="Last analysis" v={new Date(r.lastAnalysisDate).toLocaleString()} />
          )}
          {r.gti && (
            <Field
              k="GTI assessment"
              v={`${r.gti.verdict}${r.gti.severity ? ` · ${r.gti.severity}` : ''}${
                r.gti.threatScore != null ? ` · score ${r.gti.threatScore}` : ''
              }`}
            />
          )}

          {r.ip && (
            <>
              <Field k="Country" v={r.ip.country} />
              <Field k="ASN" v={r.ip.asn != null ? `AS${r.ip.asn}` : undefined} />
              <Field k="AS owner" v={r.ip.asOwner} />
              <Field k="Network" v={r.ip.network} mono />
              <Field k="RIR" v={r.ip.rir} />
            </>
          )}
          {r.domain && (
            <>
              <Field k="Registrar" v={r.domain.registrar} />
              <Field
                k="Created"
                v={r.domain.creationDate ? new Date(r.domain.creationDate).toLocaleDateString() : undefined}
              />
              <Field
                k="Categories"
                v={
                  r.domain.categories
                    ? Object.entries(r.domain.categories)
                        .map(([s, c]) => `${c} (${s})`)
                        .join(', ')
                    : undefined
                }
              />
            </>
          )}
          {r.url && (
            <>
              <Field k="Final URL" v={r.url.finalUrl} mono />
              <Field k="Title" v={r.url.title} />
              <Field k="HTTP status" v={r.url.httpResponseCode != null ? String(r.url.httpResponseCode) : undefined} />
            </>
          )}
          {r.file && (
            <>
              <Field k="Name" v={r.file.meaningfulName} />
              <Field k="File type" v={r.file.typeDescription} />
              <Field k="Threat label" v={r.file.threatLabel} />
              <Field k="Size" v={r.file.size != null ? `${r.file.size} bytes` : undefined} />
              <Field k="MD5" v={r.file.md5} mono />
              <Field k="SHA-1" v={r.file.sha1} mono />
              <Field k="SHA-256" v={r.file.sha256} mono />
            </>
          )}
          {r.tags.length > 0 && <Field k="Tags" v={r.tags.join(', ')} />}
          {r.links.apiId && <Field k="VT URL id (base64)" v={r.links.apiId} mono />}
        </div>

        <a className="btn btn-primary detail-vt" href={r.links.gui} target="_blank" rel="noreferrer">
          Open in VirusTotal ↗
        </a>

        {r.raw != null && (
          <details className="raw">
            <summary>Raw VT attributes</summary>
            <pre>{JSON.stringify(r.raw, null, 2)}</pre>
          </details>
        )}
      </aside>
    </div>
  );
}
