import { useState } from 'react';
import type { SocPrimeQueryResult } from '@vteeee/shared';
import { useStore } from '../state/store';

/** SIEM formats SOC Prime Uncoder AI supports for IOC → query generation. */
const SIEM_FORMATS: { value: string; label: string }[] = [
  { value: 'splunk', label: 'Splunk Query' },
  { value: 'ala', label: 'Microsoft Sentinel Query' },
  { value: 'mdatp', label: 'Microsoft Defender for Endpoint' },
  { value: 'qradar', label: 'IBM QRadar Query' },
  { value: 'elasticsearch', label: 'Elasticsearch Query' },
  { value: 'humio', label: 'CrowdStrike NG SIEM / LogScale' },
  { value: 'crowdstrike', label: 'CrowdStrike Endpoint Security' },
  { value: 'chronicle-query', label: 'Google SecOps Query' },
  { value: 'sumologic', label: 'Sumo Logic Query' },
  { value: 'securonix', label: 'Securonix Query' },
  { value: 's1-events', label: 'SentinelOne Events Query' },
  { value: 'carbonblack', label: 'VMware Carbon Black Cloud' },
  { value: 'carbonblack-edr', label: 'VMware Carbon Black EDR' },
  { value: 'fireeye-helix', label: 'FireEye Helix Query' },
  { value: 'rsa_netwitness', label: 'RSA NetWitness Query' },
  { value: 'graylog', label: 'Graylog Query' },
  { value: 'logpoint', label: 'LogPoint Query' },
  { value: 'arcsight-keyword', label: 'ArcSight Query' },
  { value: 'qualys', label: 'Qualys IOC Query' },
  { value: 'snowflake', label: 'Snowflake Query' },
];

/**
 * SOC Prime Uncoder AI — turn the current IOC set into a ready-to-run SIEM hunting query.
 * `iocs` are the indicator values currently shown in the results table.
 */
export function SiemQueryDialog({ iocs, onClose }: { iocs: string[]; onClose: () => void }) {
  const run = useStore((s) => s.socprimeQuery);
  const [siemType, setSiemType] = useState('splunk');
  const [iocsPerQuery, setIocsPerQuery] = useState(25);
  const [includeSourceIp, setIncludeSourceIp] = useState(false);
  const [state, setState] = useState<{ loading: boolean; data?: SocPrimeQueryResult }>({ loading: false });
  const [copied, setCopied] = useState(false);

  async function generate() {
    setCopied(false);
    setState({ loading: true });
    const data = await run(iocs.join('\n'), { siemType, iocsPerQuery, includeSourceIp });
    setState({ loading: false, data });
  }

  const queries = state.data?.queries ?? [];
  const joined = queries.join('\n\n');

  async function copy() {
    try {
      await navigator.clipboard.writeText(joined);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked */
    }
  }

  const label = SIEM_FORMATS.find((f) => f.value === siemType)?.label ?? siemType;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h2>SIEM hunting query · SOC Prime</h2>
          <button className="btn btn-ghost" onClick={onClose}>
            ✕
          </button>
        </div>
        <div className="modal-body">
          <p className="hint">
            Generate a hunting query for <strong>{iocs.length}</strong> indicator{iocs.length === 1 ? '' : 's'}{' '}
            (the results currently shown) via SOC Prime Uncoder AI. Private/reserved IPs are dropped automatically.
          </p>

          <div className="fld-row">
            <label className="fld">
              <span className="fld-label">SIEM / query format</span>
              <select value={siemType} onChange={(e) => setSiemType(e.target.value)}>
                {SIEM_FORMATS.map((f) => (
                  <option key={f.value} value={f.value}>
                    {f.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="fld">
              <span className="fld-label">IOCs / query</span>
              <input
                type="number"
                min={25}
                max={300}
                value={iocsPerQuery}
                onChange={(e) => setIocsPerQuery(Number(e.target.value) || 25)}
              />
            </label>
          </div>
          <label className="chk">
            <input type="checkbox" checked={includeSourceIp} onChange={(e) => setIncludeSourceIp(e.target.checked)} />
            Also match source IPs (not just destination)
          </label>

          <div className="siem-actions">
            <button className="btn btn-primary" onClick={generate} disabled={state.loading || !iocs.length}>
              {state.loading ? 'Generating…' : `Generate ${label}`}
            </button>
            {queries.length > 0 && (
              <button className="btn btn-sm" onClick={copy}>
                {copied ? '✓ Copied' : 'Copy'}
              </button>
            )}
          </div>

          {state.data?.error && <div className="detail-note">{state.data.error}</div>}
          {state.data && !state.data.error && queries.length === 0 && (
            <div className="detail-note">No query returned for this format.</div>
          )}
          {queries.length > 0 && (
            <>
              {state.data?.iocCount != null && (
                <p className="hint">Built from {state.data.iocCount} IOCs · {queries.length} query(ies).</p>
              )}
              <textarea className="siem-output mono" readOnly value={joined} rows={14} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
