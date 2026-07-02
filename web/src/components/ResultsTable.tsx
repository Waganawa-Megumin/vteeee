import { useMemo, useState } from 'react';
import type { NormalizedResult } from '@vteeee/shared';
import { useStore } from '../state/store';
import { GtiBadge, ShodanChips, VerdictBadge } from './Badges';
import { detectionRatio, verdictRank } from '../lib/verdict';
import { downloadCsv, resultsToCsv } from '../lib/csv-export';
import { SiemQueryDialog } from './SiemQueryDialog';

type SortKey = 'value' | 'type' | 'verdict' | 'detections' | 'reputation';

function contextCell(r: NormalizedResult): string {
  if (r.ip) return [r.ip.country, r.ip.asOwner].filter(Boolean).join(' · ');
  if (r.domain)
    return [r.domain.registrar, r.domain.categories ? Object.values(r.domain.categories)[0] : '']
      .filter(Boolean)
      .join(' · ');
  if (r.url) return r.url.title ?? r.url.finalUrl ?? '';
  if (r.file) return r.file.threatLabel ?? r.file.typeDescription ?? '';
  return '';
}

export function ResultsTable() {
  const order = useStore((s) => s.order);
  const results = useStore((s) => s.results);
  const select = useStore((s) => s.select);
  const selected = useStore((s) => s.selected);
  // Live: only when SOC Prime is configured on the proxy. Demo: always (uses the sample stub).
  const socprimeOn = useStore((s) => s.mode === 'demo' || Boolean(s.health?.socprime));
  const [sortKey, setSortKey] = useState<SortKey>('verdict');
  const [asc, setAsc] = useState(false);
  const [filter, setFilter] = useState('');
  const [siemOpen, setSiemOpen] = useState(false);

  const rows = useMemo(() => {
    let list = order.map((v) => results[v]).filter(Boolean);
    if (filter.trim()) {
      const f = filter.toLowerCase();
      list = list.filter(
        (r) =>
          r.value.toLowerCase().includes(f) || r.verdict.includes(f) || r.type.includes(f),
      );
    }
    const dir = asc ? 1 : -1;
    return [...list].sort((a, b) => {
      switch (sortKey) {
        case 'value':
          return dir * a.value.localeCompare(b.value);
        case 'type':
          return dir * a.type.localeCompare(b.type);
        case 'reputation':
          return dir * ((a.reputation ?? 0) - (b.reputation ?? 0));
        case 'detections':
          return (
            dir *
            ((a.detection?.malicious ?? 0) +
              (a.detection?.suspicious ?? 0) -
              ((b.detection?.malicious ?? 0) + (b.detection?.suspicious ?? 0)))
          );
        default:
          return dir * (verdictRank(a.verdict) - verdictRank(b.verdict));
      }
    });
  }, [order, results, filter, sortKey, asc]);

  function header(key: SortKey, label: string) {
    return (
      <th
        className={`sortable${sortKey === key ? ' active' : ''}`}
        onClick={() => {
          if (sortKey === key) setAsc(!asc);
          else {
            setSortKey(key);
            setAsc(false);
          }
        }}
      >
        {label}
        {sortKey === key ? (asc ? ' ▲' : ' ▼') : ''}
      </th>
    );
  }

  if (!order.length) return null;

  return (
    <section className="panel results-panel">
      <div className="panel-head">
        <h2>
          Results <span className="count">{rows.length}</span>
        </h2>
        <div className="spacer" />
        <input
          className="filter"
          placeholder="Filter…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        {socprimeOn && (
          <button className="btn btn-sm" onClick={() => setSiemOpen(true)} title="Generate a SIEM hunting query from these IOCs (SOC Prime)">
            SIEM query
          </button>
        )}
        <button
          className="btn btn-sm"
          onClick={() => downloadCsv('vteeee-results.csv', resultsToCsv(rows))}
        >
          Export CSV
        </button>
      </div>
      {siemOpen && <SiemQueryDialog iocs={rows.map((r) => r.value)} onClose={() => setSiemOpen(false)} />}
      <div className="table-wrap">
        <table className="results-table">
          <thead>
            <tr>
              {header('value', 'Indicator')}
              {header('type', 'Type')}
              {header('verdict', 'Verdict')}
              {header('detections', 'Detections')}
              {header('reputation', 'Rep')}
              <th>GTI</th>
              <th>Context</th>
              <th>VT</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr
                key={r.value}
                className={`${selected === r.value ? 'sel ' : ''}row-${r.verdict}`}
                onClick={() => select(r.value)}
              >
                <td className="mono ind" title={r.input !== r.value ? `raw: ${r.input}` : undefined}>
                  {r.value}
                </td>
                <td>
                  <span className={`badge type type-${r.type}`}>{r.type}</span>
                </td>
                <td>
                  <VerdictBadge verdict={r.verdict} status={r.status} />
                </td>
                <td className="mono">{detectionRatio(r)}</td>
                <td className="mono">{r.reputation ?? '—'}</td>
                <td>
                  <GtiBadge r={r} />
                </td>
                <td className="context">
                  {contextCell(r)}
                  <ShodanChips r={r} />
                </td>
                <td onClick={(e) => e.stopPropagation()}>
                  <a className="vt-link" href={r.links.gui} target="_blank" rel="noreferrer" title="Open in VirusTotal">
                    ↗
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
