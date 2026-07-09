import { useEffect, useMemo, useState } from 'react';
import type { EnrichableType, NormalizedResult } from '@vteeee/shared';
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
  const setNavOrder = useStore((s) => s.setNavOrder);
  // Live: only when SOC Prime is configured on the proxy. Demo: always (uses the sample stub).
  const socprimeOn = useStore((s) => s.mode === 'demo' || Boolean(s.health?.socprime));
  const monitorAvailable = useStore((s) => s.mode === 'demo' || Boolean(s.health?.shodan));
  const addMonitor = useStore((s) => s.addMonitor);
  const monitors = useStore((s) => s.monitors);
  const campaigns = useStore((s) => s.campaigns);
  const addCampaignIocs = useStore((s) => s.addCampaignIocs);
  const [sortKey, setSortKey] = useState<SortKey>('verdict');
  const [asc, setAsc] = useState(false);
  const [filter, setFilter] = useState('');
  const [siemOpen, setSiemOpen] = useState(false);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [campaignSel, setCampaignSel] = useState('');

  function toggle(value: string) {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });
  }

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

  // Publish the VISIBLE row order so the detail panel's ‹ / › navigation (and ←/→ keys) step through
  // exactly what the analyst sees here — respecting the current sort and filter, not raw input order.
  useEffect(() => {
    setNavOrder(rows.map((r) => r.value));
  }, [rows, setNavOrder]);

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

  const selectedIocs = rows.filter((r) => checked.has(r.value)).map((r) => r.value);
  const checkedRows = rows.filter((r) => checked.has(r.value));
  function addToCampaign() {
    if (!campaignSel || !checkedRows.length) return;
    const iocs = checkedRows
      .filter((r) => r.type !== 'unknown')
      .map((r) => ({ value: r.value, type: r.type as EnrichableType }));
    if (iocs.length) void addCampaignIocs(campaignSel, iocs);
  }
  const allShownChecked = rows.length > 0 && rows.every((r) => checked.has(r.value));
  function toggleAll() {
    setChecked((prev) => {
      const next = new Set(prev);
      if (allShownChecked) rows.forEach((r) => next.delete(r.value));
      else rows.forEach((r) => next.add(r.value));
      return next;
    });
  }

  const isIp = (r: NormalizedResult) => r.type === 'ipv4' || r.type === 'ipv6';
  const checkedIps = rows.filter((r) => checked.has(r.value) && isIp(r));
  /** Tick the IP rows Shodan has no data on — the best monitor candidates (Shodan will start scanning them). */
  function selectNoShodanIps() {
    setChecked((prev) => {
      const next = new Set(prev);
      rows.forEach((r) => {
        if (isIp(r) && !r.shodan?.found && !monitors[r.value]) next.add(r.value);
      });
      return next;
    });
  }
  function bulkMonitor() {
    checkedIps.forEach((r) => void addMonitor(r.value, r));
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
          <button
            className="btn btn-sm"
            onClick={() => setSiemOpen(true)}
            title={
              selectedIocs.length
                ? `Generate a SIEM hunting query from the ${selectedIocs.length} checked IOC(s)`
                : 'Tick the rows to include, then generate a SIEM hunting query (SOC Prime)'
            }
          >
            SIEM query{selectedIocs.length ? ` (${selectedIocs.length})` : ''}
          </button>
        )}
        {monitorAvailable && (
          <>
            <button
              className="btn btn-sm"
              onClick={selectNoShodanIps}
              title="Tick the IP rows Shodan has no data on — the best monitor candidates"
            >
              No-Shodan IPs
            </button>
            <button
              className="btn btn-sm"
              disabled={!checkedIps.length}
              onClick={bulkMonitor}
              title={
                checkedIps.length
                  ? `Register the ${checkedIps.length} checked IP(s) to Shodan Monitor + snapshot their enrichment`
                  : 'Tick IP rows, then bulk-register them to Shodan Monitor'
              }
            >
              Monitor{checkedIps.length ? ` (${checkedIps.length})` : ''}
            </button>
          </>
        )}
        {Object.keys(campaigns).length > 0 && (
          <>
            <select
              className="filter"
              value={campaignSel}
              onChange={(e) => setCampaignSel(e.target.value)}
              title="Add the checked IOCs to a pre-registered CP-Mon campaign"
              aria-label="Campaign"
            >
              <option value="">Campaign…</option>
              {Object.values(campaigns)
                .sort((a, b) => a.name.localeCompare(b.name))
                .map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
            </select>
            <button
              className="btn btn-sm"
              disabled={!campaignSel || !checkedRows.length}
              onClick={addToCampaign}
              title={
                checkedRows.length
                  ? 'Register the checked IOCs to the selected campaign (CP-Mon)'
                  : 'Tick rows, pick a campaign, then add'
              }
            >
              ＋ Campaign{checkedRows.length ? ` (${checkedRows.length})` : ''}
            </button>
          </>
        )}
        <button
          className="btn btn-sm"
          onClick={() => downloadCsv('vteeee-results.csv', resultsToCsv(rows))}
        >
          Export CSV
        </button>
      </div>
      {siemOpen && (
        <SiemQueryDialog
          iocs={selectedIocs.length ? selectedIocs : rows.map((r) => r.value)}
          selected={selectedIocs.length > 0}
          onClose={() => setSiemOpen(false)}
        />
      )}
      <div className="table-wrap">
        <table className="results-table">
          <thead>
            <tr>
              <th className="cb-col">
                <input
                  type="checkbox"
                  checked={allShownChecked}
                  onChange={toggleAll}
                  title={allShownChecked ? 'Deselect all shown' : 'Select all shown'}
                />
              </th>
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
                <td className="cb-col" onClick={(e) => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={checked.has(r.value)}
                    onChange={() => toggle(r.value)}
                    aria-label={`Select ${r.value}`}
                  />
                </td>
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
                  {monitors[r.value] ? (
                    <span className="ctx-mon" title="In the IP-Mon watchlist">
                      monitored
                    </span>
                  ) : (
                    isIp(r) &&
                    !r.shodan?.found && (
                      <span className="ctx-hint" title="Shodan has no data — a good monitor candidate">
                        no Shodan data
                      </span>
                    )
                  )}
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
