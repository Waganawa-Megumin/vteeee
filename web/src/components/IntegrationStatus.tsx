import { useState } from 'react';
import { useStore } from '../state/store';

/**
 * Compact header readout of which integrations are live. Collapsed to just the mode pill + a count
 * (so it never overflows the header on small screens); click LIVE to drop down the full on/off list.
 */
export function IntegrationStatus({ onManage }: { onManage: () => void }) {
  const mode = useStore((s) => s.mode);
  const health = useStore((s) => s.health);
  const settings = useStore((s) => s.settings);
  const [open, setOpen] = useState(false);

  if (mode === 'demo') {
    return (
      <button
        className="intg-cluster"
        onClick={onManage}
        title="Demo mode — bundled sample data. Add a proxy URL in Settings to go live."
      >
        <span className="mode-pill demo">DEMO</span>
      </button>
    );
  }

  const reachable = health?.ok ?? false;
  const optional = (present?: boolean, on?: boolean) =>
    present ? (on !== false ? 'active' : 'key set · off in Settings') : 'not configured';

  const items: { label: string; on: boolean; note: string }[] = reachable
    ? [
        { label: 'VirusTotal / GTI', on: Boolean(health?.vtKey), note: health?.vtKey ? 'base key configured' : 'MISSING — required' },
        { label: 'Shodan', on: Boolean(health?.shodan) && settings.shodan !== false, note: optional(health?.shodan, settings.shodan) },
        { label: 'MaxMind', on: Boolean(health?.maxmind) && settings.maxmind !== false, note: optional(health?.maxmind, settings.maxmind) },
        { label: 'AbuseIPDB', on: Boolean(health?.abuseipdb) && settings.abuseipdb !== false, note: optional(health?.abuseipdb, settings.abuseipdb) },
        { label: 'urlscan', on: Boolean(health?.urlscan), note: health?.urlscan ? 'active — 魚拓' : 'not configured' },
        { label: 'DomainTools', on: Boolean(health?.domaintools) && settings.domaintools !== false, note: optional(health?.domaintools, settings.domaintools) },
        { label: 'DNSLytics', on: Boolean(health?.dnslytics) && settings.dnslytics !== false, note: optional(health?.dnslytics, settings.dnslytics) },
        { label: 'Intel 471', on: Boolean(health?.intel471) && settings.intel471 !== false, note: optional(health?.intel471, settings.intel471) },
        { label: 'CYFIRMA', on: Boolean(health?.cyfirma) && settings.cyfirma !== false, note: optional(health?.cyfirma, settings.cyfirma) },
        { label: 'ThreatVision', on: Boolean(health?.threatvision) && settings.threatvision !== false, note: optional(health?.threatvision, settings.threatvision) },
        { label: 'Recorded Future', on: Boolean(health?.recordedfuture) && settings.recordedfuture !== false, note: optional(health?.recordedfuture, settings.recordedfuture) },
        { label: 'SOC Prime', on: Boolean(health?.socprime), note: health?.socprime ? 'active — SIEM rules/queries' : 'not configured' },
        { label: 'Claude', on: Boolean(health?.claude), note: health?.claude ? 'active — smart-parse' : 'not configured' },
      ]
    : [];
  const activeCount = items.filter((i) => i.on).length;

  return (
    <div className="intg-wrap">
      <button
        className={`intg-cluster${open ? ' open' : ''}`}
        onClick={() => setOpen((o) => !o)}
        title="Integrations — click to see which are live"
        aria-expanded={open}
      >
        <span className="mode-pill live">LIVE</span>
        {reachable ? (
          <span className="intg-summary">
            {activeCount} active <span className="intg-caret">▾</span>
          </span>
        ) : (
          <span className="intg-summary warn">
            proxy? <span className="intg-caret">▾</span>
          </span>
        )}
      </button>

      {open && (
        <>
          <div className="intg-backdrop" onClick={() => setOpen(false)} />
          <div className="intg-menu" role="menu">
            <div className="intg-menu-head">
              <span>Integrations</span>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => {
                  setOpen(false);
                  onManage();
                }}
              >
                Manage ⚙
              </button>
            </div>
            {!reachable ? (
              <div className="intg-menu-row off">
                <span className="intg-dot" />
                <span className="intg-menu-label">proxy /health not reachable</span>
                <span className="intg-menu-state">check the proxy URL in Settings</span>
              </div>
            ) : (
              items.map((i) => (
                <div key={i.label} className={`intg-menu-row ${i.on ? 'on' : 'off'}`}>
                  <span className="intg-dot" />
                  <span className="intg-menu-label">{i.label}</span>
                  <span className="intg-menu-state">{i.note}</span>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
}
