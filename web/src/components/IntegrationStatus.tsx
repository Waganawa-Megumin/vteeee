import { useStore } from '../state/store';

function Chip({ label, on, title }: { label: string; on: boolean; title: string }) {
  return (
    <span className={`intg-chip ${on ? 'on' : 'off'}`} title={title}>
      <span className="intg-dot" aria-hidden />
      {label}
    </span>
  );
}

/**
 * Header readout of which integrations are live, from the proxy /health.
 * Click to open Settings (where the optional ones are toggled / documented).
 */
export function IntegrationStatus({ onManage }: { onManage: () => void }) {
  const mode = useStore((s) => s.mode);
  const health = useStore((s) => s.health);
  const settings = useStore((s) => s.settings);

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
  const shodanOn = Boolean(health?.shodan) && settings.shodan !== false;

  return (
    <button className="intg-cluster" onClick={onManage} title="Integrations — click to manage & see setup">
      <span className="mode-pill live">LIVE</span>
      {!reachable ? (
        <Chip label="proxy?" on={false} title="Proxy /health not reachable — check the proxy URL in Settings" />
      ) : (
        <>
          <Chip
            label="VT"
            on={Boolean(health?.vtKey)}
            title={health?.vtKey ? 'VirusTotal / GTI key configured (base)' : 'VT key missing on the proxy'}
          />
          <Chip
            label="Shodan"
            on={shodanOn}
            title={
              health?.shodan
                ? settings.shodan !== false
                  ? 'Shodan OSINT active — IPs get ports / services / CVEs'
                  : 'Shodan key present, but enrichment is turned OFF in Settings'
                : 'Optional — no SHODAN_API_KEY on the proxy'
            }
          />
          <Chip
            label="DomainTools"
            on={Boolean(health?.domaintools) && settings.domaintools !== false}
            title={
              health?.domaintools
                ? settings.domaintools !== false
                  ? 'DomainTools Iris active — domains (Enrich) & IPs (reverse)'
                  : 'DomainTools creds present, but turned OFF in Settings'
                : 'Optional — no DomainTools creds on the proxy'
            }
          />
          <Chip
            label="DNSLytics"
            on={Boolean(health?.dnslytics) && settings.dnslytics !== false}
            title={
              health?.dnslytics
                ? settings.dnslytics !== false
                  ? 'DNSLytics active — IP (IPInfo) + domain (HostingHistory)'
                  : 'DNSLytics key present, but turned OFF in Settings'
                : 'Optional — no DNSLYTICS_API_KEY on the proxy'
            }
          />
          <Chip
            label="Intel471"
            on={Boolean(health?.intel471) && settings.intel471 !== false}
            title={
              health?.intel471
                ? settings.intel471 !== false
                  ? 'Intel 471 (Titan) active — IOC intel on all types'
                  : 'Intel 471 creds present, but turned OFF in Settings'
                : 'Optional — no INTEL471_API_USER/KEY on the proxy'
            }
          />
          <Chip
            label="CYFIRMA"
            on={Boolean(health?.cyfirma) && settings.cyfirma !== false}
            title={
              health?.cyfirma
                ? settings.cyfirma !== false
                  ? 'CYFIRMA DeCYFIR active — risk dossier + attribution on all types'
                  : 'CYFIRMA key present, but turned OFF in Settings'
                : 'Optional — no CYFIRMA_API_KEY on the proxy'
            }
          />
          <Chip
            label="ThreatVision"
            on={Boolean(health?.threatvision) && settings.threatvision !== false}
            title={
              health?.threatvision
                ? settings.threatvision !== false
                  ? 'TeamT5 ThreatVision active — APT attribution (IP/domain = 1 AAP each, hash = 0 AAP)'
                  : 'ThreatVision creds present, but turned OFF in Settings'
                : 'Optional — no THREATVISION credentials on the proxy'
            }
          />
          <Chip
            label="Claude"
            on={Boolean(health?.claude)}
            title={health?.claude ? 'Claude smart-parse available' : 'Optional — no ANTHROPIC_API_KEY on the proxy'}
          />
        </>
      )}
    </button>
  );
}
