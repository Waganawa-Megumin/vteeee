import { useEffect, useRef, useState } from 'react';
import type {
  CyfirmaContext,
  CyfirmaRelated,
  CyfirmaSearch,
  DnslyticsContext,
  DomainToolsContext,
  EnrichableType,
  Intel471Context,
  Intel471Malware,
  Intel471Search,
  Intel471SearchItem,
  MaxmindContext,
  NormalizedResult,
  RecordedFutureContext,
  RfActorProfile,
  RfDetectionRule,
  RfMalwareProfile,
  RfRuleSearchResult,
  RfSandboxIntel,
  ShodanContext,
  ShodanInternetDb,
  ShodanService,
  SocPrimeQueryResult,
  SocPrimeRuleSearchResult,
  ThreatVisionAdversary,
  ThreatVisionContext,
  UrlscanResult,
} from '@vteeee/shared';
import { useStore } from '../state/store';
import { GtiBadge, VerdictBadge } from './Badges';
import { InfoTip } from './InfoTip';
import { detectionRatio } from '../lib/verdict';
import { resultToText } from '../lib/detailText';
import { exportResultPdf, type PdfMapImage } from '../lib/pdf-export';
import { RuleCard } from './RuleCard';
import { SIEM_FORMATS } from '../lib/siemFormats';

function Field({ k, v, mono }: { k: string; v?: string; mono?: boolean }) {
  if (!v) return null;
  return (
    <div className="field">
      <div className="fk">{k}</div>
      <div className={`fv${mono ? ' mono' : ''}`}>{v}</div>
    </div>
  );
}

function serviceLabel(s: ShodanService): string {
  return [s.port, s.product ?? s.module, s.version].filter(Boolean).join(' ');
}

/** Shodan OSINT block (IPs). Renders the host's ports, services, known CVEs and tags. */
function ShodanSection({ s, ip }: { s: ShodanContext; ip: string }) {
  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🛰
        </span>
        Shodan · OSINT
        {s.found && s.lastUpdate && (
          <span className="shodan-when">seen {new Date(s.lastUpdate).toLocaleDateString()}</span>
        )}
      </div>

      {!s.found ? (
        <div className="detail-note">{s.error ?? 'No Shodan record for this host.'}</div>
      ) : (
        <div className="detail-grid">
          <Field k="Org" v={s.org} />
          <Field k="ISP" v={s.isp && s.isp !== s.org ? s.isp : undefined} />
          <Field k="OS" v={s.os} />
          <Field k="Location" v={[s.city, s.country].filter(Boolean).join(', ') || undefined} />
          <Field k="ASN" v={s.asn} />
          {s.ports && s.ports.length > 0 && <Field k="Open ports" v={s.ports.join(', ')} mono />}
          {s.services && s.services.length > 0 && (
            <div className="field">
              <div className="fk">Services</div>
              <div className="fv chips">
                {s.services.map((svc, i) => (
                  <span key={`${svc.port}-${i}`} className="chip shodan mono">
                    {serviceLabel(svc)}
                  </span>
                ))}
              </div>
            </div>
          )}
          {s.vulns && s.vulns.length > 0 && (
            <div className="field">
              <div className="fk">Vulnerabilities</div>
              <div className="fv chips">
                {s.vulns.map((cve) => (
                  <a
                    key={cve}
                    className="chip shodan-vuln mono"
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noreferrer"
                    title="Open in NVD"
                  >
                    {cve}
                  </a>
                ))}
              </div>
            </div>
          )}
          {s.hostnames && s.hostnames.length > 0 && (
            <Field k="Hostnames" v={s.hostnames.join(', ')} mono />
          )}
          {s.tags && s.tags.length > 0 && (
            <div className="field">
              <div className="fk">Shodan tags</div>
              <div className="fv chips">
                {s.tags.map((t) => (
                  <span key={t} className="chip">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {s.found && (
        <a
          className="btn btn-ghost shodan-link"
          href={`https://www.shodan.io/host/${encodeURIComponent(ip)}`}
          target="_blank"
          rel="noreferrer"
        >
          Open in Shodan ↗
        </a>
      )}
    </div>
  );
}

function Chips({ items }: { items: string[] }) {
  return (
    <div className="fv chips">
      {items.map((t) => (
        <span key={t} className="chip">
          {t}
        </span>
      ))}
    </div>
  );
}

/** Country/region name plus its ISO code (and an EU marker), when present. */
function place(name?: string, code?: string, inEu?: boolean): string | undefined {
  if (!name && !code) return undefined;
  const base = [name, code ? `(${code})` : ''].filter(Boolean).join(' ');
  return inEu ? `${base} · EU` : base || undefined;
}
const pct = (n?: number): string | undefined => (n != null ? `${n}%` : undefined);

/** OSM zoom level roughly matched to the accuracy radius (km). */
function zoomForRadius(rk: number): number {
  if (rk <= 5) return 12;
  if (rk <= 20) return 10;
  if (rk <= 75) return 9;
  if (rk <= 250) return 7;
  if (rk <= 1000) return 5;
  return 4;
}

// Minimal surface of the Leaflet API we use — avoids the CJS default/namespace interop friction of
// @types/leaflet under a dynamic import, and keeps Leaflet fully lazy-loaded (only when a map shows).
interface LMapLike {
  setView(c: [number, number], z: number): LMapLike;
  invalidateSize(): void;
  remove(): void;
  removeLayer(layer: LLayerLike): void;
}
interface LLayerLike {
  addTo(m: LMapLike): LLayerLike;
  on(event: string, handler: () => void): LLayerLike;
}
interface LeafletApi {
  map(el: HTMLElement, opts?: Record<string, unknown>): LMapLike;
  tileLayer(url: string, opts?: Record<string, unknown>): LLayerLike;
  circle(c: [number, number], opts?: Record<string, unknown>): LLayerLike;
  circleMarker(c: [number, number], opts?: Record<string, unknown>): LLayerLike;
}

// Saturated violet for the accuracy overlay. The amber ring washed out on OpenStreetMap's warm beige
// tiles; violet has strong contrast against ALL OSM base features (beige land, green parks, blue water,
// grey/orange roads) and doesn't collide with the app's verdict palette (red/amber/green) or teal accent.
const MAP_RING = '#6d28d9';
const MAP_FILL = '#8b5cf6';
const MAP_HEIGHT_PX = 240; // must match the .maxmind-map height in app.css

/**
 * Largest integer Web-Mercator zoom at which a circle of `radiusKm` (at `lat`) still fits inside the
 * map's fixed height, with margin. Deterministic — depends only on the radius, latitude and the known
 * 240px map height, NOT on the container width or on fitBounds/layout timing (fitBounds was racing the
 * detail panel's slide-in and leaving the map zoomed in with the circle off-screen).
 */
function zoomToFitRadius(lat: number, radiusKm: number): number {
  const C = 156543.03392 * Math.cos((lat * Math.PI) / 180); // metres/pixel at zoom 0
  const diameterM = radiusKm * 1000 * 2 * 1.25; // circle diameter + 25% margin
  const z = Math.log2((C * MAP_HEIGHT_PX) / diameterM);
  return Math.max(2, Math.min(16, Math.floor(z)));
}

/**
 * Interactive OpenStreetMap (Leaflet) centred on the IP's coordinates, with a semi-transparent
 * circle drawn at the MaxMind accuracy radius so the "approximate area, not a point" nature is
 * visually obvious (reinforces the ToS disclaimer). Leaflet + its CSS load lazily on first render.
 * Tiles come from openstreetmap.org (keyless). Cross-origin tiles can't be captured by the copy-image
 * pass, so the container is marked data-noimage.
 */
function MaxmindMap({ lat, lon, radiusKm }: { lat: number; lon: number; radiusKm: number | null }) {
  const ref = useRef<HTMLDivElement>(null);
  // 'loading' until a tile paints; 'error' if tiles never load (network/OSM block) so we can say so.
  const [status, setStatus] = useState<'loading' | 'ok' | 'error'>('loading');
  useEffect(() => {
    let map: LMapLike | null = null;
    let cancelled = false;
    let ro: ResizeObserver | null = null;
    let noTileTimer: ReturnType<typeof setTimeout> | undefined;
    let loaded = 0;
    let errors = 0;
    let swapped = false;
    setStatus('loading');
    // Pick the zoom up front so the whole accuracy circle is framed regardless of layout timing.
    const zoom = zoomToFitRadius(lat, radiusKm && radiusKm > 0 ? radiusKm : 25);
    const TILE_URL = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
    void (async () => {
      const el = ref.current;
      if (!el) return;
      try {
        await import('leaflet/dist/leaflet.css');
        const mod = await import('leaflet');
        const L = ((mod as { default?: unknown }).default ?? mod) as unknown as LeafletApi;
        if (cancelled || !ref.current) return;
        map = L.map(el, { scrollWheelZoom: false, attributionControl: true }).setView([lat, lon], zoom);

        // Tiles load cross-origin so the copy-image pass can rasterize them (OSM sends CORS headers).
        // But if a CDN edge omits the ACAO header, a cross-origin tile is *blocked* and the map goes
        // blank — a real "sometimes it doesn't show". So on repeated tile errors with nothing painted
        // we transparently swap to a plain (non-cross-origin) layer: the map always displays; copy-image
        // just falls back to dropping the map if that layer later taints the canvas.
        const addTiles = (crossOrigin: boolean) => {
          const layer = L.tileLayer(TILE_URL, {
            maxZoom: 19,
            attribution: '© OpenStreetMap contributors',
            crossOrigin,
          });
          layer.on('tileload', () => {
            loaded++;
            if (!cancelled) setStatus('ok');
          });
          layer.on('tileerror', () => {
            errors++;
            if (!map) return;
            if (!swapped && crossOrigin && loaded === 0 && errors >= 3) {
              // Likely a missing CORS header — retry the same tiles without cross-origin so they paint.
              swapped = true;
              map.removeLayer(layer);
              addTiles(false);
            } else if (loaded === 0 && errors >= 8) {
              if (!cancelled) setStatus('error');
            }
          });
          layer.addTo(map!);
          return layer;
        };
        addTiles(true);

        // The accuracy-radius area, shaded — the whole point is "this is an area, not an address".
        if (radiusKm && radiusKm > 0) {
          L.circle([lat, lon], {
            radius: radiusKm * 1000,
            color: MAP_RING,
            weight: 2.5,
            opacity: 0.95,
            fillColor: MAP_FILL,
            fillOpacity: 0.22,
          }).addTo(map);
        }
        // Centre marker as a plain SVG dot with a white halo (no default PNG icon → no broken-image
        // path under bundlers; the halo keeps the dot visible over any map feature).
        L.circleMarker([lat, lon], {
          radius: 6,
          color: '#ffffff',
          weight: 2,
          fillColor: MAP_RING,
          fillOpacity: 1,
        }).addTo(map);
        // The detail panel slides in; re-measure the container and re-assert the framing once it has
        // settled so the tiles fill the box and the zoom (which frames the whole circle) is kept.
        const settle = () => {
          if (cancelled || !map) return;
          map.invalidateSize();
          map.setView([lat, lon], zoom);
        };
        setTimeout(settle, 80);
        setTimeout(settle, 400);
        // Resizing the detail panel (width steps) changes the container — re-measure so tiles refill
        // instead of leaving a grey strip. This is another common "the map half-disappeared" cause.
        if (typeof ResizeObserver !== 'undefined') {
          ro = new ResizeObserver(() => {
            if (!cancelled && map) map.invalidateSize();
          });
          ro.observe(el);
        }
        // If nothing has painted after 7s it's almost certainly the network / OSM blocking tiles.
        noTileTimer = setTimeout(() => {
          if (!cancelled && loaded === 0) setStatus('error');
        }, 7000);
      } catch {
        // offline / Leaflet failed to load — surface it; the coordinates + disclaimer still convey the area.
        if (!cancelled) setStatus('error');
      }
    })();
    return () => {
      cancelled = true;
      if (noTileTimer) clearTimeout(noTileTimer);
      ro?.disconnect();
      map?.remove();
    };
  }, [lat, lon, radiusKm]);
  // The map IS included in the copy-image (tiles load cross-origin so they rasterize; copyImage falls
  // back to dropping the map if a tile ever taints the canvas).
  return (
    <div className="maxmind-map-wrap">
      <div className="maxmind-map" ref={ref} />
      {status === 'error' && (
        <div className="maxmind-map-note" data-noimage="true">
          🗺 地図タイルを取得できませんでした（ネットワーク / OSM 側の可能性）。緯度経度・精度半径は上に表示しています。
        </div>
      )}
    </div>
  );
}

/**
 * MaxMind GeoIP geolocation block (IPs). Shows the full GeoIP2/Insights field set — place names
 * with confidence, network/ASN/ISP/domain, connection type, anonymizer (VPN/Tor/proxy) signals,
 * static-IP score, user counts and US demographics — plus an embedded OpenStreetMap.
 * Per MaxMind's ToS the accuracy radius is always shown with the coordinates, which mark an
 * approximate area (often ISP/city level), NOT a precise address.
 */
function MaxmindSection({ m }: { m: MaxmindContext }) {
  const hasCoords = m.latitude != null && m.longitude != null;
  const lat = m.latitude ?? 0;
  const lon = m.longitude ?? 0;
  const rk = m.accuracyRadius && m.accuracyRadius > 0 ? m.accuracyRadius : 50;
  const largeUrl = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=${zoomForRadius(rk)}/${lat}/${lon}`;

  const asn =
    m.asn != null ? [`AS${m.asn}`, m.asnOrganization].filter(Boolean).join(' ') : m.asnOrganization;
  const mcc = [m.mobileCountryCode, m.mobileNetworkCode].filter(Boolean).join(' / ');
  const income = m.averageIncome != null ? `$${m.averageIncome.toLocaleString()}` : undefined;
  const density = m.populationDensity != null ? `${m.populationDensity.toLocaleString()} /km²` : undefined;

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🗺
        </span>
        MaxMind · GeoIP
        {m.found && (m.country || m.city) && (
          <span className="shodan-when">{[m.city, m.countryCode].filter(Boolean).join(', ')}</span>
        )}
      </div>

      {!m.found ? (
        <div className="detail-note">
          {m.error ?? 'No MaxMind geolocation for this IP (reserved / not in the database).'}
        </div>
      ) : (
        <>
          <div className="detail-grid">
            {/* --- Place --- */}
            <Field
              k="Country"
              v={
                place(m.country, m.countryCode, m.countryInEu) &&
                [place(m.country, m.countryCode, m.countryInEu), pct(m.countryConfidence)]
                  .filter(Boolean)
                  .join(' · ')
              }
            />
            <Field
              k="Registered country"
              v={
                m.registeredCountryCode && m.registeredCountryCode !== m.countryCode
                  ? place(m.registeredCountry, m.registeredCountryCode, m.registeredCountryInEu)
                  : undefined
              }
            />
            <Field
              k="Represented country"
              v={place(m.representedCountry, m.representedCountryCode)}
            />
            <Field
              k="Region"
              v={
                m.subdivisions && m.subdivisions.length
                  ? [m.subdivisions.join(' › '), m.subdivisionCode ? `(${m.subdivisionCode})` : '']
                      .filter(Boolean)
                      .join(' ')
                  : undefined
              }
            />
            <Field
              k="City"
              v={m.city && [m.city, pct(m.cityConfidence)].filter(Boolean).join(' · ')}
            />
            <Field
              k="Postal"
              v={m.postal && [m.postal, pct(m.postalConfidence)].filter(Boolean).join(' · ')}
              mono
            />
            <Field k="Continent" v={m.continent} />
            <Field k="Time zone" v={m.timeZone} />
            <Field k="Avg income (US)" v={income} />
            <Field k="Pop. density (US)" v={density} />

            {/* --- Network / operator --- */}
            <Field k="Network" v={m.network} mono />
            <Field k="ASN" v={asn} />
            <Field k="ISP" v={m.isp} />
            <Field k="Organization" v={m.organization && m.organization !== m.isp ? m.organization : undefined} />
            <Field k="Domain" v={m.domain} mono />
            <Field k="Connection" v={m.connectionType} />
            <Field k="Mobile MCC/MNC" v={mcc || undefined} mono />

            {/* --- Anonymizer / VPN --- */}
            {m.anonymizerType && m.anonymizerType.length > 0 && (
              <div className="field">
                <div className="fk">Anonymizer</div>
                <div className="fv chips">
                  {m.anonymizerType.map((t) => (
                    <span key={t} className="chip shodan-vuln">
                      {t}
                    </span>
                  ))}
                  {m.anonymizerConfidence != null && (
                    <span className="chip">confidence {m.anonymizerConfidence}</span>
                  )}
                </div>
              </div>
            )}
            <Field k="VPN provider" v={m.providerName} />
            <Field
              k="Network last seen"
              v={m.networkLastSeen ? new Date(m.networkLastSeen).toLocaleDateString() : undefined}
            />

            {/* --- Risk / usage --- */}
            <Field k="Static IP score" v={m.staticIpScore != null ? m.staticIpScore.toFixed(2) : undefined} />
            <Field k="IP risk" v={m.ipRisk != null ? String(m.ipRisk) : undefined} />
            <Field k="User count" v={m.userCount != null ? m.userCount.toLocaleString() : undefined} />
            <Field k="User type" v={m.userType?.replace(/_/g, ' ')} />
            {m.confidenceFactors && m.confidenceFactors.length > 0 && (
              <div className="field">
                <div className="fk">Confidence factors</div>
                <div className="fv chips">
                  {m.confidenceFactors.map((f) => (
                    <span key={f.factor} className="chip">
                      {f.factor}
                      {f.influence != null ? ` ${f.influence}` : ''}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {hasCoords && (
            <div className="maxmind-geo">
              <div className="maxmind-coords mono">
                📍 {lat.toFixed(4)}, {lon.toFixed(4)}
                {m.accuracyRadius != null ? ` · accuracy radius ±${m.accuracyRadius} km` : ''}
              </div>
              {/* MaxMind ToS: the coordinates refer to an area, not a precise location. */}
              <div className="maxmind-approx">
                ⚠ Approximate area — the shaded circle is the
                {m.accuracyRadius != null ? ` ~${m.accuracyRadius} km` : ' estimated'} accuracy radius; the dot marks
                its centre (typically ISP / city level), <strong>not a precise address or household</strong>.
              </div>
              <MaxmindMap lat={lat} lon={lon} radiusKm={m.accuracyRadius ?? null} />
              <a className="btn btn-ghost shodan-link" href={largeUrl} target="_blank" rel="noreferrer">
                View larger map (OpenStreetMap) ↗
              </a>
            </div>
          )}
        </>
      )}

      {m.raw != null && (
        <details className="raw">
          <summary>Raw MaxMind data</summary>
          <pre>{JSON.stringify(m.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

/** DomainTools Iris block — Enrich for domains, Investigate reverse for IPs. */
function DomainToolsSection({ d }: { d: DomainToolsContext }) {
  const riskClass = (s?: number) => (s != null && s >= 70 ? 'chip shodan-vuln' : 'chip shodan');
  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🧭
        </span>
        DomainTools · Iris{d.mode === 'reverse-ip' ? ' (reverse IP)' : ''}
      </div>

      {!d.found ? (
        <div className="detail-note">
          {d.error ??
            (d.mode === 'reverse-ip' ? 'No domains hosted on this IP in Iris.' : 'No Iris record for this domain.')}
        </div>
      ) : d.mode === 'enrich' ? (
        <div className="detail-grid">
          {d.riskScore != null && (
            <div className="field">
              <div className="fk">Risk score</div>
              <div className="fv chips">
                <span className={riskClass(d.riskScore)}>{d.riskScore}</span>
                {d.riskComponents?.map((c) => (
                  <span key={c.name} className="chip">
                    {c.name} {c.riskScore}
                  </span>
                ))}
              </div>
            </div>
          )}
          <Field k="Created" v={d.created} />
          <Field k="First seen" v={d.firstSeen} />
          <Field k="Registrar" v={d.registrar} />
          <Field k="IP(s)" v={d.ips?.join(', ')} mono />
          <Field k="ASN" v={d.asns?.length ? d.asns.map((a) => `AS${a}`).join(', ') : undefined} />
          <Field k="Name servers" v={d.nameServers?.join(', ')} mono />
          <Field k="MX" v={d.mailServers?.join(', ')} mono />
          <Field k="SSL issuer" v={d.sslIssuer} />
          <Field k="SSL expires" v={d.sslNotAfter} />
          <Field
            k="Website"
            v={
              [d.websiteResponse ? `HTTP ${d.websiteResponse}` : '', d.serverType, d.websiteTitle]
                .filter(Boolean)
                .join(' · ') || undefined
            }
          />
          {d.tags && d.tags.length > 0 && (
            <div className="field">
              <div className="fk">Tags</div>
              <Chips items={d.tags} />
            </div>
          )}
        </div>
      ) : (
        <div className="detail-grid">
          <Field
            k="Domains on IP"
            v={d.hostedDomainCount != null ? d.hostedDomainCount.toLocaleString() : undefined}
          />
          {d.sampleDomains && d.sampleDomains.length > 0 && (
            <div className="field">
              <div className="fk">Sample domains</div>
              <div className="fv chips">
                {d.sampleDomains.map((s) => (
                  <span key={s.domain} className={riskClass(s.riskScore)}>
                    {s.domain}
                    {s.riskScore != null ? ` (${s.riskScore})` : ''}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw DomainTools data</summary>
          <pre>{JSON.stringify(d.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

/** DNSLytics block — IPInfo for IPs, DomainInfo for domains. */
function DnslyticsSection({ d }: { d: DnslyticsContext }) {
  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🌐
        </span>
        DNSLytics · {d.kind === 'ip' ? 'IP' : 'Domain (hosting history)'}
      </div>

      {!d.found ? (
        <div className="detail-note">{d.error ?? 'No DNSLytics record.'}</div>
      ) : d.kind === 'ip' ? (
        <div className="detail-grid">
          <Field k="ASN" v={d.asn != null ? `AS${d.asn}` : undefined} />
          <Field k="Org" v={d.org} />
          <Field k="ISP" v={d.isp && d.isp !== d.org ? d.isp : undefined} />
          <Field k="Network" v={d.network} mono />
          <Field k="Location" v={[d.city, d.country].filter(Boolean).join(', ') || undefined} />
          <Field k="Reverse DNS" v={d.hostname} mono />
          <Field k="Domains on IP" v={d.domainsOnIp != null ? d.domainsOnIp.toLocaleString() : undefined} />
          {d.hostedDomains && d.hostedDomains.length > 0 && (
            <div className="field">
              <div className="fk">Hosted domains</div>
              <div className="fv chips">
                {d.hostedDomains.map((dm) => (
                  <span key={dm} className="chip mono">
                    {dm}
                  </span>
                ))}
              </div>
            </div>
          )}
          <Field k="Threat" v={d.threat} />
        </div>
      ) : (
        <div className="detail-grid">
          <Field k="IP history (A/AAAA)" v={d.ips?.join(', ')} mono />
          <Field k="Name servers" v={d.nameServers?.join(', ')} mono />
          <Field k="Mail servers" v={d.mailServers?.join(', ')} mono />
          <Field k="SPF" v={d.spf?.join('  |  ')} mono />
        </div>
      )}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw DNSLytics data</summary>
          <pre>{JSON.stringify(d.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

interface IntelCount {
  label: string;
  count: number;
  items?: Intel471SearchItem[];
}

/** Non-zero Global Search categories, each with its top drill-down items (when available). */
function intelCounts(s: Intel471Search): IntelCount[] {
  const it = s.items ?? {};
  const entries: { label: string; count?: number; items?: Intel471SearchItem[] }[] = [
    { label: 'reports', count: s.reports, items: it.reports },
    { label: 'malware', count: s.malwareReports, items: it.malwareReports },
    { label: 'actors', count: s.actors, items: it.actors },
    { label: 'entities', count: s.entities, items: it.entities },
    { label: 'events', count: s.events, items: it.events },
    { label: 'posts', count: s.posts, items: it.posts },
    { label: 'news', count: s.news, items: it.news },
    { label: 'IOCs', count: s.iocs, items: it.iocs },
    { label: 'indicators', count: s.indicators, items: it.indicators },
    { label: 'credentials', count: s.credentials, items: it.credentials },
    { label: 'cred sets', count: s.credentialSets },
    { label: 'data-leak posts', count: s.dataLeakPosts },
    { label: 'breach alerts', count: s.breachAlerts },
    { label: 'CVEs', count: s.cveReports, items: it.cveReports },
  ];
  return entries.filter((e): e is IntelCount => typeof e.count === 'number' && e.count > 0);
}

/** Intel 471 (Titan) IOC block — auto IOC context + on-demand Global Search counts. */
function Intel471Section({ d, value, type }: { d: Intel471Context; value: string; type: EnrichableType }) {
  const search = useStore((s) => s.intel471Search);
  const malware = useStore((s) => s.intel471Malware);
  const [gs, setGs] = useState<{ loading: boolean; data?: Intel471Search }>({ loading: false });
  const [mw, setMw] = useState<{ loading: boolean; data?: Intel471Malware } | null>(null);
  const [openCat, setOpenCat] = useState<string | null>(null);

  async function runSearch() {
    setOpenCat(null);
    setGs({ loading: true });
    setGs({ loading: false, data: await search(value, type) });
  }

  async function runMalware() {
    if (!d.malwareFamilyUid) return;
    setMw({ loading: true });
    setMw({ loading: false, data: await malware(d.malwareFamilyUid, d.malwareFamily) });
  }

  const activeRange =
    [d.activeFrom, d.activeTill].filter(Boolean).map((s) => new Date(s!).toLocaleDateString()).join(' – ') || undefined;
  const linked =
    [
      d.reports != null ? `${d.reports} reports` : '',
      d.actors != null ? `${d.actors} actors` : '',
      d.malwareReports ? `${d.malwareReports} malware` : '',
      d.events ? `${d.events} events` : '',
    ]
      .filter(Boolean)
      .join(' · ') || undefined;
  const counts = gs.data && !gs.data.error ? intelCounts(gs.data) : [];

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🦉
        </span>
        Intel 471 · Titan
        {d.found && (d.malwareFamily || d.totalCount != null) && (
          <span className="shodan-when">
            {d.malwareFamily ? 'Malware Intel + IOC' : `${d.totalCount!.toLocaleString()} IOC records`}
          </span>
        )}
      </div>

      {!d.found ? (
        <div className="detail-note">{d.error ?? 'No Intel 471 record for this indicator.'}</div>
      ) : (
        <div className="detail-grid">
          {d.malwareFamily && (
            <div className="field">
              <div className="fk">Malware family</div>
              <div className="fv chips">
                {d.malwareFamilyUid ? (
                  <button
                    className="chip shodan-vuln"
                    onClick={runMalware}
                    title="Fetch Intel 471 malware details (reports · aka · MITRE) + open in Titan"
                  >
                    🔎 {d.malwareFamily}
                  </button>
                ) : (
                  <span className="chip shodan-vuln">{d.malwareFamily}</span>
                )}
                {d.confidence && <span className="chip">confidence {d.confidence}</span>}
              </div>
            </div>
          )}
          <Field k="Threat type" v={d.threatType} />
          <Field k="Context" v={d.context} />
          <Field k="MITRE tactic" v={d.mitreTactics?.replace(/_/g, ' ')} />
          <Field k="Active" v={activeRange} />
          <Field k="Last updated" v={d.lastUpdated ? new Date(d.lastUpdated).toLocaleString() : undefined} />
          <Field k="IOC type" v={d.type} />
          <Field k="ISP" v={[d.isp, d.ispCountryCode].filter(Boolean).join(' · ') || undefined} />
          <Field k="Linked" v={linked} />
          {d.reportTitles && d.reportTitles.length > 0 && (
            <div className="field">
              <div className="fk">Reports</div>
              <div className="fv">
                {d.reportTitles.map((t, i) => (
                  <div key={i}>• {t}</div>
                ))}
              </div>
            </div>
          )}
          <Field k="GIR" v={d.girs && d.girs.length > 0 ? d.girs.join(', ') : undefined} />
        </div>
      )}

      {mw && (
        <div className="cyfirma-actor">
          {mw.loading ? (
            <div className="detail-note">Loading malware profile…</div>
          ) : mw.data?.error ? (
            <div className="detail-note">{mw.data.error}</div>
          ) : mw.data ? (
            <>
              <div className="cyfirma-actor-title">
                Malware · {mw.data.family ?? d.malwareFamily}
                {mw.data.reportCount != null ? ` · ${mw.data.reportCount.toLocaleString()} reports` : ''}
              </div>
              <div className="detail-grid">
                <Field k="aka" v={mw.data.aka && mw.data.aka.length ? mw.data.aka.join(', ') : undefined} />
                <Field k="Summary" v={mw.data.summary} />
                <Field
                  k="MITRE tactics"
                  v={mw.data.mitreTactics?.map((t) => t.replace(/_/g, ' ')).join(', ')}
                />
                <Field k="GIR" v={mw.data.girs && mw.data.girs.length ? mw.data.girs.join(', ') : undefined} />
                <Field
                  k="Active"
                  v={
                    [mw.data.activeFrom, mw.data.activeTill]
                      .filter(Boolean)
                      .map((s) => new Date(s!).toLocaleDateString())
                      .join(' – ') || undefined
                  }
                />
                {mw.data.reports && mw.data.reports.length > 0 && (
                  <div className="field">
                    <div className="fk">Reports</div>
                    <div className="fv">
                      {mw.data.reports.map((t, i) => (
                        <div key={i}>• {t}</div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
              {mw.data.portalUrl && (
                <a className="btn btn-ghost shodan-link" href={mw.data.portalUrl} target="_blank" rel="noreferrer">
                  Open malware profile ↗
                </a>
              )}
            </>
          ) : null}
        </div>
      )}

      <div className="i471-actions">
        {d.portalUrl && (
          <a className="btn btn-ghost shodan-link" href={d.portalUrl} target="_blank" rel="noreferrer">
            Open report ↗
          </a>
        )}
        <button className="btn btn-ghost" onClick={runSearch} disabled={gs.loading}>
          {gs.loading ? 'Searching…' : 'Global Search'}
        </button>
      </div>

      {gs.data &&
        (gs.data.error ? (
          <div className="detail-note">{gs.data.error}</div>
        ) : counts.length ? (
          <div className="i471-search-results">
            <div className="fv chips">
              {counts.map((c) => {
                const hasItems = !!c.items && c.items.length > 0;
                const open = openCat === c.label;
                return (
                  <button
                    key={c.label}
                    className={`chip${hasItems ? ' chip-btn' : ''}${open ? ' chip-open' : ''}`}
                    onClick={() => hasItems && setOpenCat(open ? null : c.label)}
                    disabled={!hasItems}
                    title={hasItems ? `Show top ${c.label}` : `${c.count} ${c.label} — no preview available`}
                  >
                    {c.label} {c.count.toLocaleString()}
                    {hasItems ? (open ? ' ▾' : ' ▸') : ''}
                  </button>
                );
              })}
            </div>
            {(() => {
              const open = counts.find((c) => c.label === openCat);
              if (!open?.items?.length) return null;
              return (
                <div className="i471-search-items">
                  {open.items.map((it, i) =>
                    it.url ? (
                      <a key={i} className="i471-search-item" href={it.url} target="_blank" rel="noreferrer">
                        • {it.title} ↗
                      </a>
                    ) : (
                      <div key={i} className="i471-search-item">
                        • {it.title}
                      </div>
                    ),
                  )}
                </div>
              );
            })()}
          </div>
        ) : (
          <div className="detail-note">No matches across Intel 471 collections.</div>
        ))}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw Intel 471 data</summary>
          <pre>{JSON.stringify(d.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

function trendArrow(t?: string): string {
  const u = (t ?? '').toUpperCase();
  if (u === 'UP' || u === 'INCREASE' || u === 'HIGH') return ' ↑';
  if (u === 'DOWN' || u === 'DECREASE' || u === 'LOW') return ' ↓';
  return '';
}

/** CYFIRMA related-infra buckets that have at least one value, as [label, values] pairs. */
function cyfirmaRelated(rel: CyfirmaRelated): [string, string[]][] {
  const groups: [string, string[] | undefined][] = [
    ['IPs', rel.ips],
    ['domains', rel.domains],
    ['hostnames', rel.hostnames],
    ['URLs', rel.urls],
    ['hashes', rel.hashes],
    ['emails', rel.emails],
    ['CVEs', rel.cves],
    ['exploits', rel.exploits],
  ];
  return groups.filter((g): g is [string, string[]] => Array.isArray(g[1]) && g[1].length > 0);
}

/**
 * CYFIRMA DeCYFIR block — Risk Dossier scores + recommended action + correlated infrastructure
 * (attack-infra side), STIX attribution (actors/campaigns/malware), and an on-demand actor
 * deep-dive (broad search) reachable by clicking a threat-actor chip.
 */
function CyfirmaSection({ d }: { d: CyfirmaContext }) {
  const search = useStore((s) => s.cyfirmaSearch);
  const [actor, setActor] = useState<{ name: string; loading: boolean; data?: CyfirmaSearch } | null>(null);

  async function runActor(name: string) {
    setActor({ name, loading: true });
    setActor({ name, loading: false, data: await search(name) });
  }

  const rel = d.related ? cyfirmaRelated(d.related) : [];
  const scoreLine =
    [
      d.riskScore != null ? `risk ${d.riskScore}/10${trendArrow(d.riskScoreTrend)}` : '',
      d.externalThreatScore != null
        ? `ext threat ${d.externalThreatScore}/10${trendArrow(d.externalThreatScoreTrend)}`
        : '',
    ]
      .filter(Boolean)
      .join('  ·  ') || undefined;

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🛡
        </span>
        CYFIRMA · DeCYFIR
        {d.found && d.indicatorRiskScore != null && (
          <span className="shodan-when">risk {d.indicatorRiskScore}/10</span>
        )}
      </div>

      {!d.found ? (
        <div className="detail-note">{d.error ?? 'No CYFIRMA record for this indicator.'}</div>
      ) : (
        <div className="detail-grid">
          <Field k="Risk scores" v={scoreLine} />
          <Field k="Indicator" v={[d.indicatorType, d.indicatorName].filter(Boolean).join(' · ') || undefined} />
          {d.action && (
            <div className="field">
              <div className="fk">Recommended action</div>
              <div className="fv chips">
                <span className="chip shodan-vuln">{d.action}</span>
              </div>
            </div>
          )}
          <Field k="Story" v={d.story} />
          <Field k="Impact" v={d.impact} />
          <Field k="Description" v={d.description} />
          <Field k="ASN" v={[d.asn ? `AS${d.asn}` : '', d.asnOwner].filter(Boolean).join(' ') || undefined} />
          <Field k="Organization" v={d.organization && d.organization !== d.asnOwner ? d.organization : undefined} />
          <Field k="Country" v={d.country} />

          {d.threatActors && d.threatActors.length > 0 && (
            <div className="field">
              <div className="fk">Threat actors</div>
              <div className="fv chips">
                {d.threatActors.map((a) => (
                  <button
                    key={a}
                    className="chip chip-btn"
                    onClick={() => runActor(a)}
                    title={`CYFIRMA broad search — ${a}: campaigns, malware, targeted CVEs`}
                  >
                    🔎 {a}
                  </button>
                ))}
              </div>
            </div>
          )}
          <Field k="Campaigns" v={d.campaigns && d.campaigns.length ? d.campaigns.join(', ') : undefined} />
          <Field k="Malware" v={d.malware && d.malware.length ? d.malware.join(', ') : undefined} />

          {rel.length > 0 && (
            <div className="field">
              <div className="fk">Related infra{d.relatedCount ? ` · ${d.relatedCount} linked` : ''}</div>
              <div className="fv">
                {rel.map(([label, vals]) => (
                  <div key={label} className="cyfirma-rel-row">
                    <span className="cyfirma-rel-label">{label}</span>
                    <span className="fv chips">
                      {vals.map((v) => (
                        <span key={v} className="chip mono">
                          {v}
                        </span>
                      ))}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {actor && (
        <div className="cyfirma-actor">
          {actor.loading ? (
            <div className="detail-note">Searching {actor.name}…</div>
          ) : actor.data?.error ? (
            <div className="detail-note">{actor.data.error}</div>
          ) : actor.data ? (
            <>
              <div className="cyfirma-actor-title">Actor · {actor.data.actor}</div>
              <div className="detail-grid">
                <Field k="Aliases" v={actor.data.aliases?.join(', ')} />
                <Field k="Motivation" v={actor.data.motivation} />
                <Field k="Description" v={actor.data.description} />
                <Field k="Campaigns" v={actor.data.campaigns?.join(', ')} />
                <Field k="Malware" v={actor.data.malware?.join(', ')} />
                <Field k="Targeted CVEs" v={actor.data.vulnerabilities?.join(', ')} />
                <Field k="Related IOCs" v={actor.data.relatedIocs?.join(', ')} />
              </div>
            </>
          ) : null}
        </div>
      )}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw CYFIRMA data</summary>
          <pre>{JSON.stringify(d.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

/**
 * TeamT5 ThreatVision block — APT-attribution CTI. Risk + adversary groups (clickable → on-demand
 * APT profile with origin/targeting), malware families (samples), attributes (Malware C2 / Hosting),
 * geo/registrar and related-intel counts.
 */
function ThreatVisionSection({ d }: { d: ThreatVisionContext }) {
  const lookup = useStore((s) => s.threatvisionAdversary);
  const [adv, setAdv] = useState<{ name: string; loading: boolean; data?: ThreatVisionAdversary } | null>(null);

  async function runAdv(name: string) {
    setAdv({ name, loading: true });
    setAdv({ name, loading: false, data: await lookup(name) });
  }

  const risk =
    [d.riskLevel, d.riskScore != null ? `score ${d.riskScore}` : ''].filter(Boolean).join(' · ') || undefined;
  const summary =
    [
      d.relatedReports ? `${d.relatedReports} reports` : '',
      d.relatedSamples ? `${d.relatedSamples} samples` : '',
      d.relatedAdversaries ? `${d.relatedAdversaries} adversaries` : '',
      d.dnsRecords ? `${d.dnsRecords} DNS` : '',
      d.osint ? `${d.osint} OSINT` : '',
    ]
      .filter(Boolean)
      .join(' · ') || undefined;

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🔭
        </span>
        ThreatVision · TeamT5
        {d.found && d.riskLevel && <span className="shodan-when">{d.riskLevel} risk</span>}
      </div>

      {!d.found ? (
        <div className="detail-note">{d.error ?? 'No ThreatVision record for this indicator.'}</div>
      ) : (
        <div className="detail-grid">
          <Field k="Risk" v={risk} />
          <Field k="Risk types" v={d.riskTypes && d.riskTypes.length ? d.riskTypes.join(', ') : undefined} />
          {d.adversaries && d.adversaries.length > 0 && (
            <div className="field">
              <div className="fk">Adversaries</div>
              <div className="fv chips">
                {d.adversaries.map((a) => (
                  <button
                    key={a}
                    className="chip chip-btn"
                    onClick={() => runAdv(a)}
                    title={`ThreatVision APT profile — ${a}: aliases, origin, targets`}
                  >
                    🔎 {a}
                  </button>
                ))}
              </div>
            </div>
          )}
          {d.malwareFamilies && d.malwareFamilies.length > 0 && (
            <div className="field">
              <div className="fk">Malware</div>
              <div className="fv chips">
                {d.malwareFamilies.map((m) => (
                  <span key={m} className="chip shodan-vuln">
                    {m}
                  </span>
                ))}
              </div>
            </div>
          )}
          {d.attributes && d.attributes.length > 0 && (
            <div className="field">
              <div className="fk">Attributes</div>
              <div className="fv chips">
                {d.attributes.map((a) => (
                  <span key={a} className="chip">
                    {a}
                  </span>
                ))}
              </div>
            </div>
          )}
          <Field k="Location" v={[d.city, d.region, d.country].filter(Boolean).join(', ') || undefined} />
          <Field k="Registrar" v={d.registrar} />
          <Field k="SHA-256" v={d.sha256} mono />
          <Field k="MD5" v={d.md5} mono />
          <Field k="Size" v={d.size != null ? `${d.size.toLocaleString()} bytes` : undefined} />
          <Field k="First seen" v={d.firstSeen ? new Date(d.firstSeen).toLocaleDateString() : undefined} />
          {d.hasNetworkActivity != null && <Field k="Network activity" v={d.hasNetworkActivity ? 'yes' : 'no'} />}
          <Field k="Related intel" v={summary} />
          <Field k="Updated" v={d.lastUpdate ? new Date(d.lastUpdate).toLocaleDateString() : undefined} />
        </div>
      )}

      {adv && (
        <div className="cyfirma-actor">
          {adv.loading ? (
            <div className="detail-note">Loading {adv.name}…</div>
          ) : adv.data?.error ? (
            <div className="detail-note">{adv.data.error}</div>
          ) : adv.data ? (
            <>
              <div className="cyfirma-actor-title">APT · {adv.data.name}</div>
              <div className="detail-grid">
                <Field k="Aliases" v={adv.data.aliases?.join(', ')} />
                <Field k="Origin" v={adv.data.originCountries?.join(', ')} />
                <Field k="Targets" v={adv.data.targetedCountries?.join(', ')} />
                <Field k="Industries" v={adv.data.targetedIndustries?.join(', ')} />
                <Field k="Overview" v={adv.data.overview} />
              </div>
            </>
          ) : null}
        </div>
      )}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw ThreatVision data</summary>
          <pre>{JSON.stringify(d.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

/** Recorded Future criticality → chip class (Very Malicious/Malicious → red, Suspicious → amber). */
function rfCritClass(c?: number): string {
  if (c != null && c >= 3) return 'chip shodan-vuln';
  return 'chip';
}

/** One Recorded Future detection rule (Sigma / YARA / Snort) with a copyable body. */
function RfRuleCard({ rule }: { rule: RfDetectionRule }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    if (!rule.content) return;
    try {
      await navigator.clipboard.writeText(rule.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked */
    }
  }
  return (
    <div className="rule-card">
      <div className="rule-card-head">
        <span className={`badge type type-${(rule.type ?? 'rule').toLowerCase()}`}>{rule.type ?? 'rule'}</span>
        <span className="rule-name">{rule.title ?? rule.fileName ?? rule.id}</span>
      </div>
      {rule.description && <div className="pv-raw">{rule.description}</div>}
      {rule.entities && rule.entities.length > 0 && (
        <div className="fv chips">
          {rule.entities.map((e) => (
            <span key={e} className="chip">
              {e}
            </span>
          ))}
        </div>
      )}
      {rule.content && (
        <>
          <div className="i471-actions">
            <span className="fk">{rule.fileName ?? `${rule.type ?? 'rule'} body`}</span>
            <button className="btn btn-sm btn-ghost" onClick={copy}>
              {copied ? '✓ Copied' : 'Copy'}
            </button>
          </div>
          <textarea className="siem-output mono" readOnly rows={8} value={rule.content} />
        </>
      )}
    </div>
  );
}

/**
 * Recorded Future block — automatic Connect enrichment (risk score + triggered rules/evidence,
 * activity window, threat lists, related actors/malware, MITRE, AI Insights, Intelligence Card link)
 * plus on-demand pivots: click an actor/malware chip for its RF profile; for hashes fetch a sandbox
 * summary (read-only — nothing is submitted); and search related Sigma/YARA/Snort detection rules.
 */
function RecordedFutureSection({ d, r }: { d: RecordedFutureContext; r: NormalizedResult }) {
  const rfActor = useStore((s) => s.rfActor);
  const rfMalware = useStore((s) => s.rfMalware);
  const rfSandbox = useStore((s) => s.rfSandbox);
  const rfRules = useStore((s) => s.rfRules);
  const [actor, setActor] = useState<{ name: string; loading: boolean; data?: RfActorProfile } | null>(null);
  const [malware, setMalware] = useState<{ name: string; loading: boolean; data?: RfMalwareProfile } | null>(null);
  const [sandbox, setSandbox] = useState<{ loading: boolean; data?: RfSandboxIntel } | null>(null);
  const [rules, setRules] = useState<{ loading: boolean; basis: string; data?: RfRuleSearchResult } | null>(null);

  const isHash = r.type === 'md5' || r.type === 'sha1' || r.type === 'sha256';

  async function runActor(name: string) {
    setActor({ name, loading: true });
    setActor({ name, loading: false, data: await rfActor(name) });
  }
  async function runMalware(m: { id?: string; name: string }) {
    setMalware({ name: m.name, loading: true });
    setMalware({ name: m.name, loading: false, data: await rfMalware({ id: m.id, name: m.name }) });
  }
  async function runSandbox() {
    setSandbox({ loading: true });
    setSandbox({ loading: false, data: await rfSandbox(r.value) });
  }
  async function runRules() {
    // Prefer pivoting on the RF entity ids of related malware/actors; else free-text the top name.
    const ids = [
      ...(d.relatedMalware ?? []),
      ...(d.relatedActors ?? []),
    ]
      .map((e) => e.id)
      .filter((x): x is string => Boolean(x));
    const title = d.relatedMalware?.[0]?.name ?? d.relatedActors?.[0]?.name;
    const basis = ids.length ? (title ?? 'related entities') : (title ?? r.value);
    setRules({ loading: true, basis });
    const params = ids.length ? { entities: ids, limit: 8 } : { title: title ?? r.value, limit: 8 };
    setRules({ loading: false, basis, data: await rfRules(params) });
  }

  const scoreLine =
    [
      d.riskScore != null ? `risk ${d.riskScore}/99` : '',
      d.criticalityLabel ?? '',
      d.riskString ? `(${d.riskString} rules)` : '',
    ]
      .filter(Boolean)
      .join('  ·  ') || undefined;
  const ruleList = rules?.data?.rules ?? [];

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🔮
        </span>
        Recorded Future
        {d.found && d.riskScore != null && (
          <span className="shodan-when">risk {d.riskScore}/99 · {d.criticalityLabel ?? '—'}</span>
        )}
      </div>

      {!d.found ? (
        <div className="detail-note">{d.error ?? 'No Recorded Future record for this indicator.'}</div>
      ) : (
        <div className="detail-grid">
          <Field k="Risk" v={scoreLine} />
          <Field k="Summary" v={d.riskSummary} />
          {d.evidence && d.evidence.length > 0 && (
            <div className="field">
              <div className="fk">Evidence</div>
              <div className="fv">
                {d.evidence.map((e, i) => (
                  <div key={i} className="rf-evidence">
                    <span className={rfCritClass(e.criticality)}>{e.criticalityLabel ?? e.criticality ?? '·'}</span>{' '}
                    <b>{e.rule}</b>
                    {e.mitre && e.mitre.length > 0 ? ` [${e.mitre.join(', ')}]` : ''}
                    {e.evidence ? <div className="pv-raw">{e.evidence}</div> : null}
                  </div>
                ))}
              </div>
            </div>
          )}
          {d.threatLists && d.threatLists.length > 0 && (
            <div className="field">
              <div className="fk">Threat lists</div>
              <Chips items={d.threatLists} />
            </div>
          )}
          {d.relatedActors && d.relatedActors.length > 0 && (
            <div className="field">
              <div className="fk">Threat actors</div>
              <div className="fv chips">
                {d.relatedActors.map((a) => (
                  <button
                    key={a.name}
                    className="chip chip-btn"
                    onClick={() => runActor(a.name)}
                    title={`Recorded Future actor profile — ${a.name}`}
                  >
                    🔎 {a.name}
                    {a.count ? ` (${a.count})` : ''}
                  </button>
                ))}
              </div>
            </div>
          )}
          {d.relatedMalware && d.relatedMalware.length > 0 && (
            <div className="field">
              <div className="fk">Malware</div>
              <div className="fv chips">
                {d.relatedMalware.map((m) => (
                  <button
                    key={m.name}
                    className="chip chip-btn shodan-vuln"
                    onClick={() => runMalware(m)}
                    title={`Recorded Future malware profile — ${m.name}`}
                  >
                    🔎 {m.name}
                    {m.count ? ` (${m.count})` : ''}
                  </button>
                ))}
              </div>
            </div>
          )}
          <Field k="MITRE ATT&CK" v={d.mitre && d.mitre.length ? d.mitre.join(', ') : undefined} />
          <Field k="ASN" v={[d.asn, d.organization].filter(Boolean).join(' · ') || undefined} />
          <Field k="Location" v={[d.city, d.country].filter(Boolean).join(', ') || undefined} />
          <Field k="First seen" v={d.firstSeen ? new Date(d.firstSeen).toLocaleDateString() : undefined} />
          <Field k="Last seen" v={d.lastSeen ? new Date(d.lastSeen).toLocaleDateString() : undefined} />
          {d.aiInsights && (
            <div className="field">
              <div className="fk">AI Insights</div>
              <div className="fv">{d.aiInsights}</div>
            </div>
          )}
        </div>
      )}

      {/* On-demand actor profile */}
      {actor && (
        <div className="cyfirma-actor">
          {actor.loading ? (
            <div className="detail-note">Loading {actor.name}…</div>
          ) : actor.data?.error ? (
            <div className="detail-note">{actor.data.error}</div>
          ) : actor.data ? (
            <>
              <div className="cyfirma-actor-title">Actor · {actor.data.name}</div>
              <div className="detail-grid">
                <Field k="Common names" v={actor.data.commonNames?.join(', ')} />
                <Field k="Aliases" v={actor.data.aliases?.join(', ')} />
                <Field k="Categories" v={actor.data.categories?.join(', ')} />
              </div>
              {actor.data.intelCard && (
                <a className="btn btn-ghost shodan-link" href={actor.data.intelCard} target="_blank" rel="noreferrer">
                  Open actor in Recorded Future ↗
                </a>
              )}
            </>
          ) : null}
        </div>
      )}

      {/* On-demand malware profile */}
      {malware && (
        <div className="cyfirma-actor">
          {malware.loading ? (
            <div className="detail-note">Loading {malware.name}…</div>
          ) : malware.data?.error ? (
            <div className="detail-note">{malware.data.error}</div>
          ) : malware.data ? (
            <>
              <div className="cyfirma-actor-title">Malware · {malware.data.name}</div>
              <div className="detail-grid">
                <Field k="Categories" v={malware.data.categories?.join(', ')} />
                <Field k="Related actors" v={malware.data.relatedActors?.join(', ')} />
                <Field
                  k="Active"
                  v={
                    [malware.data.firstSeen, malware.data.lastSeen]
                      .filter(Boolean)
                      .map((s) => new Date(s!).toLocaleDateString())
                      .join(' – ') || undefined
                  }
                />
              </div>
              {malware.data.intelCard && (
                <a
                  className="btn btn-ghost shodan-link"
                  href={malware.data.intelCard}
                  target="_blank"
                  rel="noreferrer"
                >
                  Open malware in Recorded Future ↗
                </a>
              )}
            </>
          ) : null}
        </div>
      )}

      {/* On-demand sandbox summary (hashes) + detection-rule search */}
      {d.found && (
        <div className="i471-actions">
          {isHash && (
            <button className="btn btn-ghost btn-sm" onClick={runSandbox} disabled={sandbox?.loading}>
              {sandbox?.loading ? 'Loading…' : 'Sandbox intel'}
            </button>
          )}
          <button className="btn btn-ghost btn-sm" onClick={runRules} disabled={rules?.loading}>
            {rules?.loading ? 'Searching…' : 'Detection rules (Sigma/YARA/Snort)'}
          </button>
          {d.intelCard && (
            <a className="btn btn-ghost shodan-link" href={d.intelCard} target="_blank" rel="noreferrer">
              Intelligence Card ↗
            </a>
          )}
        </div>
      )}

      {sandbox?.data &&
        (sandbox.data.error ? (
          <div className="detail-note">{sandbox.data.error}</div>
        ) : (
          <div className="cyfirma-actor">
            <div className="cyfirma-actor-title">Sandbox (Malware Intelligence)</div>
            <div className="detail-grid">
              <Field
                k="Scores"
                v={
                  [
                    sandbox.data.riskScore != null ? `risk ${sandbox.data.riskScore}/99` : '',
                    sandbox.data.sandboxScore != null ? `sandbox ${sandbox.data.sandboxScore}/10` : '',
                  ]
                    .filter(Boolean)
                    .join(' · ') || undefined
                }
              />
              {sandbox.data.tags && sandbox.data.tags.length > 0 && (
                <div className="field">
                  <div className="fk">Tags</div>
                  <Chips items={sandbox.data.tags} />
                </div>
              )}
              <Field k="File types" v={sandbox.data.fileExtensions?.join(', ')} mono />
            </div>
            {sandbox.data.universalReport && (
              <a
                className="btn btn-ghost shodan-link"
                href={sandbox.data.universalReport}
                target="_blank"
                rel="noreferrer"
              >
                Open sandbox report ↗
              </a>
            )}
          </div>
        ))}

      {rules?.data &&
        (rules.data.error ? (
          <div className="detail-note">{rules.data.error}</div>
        ) : ruleList.length === 0 ? (
          <div className="detail-note">No Recorded Future detection rules for “{rules.basis}”.</div>
        ) : (
          <>
            <div className="hint">
              Recorded Future detection rules related to “{rules.basis}” ({rules.data.total ?? ruleList.length}):
            </div>
            <div className="rule-list">
              {ruleList.map((rl, i) => (
                <RfRuleCard key={rl.id ?? i} rule={rl} />
              ))}
            </div>
          </>
        ))}

      {d.raw != null && (
        <details className="raw">
          <summary>Raw Recorded Future data</summary>
          <pre>{JSON.stringify(d.raw, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

/**
 * SOC Prime block — checks the Threat Detection Marketplace for existing/related detections for this
 * indicator. On open it auto-searches by the threat the *other* providers attributed (Intel 471
 * malware family, CYFIRMA/ThreatVision actor/malware); you can also check for rules referencing this
 * exact IOC, or generate a fresh hunting query. The header shows how many rules exist in the Marketplace.
 */
function SocPrimeSection({ r }: { r: NormalizedResult }) {
  const searchRules = useStore((s) => s.socprimeRules);
  const genQuery = useStore((s) => s.socprimeQuery);
  const [siemType, setSiemType] = useState('splunk');
  const [rules, setRules] = useState<{
    loading: boolean;
    mode: 'threat' | 'ioc';
    basis: string;
    data?: SocPrimeRuleSearchResult;
  } | null>(null);
  const [query, setQuery] = useState<{ loading: boolean; data?: SocPrimeQueryResult } | null>(null);
  const [copied, setCopied] = useState(false);

  // Best available threat context from the other providers (malware family, then actor).
  const tool = r.intel471?.malwareFamily ?? r.cyfirma?.malware?.[0] ?? r.threatvision?.malwareFamilies?.[0];
  const actor = r.cyfirma?.threatActors?.[0] ?? r.threatvision?.adversaries?.[0];
  const threat = tool ?? actor ?? r.file?.threatLabel;

  async function searchBy(mode: 'threat' | 'ioc', siem = siemType) {
    const basis = mode === 'ioc' ? r.value : (threat ?? r.value);
    setRules({ loading: true, mode, basis });
    const params =
      mode === 'threat' && (tool || actor)
        ? { siemType: siem, tool, actor, pageSize: 5 }
        : mode === 'ioc'
          ? // Search the rule body specifically — "is this exact IOC already covered by a rule?"
            { siemType: siem, query: `sigma.text: "${r.value}"`, pageSize: 5 }
          : { siemType: siem, query: `"${basis}"`, pageSize: 5 };
    setRules({ loading: false, mode, basis, data: await searchRules(params) });
  }

  // Proactively check the Marketplace when opening a notable indicator.
  useEffect(() => {
    if (r.verdict === 'malicious' || r.verdict === 'suspicious') void searchBy('threat');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [r.value]);

  async function runQuery() {
    setQuery({ loading: true });
    setQuery({ loading: false, data: await genQuery(r.value, { siemType }) });
  }
  const q = query?.data?.queries?.join('\n\n') ?? '';
  async function copyQuery() {
    if (!q) return;
    try {
      await navigator.clipboard.writeText(q);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked */
    }
  }

  const list = rules?.data?.rules ?? [];
  const total = rules?.data && !rules.data.error ? (rules.data.total ?? list.length) : undefined;

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🛡
        </span>
        SOC Prime · TDM
        {rules?.loading ? (
          <span className="shodan-when">checking Marketplace…</span>
        ) : total != null ? (
          <span className="shodan-when">{total.toLocaleString()} in Marketplace</span>
        ) : (
          <span className="shodan-when">detection content</span>
        )}
      </div>

      <div className="soc-controls">
        {/* Group 1 — coverage/match: format-agnostic ("is this IOC / threat already covered?"). */}
        <div className="soc-group">
          <span className="soc-group-label">
            Covered?
            <InfoTip
              ja={
                <>
                  Marketplace に既存の検知ルールがあるか調べます。
                  <br />
                  <b>「Related to …」</b>＝このIOCに他プロバイダ(Intel471/CYFIRMA/ThreatVision)が紐付けた
                  <b>脅威名（マルウェアファミリ／攻撃グループ）</b>で検索。「この“脅威”に対する検知はあるか？」＝<b>広め</b>。
                  <br />
                  <b>「This exact IOC」</b>＝<b>この値そのもの</b>（IP/ドメイン/ハッシュ等）がルール本文に含まれるかを検索。
                  「この“IOC自体”を参照する既存ルールはあるか？」＝<b>厳密</b>。
                </>
              }
              en={
                <>
                  Checks the Marketplace for existing detection rules.
                  <br />
                  <b>“Related to …”</b> searches by the <b>threat</b> other providers attributed to this IOC
                  (malware family / actor) — “is this threat covered?” (broad).
                  <br />
                  <b>“This exact IOC”</b> searches for rules whose body references <b>this exact value</b>
                  (IP/domain/hash) — “is this specific IOC already in a rule?” (narrow).
                </>
              }
            />
          </span>
          <button className="btn btn-ghost btn-sm" onClick={() => searchBy('threat')} disabled={rules?.loading}>
            {threat ? `Related to “${threat}”` : 'Related detections'}
          </button>
          <button className="btn btn-ghost btn-sm" onClick={() => searchBy('ioc')} disabled={rules?.loading}>
            This exact IOC
          </button>
        </div>
        {/* Group 2 — hunting query: the SIEM/EDR is the OUTPUT format for the generated query
            (and for how matched rules above are translated). It's not a filter on matching. */}
        <div className="soc-group">
          <span className="soc-group-label">
            Hunting query
            <InfoTip
              ja={
                <>
                  このIOCから<b>ハンティングクエリを生成</b>します（Uncoder AI）。左の<b>SIEM/EDR</b>は
                  <b>出力フォーマット</b>（Splunk/Sentinel/CrowdStrike等）で、生成クエリと、上の一致ルールの
                  翻訳表示に使われます。<b>IOCが一致するかどうかとは無関係</b>です。
                </>
              }
              en={
                <>
                  <b>Generates a hunting query</b> from this IOC (Uncoder AI). The <b>SIEM/EDR</b> on the left is
                  the <b>output format</b> (Splunk/Sentinel/CrowdStrike/…) for the generated query and for how the
                  matched rules above are translated. It does <b>not</b> affect whether an IOC matches.
                </>
              }
            />
          </span>
          <select
            className="soc-siem"
            value={siemType}
            title="Target SIEM/EDR format for the generated query (and for how matched rules are shown). It does not affect whether an IOC matches."
            onChange={(e) => {
              setSiemType(e.target.value);
              if (rules) void searchBy(rules.mode, e.target.value); // re-translate shown rules to the new format
            }}
          >
            {SIEM_FORMATS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
          <button className="btn btn-ghost btn-sm" onClick={runQuery} disabled={query?.loading}>
            {query?.loading ? 'Generating…' : 'Create'}
          </button>
        </div>
      </div>

      {rules?.data?.error && <div className="detail-note">{rules.data.error}</div>}
      {rules?.data && !rules.data.error && list.length === 0 && (
        <div className="detail-note">
          {rules.mode === 'ioc'
            ? 'No existing Marketplace rule references this exact IOC.'
            : `No related detections in the Marketplace for “${rules.basis}”.`}
        </div>
      )}
      {list.length > 0 && (
        <>
          <div className="hint">
            {rules?.mode === 'ioc'
              ? 'Existing Marketplace rules referencing this IOC:'
              : `Related detections in the SOC Prime Marketplace for “${rules?.basis}”:`}
          </div>
          <div className="rule-list">
            {list.map((rl, i) => (
              <RuleCard key={rl.id ?? i} r={rl} />
            ))}
          </div>
        </>
      )}

      {query?.loading && <div className="detail-note">Generating a {siemType} query…</div>}
      {query?.data?.error && <div className="detail-note">{query.data.error}</div>}
      {q && (
        <>
          <div className="i471-actions">
            <span className="fk">{siemType} query (generated)</span>
            <button className="btn btn-sm btn-ghost" onClick={copyQuery}>
              {copied ? '✓ Copied' : 'Copy'}
            </button>
          </div>
          <textarea className="siem-output mono" readOnly rows={8} value={q} />
        </>
      )}
      {/* Never leave the button looking dead: if SOC Prime answered but we mapped no query
          (and no error), say so and expose the raw response so the shape is visible. */}
      {query?.data && !query.data.error && !q && (
        <details className="raw">
          <summary>SOC Prime returned no query for “{r.value}” — show raw response</summary>
          <pre>{JSON.stringify(query.data.raw ?? query.data, null, 2)}</pre>
        </details>
      )}
    </div>
  );
}

type DetailSize = 'sm' | 'md' | 'lg' | 'xl';
const SIZE_STEPS: { key: DetailSize; title: string }[] = [
  { key: 'sm', title: '現在幅 · default' },
  { key: 'md', title: '中 · medium' },
  { key: 'lg', title: '中大 · large' },
  { key: 'xl', title: '最大 · max (背景は残す)' },
];

/**
 * Reusable urlscan.io capture for ONE target URL (used for URL/domain rows and for the web
 * endpoints of an IP). Submits the target, urlscan renders it in ITS OWN sandbox (our egress never
 * touches the target), then we poll for the screenshot + finally-resolved URL/IP + server ASN +
 * malicious verdict + contacted hosts. Submissions default to `unlisted` (configurable in Settings).
 */
function UrlscanCapture({ target, buttonLabel }: { target: string; buttonLabel?: string }) {
  const submit = useStore((s) => s.urlscanSubmit);
  const poll = useStore((s) => s.urlscanResult);
  const visibility = useStore((s) => s.settings.urlscanVisibility ?? 'unlisted');
  const [state, setState] = useState<{
    phase: 'idle' | 'running' | 'done' | 'error' | 'stalled';
    msg?: string;
    uuid?: string;
    startedAt?: number;
    data?: UrlscanResult;
  }>({ phase: 'idle' });
  const [imgOk, setImgOk] = useState(true);
  // The visibility urlscan actually used — the proxy may clamp `public` → `unlisted` for OPSEC.
  const [effVis, setEffVis] = useState<string | null>(null);
  const aliveRef = useRef(true);
  useEffect(() => () => void (aliveRef.current = false), []);

  // Poll the result until it materializes. urlscan queues scans — a busy/slow site can take well over
  // a minute, and the result URL 404s ("Scan is not finished yet") until it's ready, so we poll
  // patiently and, if it's still not done, park in a `stalled` state with a "Check again" that resumes
  // this SAME scan (never re-submits — that would waste a scan and lose the original).
  async function pollUntilDone(uuid: string, startedAt: number) {
    for (let i = 0; i < 30; i++) {
      await new Promise((res) => setTimeout(res, i === 0 ? 5000 : 4000));
      if (!aliveRef.current) return;
      const elapsed = Math.round((Date.now() - startedAt) / 1000);
      setState({ phase: 'running', uuid, startedAt, msg: `Rendering at urlscan… ${elapsed}s` });
      const result = await poll(uuid);
      if (!aliveRef.current) return;
      if (result.error) {
        setState({ phase: 'error', uuid, msg: result.error, data: result });
        return;
      }
      if (!result.pending) {
        setState({ phase: 'done', uuid, data: result });
        return;
      }
    }
    setState({
      phase: 'stalled',
      uuid,
      startedAt,
      msg: `Still rendering at urlscan after ~${Math.round((Date.now() - startedAt) / 1000)}s — a busy or slow site can take a while. Keep waiting?`,
    });
  }

  async function run() {
    setImgOk(true);
    setEffVis(null);
    setState({ phase: 'running', msg: 'Submitting to urlscan…' });
    const sub = await submit(target, visibility);
    if (!aliveRef.current) return;
    if (sub.error || !sub.uuid) {
      setState({ phase: 'error', msg: sub.error ?? 'urlscan did not return a scan id' });
      return;
    }
    setEffVis(sub.visibility ?? visibility);
    await pollUntilDone(sub.uuid, Date.now());
  }

  async function resume() {
    if (!state.uuid) return;
    await pollUntilDone(state.uuid, state.startedAt ?? Date.now());
  }

  const d = state.data;
  const verdictLine = d
    ? [d.malicious != null ? (d.malicious ? '⚠ malicious' : 'no verdict') : '', d.score != null ? `score ${d.score}` : '']
        .filter(Boolean)
        .join(' · ') || undefined
    : undefined;

  return (
    <div className="urlscan-capture">
      <div className="i471-actions">
        <button className="btn btn-ghost btn-sm" onClick={run} disabled={state.phase === 'running'}>
          {state.phase === 'running'
            ? (state.msg ?? 'Scanning…')
            : d || state.phase === 'stalled'
              ? 'Re-scan'
              : (buttonLabel ?? `Scan now (${visibility})`)}
        </button>
        {state.phase === 'stalled' && (
          <button className="btn btn-ghost btn-sm" onClick={resume}>
            Check again
          </button>
        )}
        {/* Only link out once the result is ready — while pending the result page 404s. */}
        {d?.resultUrl && (
          <a className="btn btn-ghost shodan-link" href={d.resultUrl} target="_blank" rel="noreferrer">
            Open on urlscan ↗
          </a>
        )}
        {effVis && (
          <span className="hint">
            sent as <b>{effVis}</b>
            {effVis === 'unlisted'
              ? ' · not in urlscan public search'
              : effVis === 'public'
                ? ' · ⚠ public feed'
                : ''}
          </span>
        )}
        {state.phase === 'done' && d?.malicious != null && (
          <span className="hint">{d.malicious ? `⚠ malicious · ${d.score ?? '?'}` : 'no verdict'}</span>
        )}
      </div>

      {(state.phase === 'error' || state.phase === 'stalled') && <div className="detail-note">{state.msg}</div>}

      {state.phase === 'done' && d && !d.error && (
        <>
          {d.screenshotUrl && imgOk && (
            <figure className="urlscan-shot" data-noimage="true">
              <a href={d.resultUrl ?? d.screenshotUrl} target="_blank" rel="noreferrer">
                <img
                  src={d.screenshotUrl}
                  alt={`urlscan screenshot of ${d.finalUrl ?? target}`}
                  crossOrigin="anonymous"
                  loading="lazy"
                  onError={() => setImgOk(false)}
                />
              </a>
            </figure>
          )}
          <div className="detail-grid">
            <Field k="Final URL" v={d.finalUrl} mono />
            <Field k="Title" v={d.title} />
            <Field k="Verdict" v={verdictLine} />
            {d.brands && d.brands.length > 0 && <Field k="Impersonates" v={d.brands.join(', ')} />}
            <Field k="Resolved IP" v={d.ip} mono />
            <Field k="Server ASN" v={[d.asn, d.asnName].filter(Boolean).join(' · ') || undefined} />
            <Field k="Country" v={d.country} />
            <Field k="Server" v={d.server} />
            <Field k="HTTP status" v={d.status != null ? String(d.status) : undefined} />
            {d.tags && d.tags.length > 0 && (
              <div className="field">
                <div className="fk">Tags</div>
                <Chips items={d.tags} />
              </div>
            )}
            {d.contactedDomains && d.contactedDomains.length > 0 && (
              <div className="field">
                <div className="fk">Contacted domains</div>
                <Chips items={d.contactedDomains} />
              </div>
            )}
            {d.contactedIps && d.contactedIps.length > 0 && (
              <div className="field">
                <div className="fk">Contacted IPs</div>
                <div className="fv chips">
                  {d.contactedIps.map((ip) => (
                    <span key={ip} className="chip mono">
                      {ip}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

/** urlscan.io "web魚拓" section for a URL / domain row. */
function UrlscanSection({ r }: { r: NormalizedResult }) {
  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          🎣
        </span>
        urlscan.io · 魚拓
        <InfoTip
          ja={
            <>
              対象URL/ドメインを <b>urlscan.io のサンドボックスで実際に開き</b>、今の状態を保全（魚拓）します。
              スクリーンショット・最終URL・解決IP・サーバASN・接触した全ドメイン/IP・悪性判定を取得。
              <br />
              訪問するのは <b>urlscan 側のインフラ</b>なので、<b>こちらの出口IPは相手に晒れません</b>（OPSEC安全）。
              既定は <b>unlisted</b>（公開フィードに出ない）。オンデマンド・完了まで10〜40秒ほど。
            </>
          }
          en={
            <>
              Opens the URL/domain in urlscan.io's own sandbox to capture its current state: screenshot,
              final URL, resolved IP, server ASN, every contacted host, and a malicious verdict. The visit
              comes from urlscan's infrastructure, so your egress IP never touches the target. Unlisted by default.
            </>
          }
        />
      </div>
      <UrlscanCapture target={r.value} />
    </div>
  );
}

/** Ports that are clearly NOT browser-web — never auto-offer a web魚拓 for these. */
const NON_WEB_PORTS = new Set([
  21, 22, 23, 25, 53, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389, 427, 445, 465,
  514, 515, 587, 623, 636, 993, 995, 1080, 1433, 1521, 2049, 3306, 3389, 5060, 5432, 5900, 5985,
  5986, 6379, 9200, 11211, 27017, 27018,
]);

/**
 * Web URLs urlscan should try for an IP. 443 → https, 80 → http; every other plausibly-web port
 * (1443, 8080, 8443, 9000, …) is offered as BOTH https and http (best guess first) since a
 * non-standard port could be either — and urlscan captures even through TLS/cert errors. IPv6 bracketed.
 */
function ipWebEndpoints(ip: string, ports: number[]): string[] {
  const host = ip.includes(':') ? `[${ip}]` : ip;
  const out: string[] = [];
  for (const p of [...new Set(ports)].sort((a, b) => a - b)) {
    if (p < 1 || p > 65535 || NON_WEB_PORTS.has(p)) continue;
    if (p === 443) {
      out.push(`https://${host}`);
      continue;
    }
    if (p === 80) {
      out.push(`http://${host}`);
      continue;
    }
    const s = String(p);
    const httpFirst = s.endsWith('80') || [8000, 8008, 8081, 8888, 8090, 5000, 3000, 7001, 9000, 9080].includes(p);
    out.push(
      ...(httpFirst
        ? [`http://${host}:${p}`, `https://${host}:${p}`]
        : [`https://${host}:${p}`, `http://${host}:${p}`]),
    );
  }
  return [...new Set(out)].slice(0, 14);
}

/** A free-form URL field so an analyst can 魚拓 any scheme://ip:port/path on this host. */
function ManualUrlscan({ ip }: { ip: string }) {
  const host = ip.includes(':') ? `[${ip}]` : ip;
  const [v, setV] = useState(`https://${host}`);
  return (
    <div className="ip-web-ep">
      <input
        className="ip-web-input mono"
        value={v}
        onChange={(e) => setV(e.target.value)}
        spellCheck={false}
        aria-label="Custom URL to capture with urlscan"
        placeholder={`https://${host}:PORT/path`}
      />
      <UrlscanCapture target={v} buttonLabel="🎣 魚拓 (custom)" />
    </div>
  );
}

type ScanPhase = 'idle' | 'submitting' | 'scanning' | 'fetching' | 'done' | 'timeout' | 'error';

/**
 * Live ports / services (IPs). On demand: Shodan InternetDB gives the current *known* open ports/CVEs
 * for free (no key, no active scan). With a Shodan key, "Re-scan" is a self-driving flow — it asks
 * Shodan to re-observe the host, polls the scan status (QUEUE → PROCESSING → DONE) so you can see the
 * progress, then automatically pulls the fresh banners the moment it finishes.
 */
function LivePortsSection({ r }: { r: NormalizedResult }) {
  const shodanOn = useStore((s) => s.mode === 'demo' || Boolean(s.health?.shodan));
  const urlscanOn = useStore((s) => s.mode === 'demo' || Boolean(s.health?.urlscan));
  const idbFn = useStore((s) => s.shodanInternetDb);
  const scanFn = useStore((s) => s.shodanScan);
  const statusFn = useStore((s) => s.shodanScanStatus);
  const hostFn = useStore((s) => s.shodanHost);
  const [idb, setIdb] = useState<{ loading: boolean; data?: ShodanInternetDb } | null>(null);
  const [scan, setScan] = useState<{
    phase: ScanPhase;
    msg?: string;
    id?: string;
    creditsLeft?: number;
    host?: ShodanContext;
  }>({ phase: 'idle' });
  const aliveRef = useRef(true);
  useEffect(() => () => void (aliveRef.current = false), []);

  const scanning = scan.phase === 'submitting' || scan.phase === 'scanning' || scan.phase === 'fetching';

  async function runIdb() {
    setIdb({ loading: true });
    setIdb({ loading: false, data: await idbFn(r.value) });
  }

  async function fetchHost(creditsLeft?: number) {
    setScan({ phase: 'fetching', msg: 'Scan complete — fetching fresh banners…', creditsLeft });
    const host = await hostFn(r.value);
    if (!aliveRef.current) return;
    setScan({ phase: 'done', creditsLeft, host });
  }

  async function runScan() {
    const started = Date.now();
    setScan({ phase: 'submitting', msg: 'Requesting a Shodan re-scan…' });
    const req = await scanFn(r.value);
    if (!aliveRef.current) return;
    if (req.error || !req.id) {
      setScan({ phase: 'error', msg: req.error ?? 'Shodan did not accept the scan (no id returned)' });
      return;
    }
    const id = req.id;
    const credits = req.creditsLeft;
    // Shodan queues scans server-side — poll status until DONE (typically ~10s to a couple of minutes).
    for (let i = 0; i < 24; i++) {
      const elapsed0 = Math.round((Date.now() - started) / 1000);
      setScan({ phase: 'scanning', id, creditsLeft: credits, msg: `Scanning… ${elapsed0}s` });
      await new Promise((res) => setTimeout(res, 5000));
      if (!aliveRef.current) return;
      const st = await statusFn(id);
      if (!aliveRef.current) return;
      if (st.error) {
        setScan({ phase: 'error', id, creditsLeft: credits, msg: st.error });
        return;
      }
      const s = (st.status ?? '').toUpperCase();
      const elapsed = Math.round((Date.now() - started) / 1000);
      setScan({ phase: 'scanning', id, creditsLeft: credits, msg: `Scanning… ${elapsed}s${s ? ` · ${s}` : ''}` });
      if (s === 'DONE') {
        await fetchHost(credits);
        return;
      }
    }
    setScan({
      phase: 'timeout',
      id,
      creditsLeft: credits,
      msg: 'Still queued at Shodan after ~2 min — it finishes server-side. Fetch the banners in a moment.',
    });
  }

  const host = scan.host;

  // Combine Shodan + urlscan: for a web-facing IP, capture a "魚拓" of the site it serves. Web
  // endpoints are derived from whatever ports we know (batch Shodan, InternetDB, or a fresh re-scan);
  // until any ports are known we offer the two common candidates (https/http) so it works immediately.
  const knownPorts = [
    ...new Set([...(r.shodan?.ports ?? []), ...(idb?.data?.ports ?? []), ...(host?.ports ?? [])]),
  ];
  const hasPortData = Boolean(r.shodan?.found || idb?.data?.found || host?.found);
  const webBase = r.value.includes(':') ? `[${r.value}]` : r.value;
  const webEndpoints = hasPortData
    ? ipWebEndpoints(r.value, knownPorts)
    : [`https://${webBase}`, `http://${webBase}`];
  // The IP's hostnames (from Shodan/InternetDB) are the CLEANEST 魚拓 targets: scanning
  // https://<hostname> sends the right SNI/Host so the correct vhost + a valid cert are used —
  // a bare-IP HTTPS scan fights the cert/vhost mismatch and often stalls at urlscan.
  const hostnames = [
    ...new Set([...(r.shodan?.hostnames ?? []), ...(idb?.data?.hostnames ?? []), ...(host?.hostnames ?? [])]),
  ].filter((h) => /^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i.test(h));
  const hostnameEndpoints = hostnames.slice(0, 6).map((h) => `https://${h}`);

  return (
    <div className="shodan-block">
      <div className="shodan-head">
        <span className="shodan-logo" aria-hidden>
          📡
        </span>
        Live ports / services
        <InfoTip
          ja={
            <>
              このIPの <b>今のポート/サービス</b>を確認します。
              <br />
              <b>Current ports (InternetDB)</b>＝無料・鍵不要・<b>再スキャンなし</b>で Shodan の最新既知ポート/CVEを即取得。
              <br />
              <b>Re-scan with Shodan</b>＝Shodan に <b>今すぐ再観測</b>を依頼（スキャンクレジット消費）。再スキャンは
              <b>非同期</b>なので、状態(QUEUE→PROCESSING→DONE)と経過秒を表示し、<b>DONE になったら自動で最新バナーを取得</b>します。
              いずれも <b>Shodan 側から</b>観測するのでこちらの出口IPは晒れません。
              <br />
              Web系ポート(80/443等)があれば、下の <b>「🎣 Web 魚拓」</b>で <b>そのIPが配信しているサイトを urlscan で保全</b>できます
              （IPでも魚拓）。
            </>
          }
          en={
            <>
              Shows this IP's current ports/services. “Current ports (InternetDB)” is free and needs no key
              (Shodan's latest known state, no active scan). “Re-scan with Shodan” asks Shodan to observe the
              host again (uses credits); since that's asynchronous, it shows the status (QUEUE → PROCESSING →
              DONE) with elapsed time and auto-loads the fresh banners the moment it's DONE. If the host has web
              ports, use “🎣 Web 魚拓” below to capture the site it serves via urlscan — a 魚拓 even for a bare IP.
            </>
          }
        />
      </div>

      <div className="i471-actions">
        <button className="btn btn-ghost btn-sm" onClick={runIdb} disabled={idb?.loading}>
          {idb?.loading ? 'Checking…' : 'Current ports (InternetDB)'}
        </button>
        {shodanOn && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={runScan}
            disabled={scanning}
            title="Ask Shodan to re-scan this host now (consumes scan credits). Progress + fresh banners appear automatically."
          >
            {scanning ? (scan.msg ?? 'Scanning…') : 'Re-scan with Shodan'}
          </button>
        )}
        {scan.phase === 'timeout' && (
          <button className="btn btn-ghost btn-sm" onClick={() => fetchHost(scan.creditsLeft)}>
            Fetch banners now
          </button>
        )}
      </div>

      {idb?.data &&
        (idb.data.error ? (
          <div className="detail-note">{idb.data.error}</div>
        ) : !idb.data.found ? (
          <div className="detail-note">Not in Shodan InternetDB.</div>
        ) : (
          <div className="detail-grid">
            {idb.data.ports && idb.data.ports.length > 0 && (
              <Field k="Open ports (now)" v={idb.data.ports.join(', ')} mono />
            )}
            {idb.data.vulns && idb.data.vulns.length > 0 && (
              <div className="field">
                <div className="fk">CVEs</div>
                <div className="fv chips">
                  {idb.data.vulns.map((cve) => (
                    <a
                      key={cve}
                      className="chip shodan-vuln mono"
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      {cve}
                    </a>
                  ))}
                </div>
              </div>
            )}
            {idb.data.hostnames && idb.data.hostnames.length > 0 && (
              <Field k="Hostnames" v={idb.data.hostnames.join(', ')} mono />
            )}
            {idb.data.cpes && idb.data.cpes.length > 0 && <Field k="CPEs" v={idb.data.cpes.join(', ')} mono />}
            {idb.data.tags && idb.data.tags.length > 0 && (
              <div className="field">
                <div className="fk">Tags</div>
                <Chips items={idb.data.tags} />
              </div>
            )}
          </div>
        ))}

      {/* Re-scan progress — live status line so you can see it running and when it finishes. */}
      {scanning && (
        <div className="detail-note live-scan">
          <span className="live-dot" aria-hidden />
          {scan.msg}
          {scan.creditsLeft != null ? ` · ${scan.creditsLeft} credits left` : ''}
        </div>
      )}
      {scan.phase === 'timeout' && <div className="detail-note">{scan.msg}</div>}
      {scan.phase === 'error' && <div className="detail-note">{scan.msg}</div>}

      {scan.phase === 'done' &&
        host &&
        (host.error ? (
          <div className="detail-note">{host.error}</div>
        ) : !host.found ? (
          <div className="detail-note">
            Re-scan finished, but Shodan has no fresh host record yet — try “Current ports (InternetDB)”.
          </div>
        ) : (
          <>
            <div className="detail-note live-done">
              ✓ Re-scan complete{scan.creditsLeft != null ? ` · ${scan.creditsLeft} credits left` : ''}
            </div>
            <div className="detail-grid">
              {host.ports && host.ports.length > 0 && <Field k="Open ports (fresh)" v={host.ports.join(', ')} mono />}
              {host.services && host.services.length > 0 && (
                <div className="field">
                  <div className="fk">Services</div>
                  <div className="fv chips">
                    {host.services.map((svc, i) => (
                      <span key={`${svc.port}-${i}`} className="chip shodan mono">
                        {serviceLabel(svc)}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {host.vulns && host.vulns.length > 0 && (
                <div className="field">
                  <div className="fk">CVEs</div>
                  <div className="fv chips">
                    {host.vulns.map((cve) => (
                      <a
                        key={cve}
                        className="chip shodan-vuln mono"
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noreferrer"
                      >
                        {cve}
                      </a>
                    ))}
                  </div>
                </div>
              )}
              {host.lastUpdate && <Field k="Shodan last saw" v={new Date(host.lastUpdate).toLocaleString()} />}
            </div>
          </>
        ))}

      {/* Combined Shodan × urlscan: capture a "魚拓" of the web service(s) this IP is serving. */}
      {urlscanOn && (
        <div className="ip-web-capture">
          <div className="fk ip-web-title">🎣 Web 魚拓 (urlscan) — capture the site served on this IP</div>
          <span className="hint">
            urlscan visits from its own sandbox and captures <b>even if the TLS certificate is invalid /
            self-signed</b> (the warning is ignored). Non-standard ports (1443, 8080, …) are offered as both
            https and http.
            {!hasPortData && ' Run “Current ports (InternetDB)” to list every web port; common ones shown for now.'}
            {hasPortData && webEndpoints.length === 0 && ' No standard web ports detected — use the custom field below.'}
          </span>
          {hostnameEndpoints.length > 0 && (
            <>
              <div className="hint ip-web-group">
                ✅ Recommended — capture via the host's own name (correct vhost + valid cert; a bare-IP HTTPS
                scan often stalls on the cert/SNI mismatch):
              </div>
              {hostnameEndpoints.map((ep) => (
                <div key={ep} className="ip-web-ep">
                  <span className="mono ip-web-url">{ep}</span>
                  <UrlscanCapture target={ep} buttonLabel="🎣 魚拓" />
                </div>
              ))}
              <div className="hint ip-web-group">Or capture the bare IP directly:</div>
            </>
          )}
          {webEndpoints.map((ep) => (
            <div key={ep} className="ip-web-ep">
              <span className="mono ip-web-url">{ep}</span>
              <UrlscanCapture target={ep} buttonLabel="🎣 魚拓" />
            </div>
          ))}
          <ManualUrlscan ip={r.value} />
        </div>
      )}
    </div>
  );
}

export function DetailPanel() {
  const selected = useStore((s) => s.selected);
  const results = useStore((s) => s.results);
  const select = useStore((s) => s.select);
  const socprimeOn = useStore((s) => s.mode === 'demo' || Boolean(s.health?.socprime));
  const urlscanOn = useStore((s) => s.mode === 'demo' || Boolean(s.health?.urlscan));
  // InternetDB needs no key — live ports are available whenever the proxy is reachable (or in demo).
  const liveScanOn = useStore((s) => s.mode === 'demo' || Boolean(s.health?.ok));
  const tlp = useStore((s) => s.settings.tlp);
  const panelRef = useRef<HTMLElement>(null);
  const [copied, setCopied] = useState<'text' | 'image' | 'pdf' | 'err' | null>(null);
  const [busy, setBusy] = useState(false);
  const [size, setSize] = useState<DetailSize>(() => {
    const s = localStorage.getItem('vteeee.detailSize');
    return s === 'md' || s === 'lg' || s === 'xl' ? s : 'sm';
  });
  function changeSize(s: DetailSize): void {
    setSize(s);
    try {
      localStorage.setItem('vteeee.detailSize', s);
    } catch {
      /* ignore */
    }
  }
  const r = selected ? results[selected] : null;

  function flash(kind: 'text' | 'image' | 'pdf' | 'err'): void {
    setCopied(kind);
    setTimeout(() => setCopied((c) => (c === kind ? null : c)), 1600);
  }

  async function copyText(): Promise<void> {
    if (!r) return;
    try {
      await navigator.clipboard.writeText(resultToText(r));
      flash('text');
    } catch {
      flash('err');
    }
  }

  /** pixelRatio used for both copy-image and PDF export. */
  const CAPTURE_SCALE = 2;

  /**
   * Rasterize the whole panel to a PNG blob at its current (possibly widened) size, including the
   * MaxMind map. OSM tiles are CORS-enabled so they rasterize; if a tile ever taints the canvas the
   * capture is retried once with the map dropped. Shared by copy-image and export-PDF.
   */
  async function renderPanelBlob(): Promise<Blob | null> {
    const node = panelRef.current;
    if (!node) return null;
    const { toBlob } = await import('html-to-image');
    const bg = getComputedStyle(node).backgroundColor || '#2b3f37';
    const capture = (excludeMap: boolean): Promise<Blob | null> =>
      toBlob(node, {
        backgroundColor: bg,
        pixelRatio: CAPTURE_SCALE,
        width: node.offsetWidth,
        height: node.scrollHeight,
        style: { maxHeight: 'none', overflow: 'visible' },
        filter: (el) => {
          if (el instanceof HTMLElement) {
            if (el.dataset.noimage === 'true') return false; // action buttons etc.
            if (excludeMap && el.classList.contains('maxmind-map')) return false;
          }
          return true;
        },
      });
    try {
      return await capture(false);
    } catch {
      return await capture(true);
    }
  }

  async function copyImage(): Promise<void> {
    if (!panelRef.current || busy) return;
    setBusy(true);
    try {
      const blob = await renderPanelBlob();
      if (!blob) throw new Error('no blob');
      await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
      flash('image');
    } catch {
      flash('err');
    } finally {
      setBusy(false);
    }
  }

  async function exportPdf(): Promise<void> {
    if (!panelRef.current || busy || !r) return;
    setBusy(true);
    try {
      // Real-text document (not a screenshot). Capture ONLY the MaxMind map (if shown) as an
      // image and embed it next to the selectable text.
      let map: PdfMapImage | undefined;
      const mapEl = panelRef.current.querySelector('.maxmind-map');
      if (mapEl instanceof HTMLElement && mapEl.offsetWidth > 0) {
        try {
          const { toPng } = await import('html-to-image');
          const dataUrl = await toPng(mapEl, { pixelRatio: 2, cacheBust: true });
          map = { dataUrl, w: mapEl.offsetWidth, h: mapEl.offsetHeight };
        } catch {
          /* a cross-origin tile tainted the canvas → export the report without the map image */
        }
      }
      await exportResultPdf(r, { map, tlp });
      flash('pdf');
    } catch {
      flash('err');
    } finally {
      setBusy(false);
    }
  }

  if (!r) return null;

  return (
    <div className="detail-overlay" onClick={() => select(null)}>
      <aside className="detail-panel" data-size={size} ref={panelRef} onClick={(e) => e.stopPropagation()}>
        <div className="detail-head">
          <div>
            <div className="detail-title mono">{r.value}</div>
            <div className="detail-sub">
              <span className={`badge type type-${r.type}`}>{r.type}</span>{' '}
              <VerdictBadge verdict={r.verdict} status={r.status} /> <GtiBadge r={r} />
            </div>
          </div>
          <div className="detail-actions" data-noimage="true">
            <div className="detail-resize" role="group" aria-label="Panel width">
              {SIZE_STEPS.map((s, i) => (
                <button
                  key={s.key}
                  className={`resize-btn${size === s.key ? ' active' : ''}`}
                  onClick={() => changeSize(s.key)}
                  title={`Panel width — ${s.title}`}
                  aria-label={`width ${s.key}`}
                  aria-pressed={size === s.key}
                >
                  <span className="resize-bar" style={{ width: `${5 + i * 4}px` }} />
                </button>
              ))}
            </div>
            <button
              className="btn btn-sm btn-ghost"
              onClick={copyText}
              title="Copy the whole detail as text"
            >
              {copied === 'text' ? '✓ Copied' : copied === 'err' ? '⚠ Failed' : 'Copy text'}
            </button>
            <button
              className="btn btn-sm btn-ghost"
              onClick={copyImage}
              disabled={busy}
              title="Copy the whole detail as an image"
            >
              {busy ? '…' : copied === 'image' ? '✓ Copied' : 'Copy image'}
            </button>
            <button
              className="btn btn-sm btn-ghost"
              onClick={exportPdf}
              disabled={busy}
              title="Export the whole detail (incl. the map) as a PDF"
            >
              {busy ? '…' : copied === 'pdf' ? '✓ Saved' : 'Export PDF'}
            </button>
            <button className="btn btn-ghost" onClick={() => select(null)} title="Close">
              ✕
            </button>
          </div>
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
          {r.firstSeen && <Field k="First seen" v={new Date(r.firstSeen).toLocaleString()} />}
          {r.lastSeen && <Field k="Last seen" v={new Date(r.lastSeen).toLocaleString()} />}
          {r.lastModified && <Field k="Last modified (VT)" v={new Date(r.lastModified).toLocaleString()} />}
          {r.timesSubmitted != null && <Field k="Times submitted" v={r.timesSubmitted.toLocaleString()} />}
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
              <Field
                k="WHOIS date"
                v={r.ip.whoisDate ? new Date(r.ip.whoisDate).toLocaleDateString() : undefined}
              />
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
                k="Expires"
                v={r.domain.expiration ? new Date(r.domain.expiration).toLocaleDateString() : undefined}
              />
              <Field
                k="Last DNS records"
                v={
                  r.domain.lastDnsRecordsDate
                    ? new Date(r.domain.lastDnsRecordsDate).toLocaleDateString()
                    : undefined
                }
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

        {/* Raw VT payload sits with the VirusTotal data (collapsed), just above the VT link —
            not at the very bottom under every enrichment section. */}
        {r.raw != null && (
          <details className="raw">
            <summary>Raw VT attributes</summary>
            <pre>{JSON.stringify(r.raw, null, 2)}</pre>
          </details>
        )}

        {/* VT call-to-action stays with the VirusTotal data at the top — the enrichment
            sections below can grow long, so the button must not sink to the bottom. */}
        <a className="btn btn-primary detail-vt" href={r.links.gui} target="_blank" rel="noreferrer">
          Open in VirusTotal ↗
        </a>

        {urlscanOn && (r.type === 'url' || r.type === 'domain') && <UrlscanSection key={`us-${r.value}`} r={r} />}
        {r.shodan && <ShodanSection s={r.shodan} ip={r.value} />}
        {liveScanOn && (r.type === 'ipv4' || r.type === 'ipv6') && <LivePortsSection key={`lp-${r.value}`} r={r} />}
        {r.maxmind && <MaxmindSection m={r.maxmind} />}
        {r.domaintools && <DomainToolsSection d={r.domaintools} />}
        {r.dnslytics && <DnslyticsSection d={r.dnslytics} />}
        {r.intel471 && r.type !== 'unknown' && (
          <Intel471Section d={r.intel471} value={r.value} type={r.type as EnrichableType} />
        )}
        {r.cyfirma && <CyfirmaSection d={r.cyfirma} />}
        {r.threatvision && <ThreatVisionSection d={r.threatvision} />}
        {r.recordedfuture && <RecordedFutureSection d={r.recordedfuture} r={r} />}
        {socprimeOn && r.type !== 'unknown' && <SocPrimeSection key={r.value} r={r} />}
      </aside>
    </div>
  );
}
