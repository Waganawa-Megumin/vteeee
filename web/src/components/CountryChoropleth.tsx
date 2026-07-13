import { useEffect, useMemo, useRef, useState } from 'react';

// Minimal Leaflet surface for a GeoJSON choropleth (no tile layer — the country polygons ARE the map,
// so it stays fully self-contained: no external tiles, works offline, prints clean).
interface LBounds {
  isValid(): boolean;
}
interface LMap {
  fitBounds(b: LBounds, o?: Record<string, unknown>): void;
  setView(c: [number, number], z: number): LMap;
  invalidateSize(): void;
  remove(): void;
}
interface LFeature {
  properties: { iso2?: string; name?: string };
}
interface LGeoLayer {
  bindTooltip(html: string, o?: Record<string, unknown>): LGeoLayer;
  on(type: string, handler: () => void): LGeoLayer;
}
interface LLayerG {
  addTo(m: LMap): LLayerG;
  getBounds(): LBounds;
}
interface LApi {
  map(el: HTMLElement, o?: Record<string, unknown>): LMap;
  geoJSON(
    data: unknown,
    o?: {
      style?: (f: LFeature) => Record<string, unknown>;
      onEachFeature?: (f: LFeature, layer: LGeoLayer) => void;
    },
  ): LLayerG;
}

// Full-name variants (mostly Shodan's country_name / RF location) that differ from the Natural Earth NAME,
// so a name-based count still lands on the right polygon. ISO-code sources (MaxMind/AbuseIPDB/VT) skip this.
const NAME_ALIASES: Record<string, string> = {
  'UNITED STATES': 'US',
  'UNITED STATES OF AMERICA': 'US',
  USA: 'US',
  'RUSSIAN FEDERATION': 'RU',
  'REPUBLIC OF KOREA': 'KR',
  'KOREA, REPUBLIC OF': 'KR',
  'KOREA REPUBLIC OF': 'KR',
  'SOUTH KOREA': 'KR',
  "KOREA, DEMOCRATIC PEOPLE'S REPUBLIC OF": 'KP',
  'NORTH KOREA': 'KP',
  'IRAN, ISLAMIC REPUBLIC OF': 'IR',
  IRAN: 'IR',
  'VIET NAM': 'VN',
  VIETNAM: 'VN',
  'SYRIAN ARAB REPUBLIC': 'SY',
  SYRIA: 'SY',
  'TAIWAN, PROVINCE OF CHINA': 'TW',
  TAIWAN: 'TW',
  'CZECH REPUBLIC': 'CZ',
  CZECHIA: 'CZ',
  'REPUBLIC OF MOLDOVA': 'MD',
  'MOLDOVA, REPUBLIC OF': 'MD',
  MOLDOVA: 'MD',
  'BOLIVIA, PLURINATIONAL STATE OF': 'BO',
  BOLIVIA: 'BO',
  'VENEZUELA, BOLIVARIAN REPUBLIC OF': 'VE',
  VENEZUELA: 'VE',
  'TANZANIA, UNITED REPUBLIC OF': 'TZ',
  TANZANIA: 'TZ',
  'UNITED REPUBLIC OF TANZANIA': 'TZ',
  'LAO PEOPLE’S DEMOCRATIC REPUBLIC': 'LA',
  "LAO PEOPLE'S DEMOCRATIC REPUBLIC": 'LA',
  LAOS: 'LA',
  'BRUNEI DARUSSALAM': 'BN',
  BRUNEI: 'BN',
  'NORTH MACEDONIA': 'MK',
  MACEDONIA: 'MK',
  "COTE D'IVOIRE": 'CI',
  "CÔTE D'IVOIRE": 'CI',
  'IVORY COAST': 'CI',
  'CONGO, THE DEMOCRATIC REPUBLIC OF THE': 'CD',
  'DEMOCRATIC REPUBLIC OF THE CONGO': 'CD',
  'DR CONGO': 'CD',
  'REPUBLIC OF THE CONGO': 'CG',
  'UNITED KINGDOM': 'GB',
  'UNITED KINGDOM OF GREAT BRITAIN AND NORTHERN IRELAND': 'GB',
  'PALESTINE, STATE OF': 'PS',
  PALESTINE: 'PS',
  'STATE OF PALESTINE': 'PS',
  SWAZILAND: 'SZ',
  ESWATINI: 'SZ',
  'MYANMAR (BURMA)': 'MM',
  BURMA: 'MM',
  'MACAO': 'MO',
  'HONG KONG': 'HK',
};

interface GeoData {
  features: { properties: { iso2?: string; name?: string } }[];
}

/**
 * Resolve a raw country identifier (an ISO-2 code from MaxMind/AbuseIPDB/VT, or a full country name
 * from Shodan/RF) to an ISO-2 code, using the polygon set's own names + a small alias table.
 */
function toIso2(raw: string, nameIndex: Record<string, string>): string | undefined {
  const k = raw.trim();
  if (!k) return undefined;
  if (/^[A-Za-z]{2}$/.test(k)) return k.toUpperCase();
  const up = k.toUpperCase();
  return nameIndex[up] ?? NAME_ALIASES[up];
}

/** Pale-amber → deep-red ramp: more IOCs ⇒ deeper colour. Log-scaled so a couple of hotspots don't wash out the rest. */
function shade(n: number, max: number): string {
  if (n <= 0) return 'transparent';
  const t = max <= 1 ? 0.6 : Math.min(1, Math.log(n + 1) / Math.log(max + 1));
  const a = [253, 230, 190]; // pale amber
  const b = [124, 22, 22]; // deep red
  const c = a.map((av, i) => Math.round(av + (b[i] - av) * t));
  return `rgb(${c[0]},${c[1]},${c[2]})`;
}

/**
 * A country choropleth: `counts` maps a raw country id (ISO-2 or full name) → a number; countries are
 * shaded from pale to deep red by that number ("多いほど濃い"). Self-contained (bundled polygons, no tiles).
 */
export function CountryChoropleth({
  counts,
  height = 300,
  onPick,
}: {
  counts: Record<string, number>;
  height?: number;
  /** Click a shaded country → (iso2, name); the parent lists the matching IOCs. */
  onPick?: (iso2: string, name: string) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const onPickRef = useRef(onPick);
  onPickRef.current = onPick;
  const [geo, setGeo] = useState<GeoData | null>(null);

  // Lazy-load the polygon set once from /public (fetched only when a map renders — kept out of the JS
  // bundle and off tsc's type inference; cached by the browser thereafter).
  useEffect(() => {
    let live = true;
    void fetch(`${import.meta.env.BASE_URL}world-countries.geo.json`)
      .then((r) => (r.ok ? (r.json() as Promise<GeoData>) : null))
      .then((d) => {
        if (live && d) setGeo(d);
      })
      .catch(() => {
        /* offline — the by-country bars still convey the spread */
      });
    return () => {
      live = false;
    };
  }, []);

  // Fold the raw counts into ISO-2 buckets using the polygon names as the name→code index.
  const { resolved, max, matched } = useMemo(() => {
    const nameIndex: Record<string, string> = {};
    if (geo) for (const f of geo.features) {
      const { iso2, name } = f.properties;
      if (iso2 && name) nameIndex[name.toUpperCase()] = iso2;
    }
    const res: Record<string, number> = {};
    for (const [raw, n] of Object.entries(counts)) {
      const iso = toIso2(raw, nameIndex);
      if (!iso) continue;
      res[iso] = (res[iso] ?? 0) + n;
    }
    const mx = Object.values(res).reduce((a, b) => Math.max(a, b), 0);
    return { resolved: res, max: mx, matched: Object.keys(res).length };
  }, [counts, geo]);

  useEffect(() => {
    if (!geo) return;
    let map: LMap | null = null;
    let cancelled = false;
    void (async () => {
      const el = ref.current;
      if (!el) return;
      try {
        await import('leaflet/dist/leaflet.css');
        const mod = await import('leaflet');
        const L = ((mod as { default?: unknown }).default ?? mod) as unknown as LApi;
        if (cancelled || !ref.current) return;
        map = L.map(el, {
          scrollWheelZoom: false,
          attributionControl: false,
          worldCopyJump: false,
          minZoom: 1,
          maxZoom: 6,
        }).setView([25, 0], 1);
        const layer = L.geoJSON(geo, {
          style: (f) => {
            const n = f.properties.iso2 ? resolved[f.properties.iso2] ?? 0 : 0;
            return {
              fillColor: shade(n, max),
              fillOpacity: n > 0 ? 0.88 : 0.12,
              color: '#7c8794',
              weight: 0.5,
              className: n > 0 ? 'choro-clickable' : '',
            };
          },
          onEachFeature: (f, lyr) => {
            const iso = f.properties.iso2;
            const n = iso ? resolved[iso] ?? 0 : 0;
            lyr.bindTooltip(
              `${f.properties.name ?? iso ?? '—'}${iso ? ` (${iso})` : ''}: ${n}${n > 0 ? ' · クリックで対象IoC' : ''}`,
              { sticky: true, direction: 'top' },
            );
            if (n > 0 && iso) lyr.on('click', () => onPickRef.current?.(iso, f.properties.name ?? iso));
          },
        }).addTo(map);
        try {
          const b = layer.getBounds();
          if (b.isValid()) map.fitBounds(b, { padding: [4, 4] });
        } catch {
          /* keep the default world view */
        }
        const settle = () => map && !cancelled && map.invalidateSize();
        setTimeout(settle, 100);
        setTimeout(settle, 400);
      } catch {
        /* Leaflet failed to load — the by-country bars still convey the spread. */
      }
    })();
    return () => {
      cancelled = true;
      map?.remove();
    };
  }, [geo, resolved, max]);

  if (!Object.keys(counts).length) {
    return <div className="hint choro-empty">国データがありません（各IOCを Re-enrich すると国が付与されます）。</div>;
  }

  return (
    <div className="choro">
      <div className="choro-map" ref={ref} style={{ height }} />
      <div className="choro-legend" aria-hidden>
        <span className="choro-legend-label">少</span>
        <span className="choro-legend-bar" />
        <span className="choro-legend-label">多{max ? ` (max ${max})` : ''}</span>
        {matched === 0 && <span className="choro-legend-note">— 国コード未解決</span>}
      </div>
    </div>
  );
}
