import { useEffect, useRef } from 'react';

// Minimal Leaflet surface (dynamic import keeps it lazy) — a world map with one marker per monitored IP
// that has coordinates (from MaxMind), coloured by verdict. Shared by the IP-Mon dashboard and the
// IP-Mon assessment report. Uses OpenStreetMap tiles (online); the self-contained CountryChoropleth is
// the print-clean statistical companion.
interface LMap {
  setView(c: [number, number], z: number): LMap;
  fitBounds(b: [number, number][], o?: Record<string, unknown>): void;
  invalidateSize(): void;
  remove(): void;
}
interface LLayer {
  addTo(m: LMap): LLayer;
  bindPopup(html: string): LLayer;
}
interface LApi {
  map(el: HTMLElement, o?: Record<string, unknown>): LMap;
  tileLayer(url: string, o?: Record<string, unknown>): LLayer;
  circleMarker(c: [number, number], o?: Record<string, unknown>): LLayer;
}

export const verdictColor = (v?: string): string =>
  v === 'malicious' ? '#dc2626' : v === 'suspicious' ? '#f59e0b' : v === 'harmless' ? '#3aa981' : '#8b5cf6';

export interface MapPoint {
  lat: number;
  lon: number;
  ip: string;
  verdict?: string;
}

/** World map with a marker per monitored IP that has coordinates (from MaxMind), coloured by verdict. */
export function MonitorMap({ points, className = 'monitor-map' }: { points: MapPoint[]; className?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
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
        map = L.map(el, { scrollWheelZoom: false, worldCopyJump: true, attributionControl: true }).setView([25, 5], 1);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          maxZoom: 19,
          attribution: '© OpenStreetMap contributors',
        }).addTo(map);
        const bounds: [number, number][] = [];
        for (const p of points) {
          L.circleMarker([p.lat, p.lon], {
            radius: 6,
            color: '#ffffff',
            weight: 1.5,
            fillColor: verdictColor(p.verdict),
            fillOpacity: 0.9,
          })
            .addTo(map)
            .bindPopup(`${p.ip}${p.verdict ? ` · ${p.verdict}` : ''}`);
          bounds.push([p.lat, p.lon]);
        }
        if (bounds.length >= 2) {
          try {
            map.fitBounds(bounds, { padding: [30, 30], maxZoom: 6 });
          } catch {
            /* ignore */
          }
        } else if (bounds.length === 1) {
          map.setView(bounds[0], 4);
        }
        const settle = () => map && !cancelled && map.invalidateSize();
        setTimeout(settle, 100);
        setTimeout(settle, 400);
      } catch {
        /* offline / Leaflet failed — the country stats still convey the spread */
      }
    })();
    return () => {
      cancelled = true;
      map?.remove();
    };
  }, [points]);
  return <div className={className} ref={ref} />;
}
