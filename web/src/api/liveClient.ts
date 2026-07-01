import type {
  AppSettings,
  CyfirmaSearch,
  EnrichableType,
  EnrichEvent,
  EnrichRequest,
  Intel471Malware,
  Intel471Search,
  ParsedIndicator,
  ParseResponse,
} from '@vteeee/shared';
import type { EnrichClient, EnrichHandlers } from './client';

/** Calls the server-side proxy (which holds the VT key). Streams NDJSON results. */
export class LiveClient implements EnrichClient {
  readonly mode = 'live' as const;
  private base: string;
  private accessToken?: string | null;
  /** Indicators per /api/enrich call — keeps each Worker invocation under Cloudflare's cap. */
  private chunk: number;

  constructor(settings: AppSettings) {
    this.base = settings.proxyBaseUrl!.replace(/\/$/, '');
    this.accessToken = settings.accessToken;
    // Each indicator issues ~1 subrequest per active provider (VT + Shodan + DomainTools +
    // DNSLytics + Intel 471 + CYFIRMA). Cloudflare's free plan allows only 50 subrequests per
    // Worker invocation, so we split the batch into chunks — each POST is a fresh invocation with
    // its own budget. Target ≤ ~40/invocation to leave headroom for VT 429 retries.
    const providers =
      1 + // VirusTotal
      (settings.shodan !== false ? 1 : 0) +
      (settings.domaintools !== false ? 1 : 0) +
      (settings.dnslytics !== false ? 1 : 0) +
      (settings.intel471 !== false ? 2 : 0) + // Intel 471 = /indicators + /iocs (+on-demand /search)
      (settings.cyfirma !== false ? 2 : 0); // CYFIRMA = /riskdossier + /threatioc search (+on-demand actor)
    this.chunk = Math.max(3, Math.floor(40 / (providers + 1)));
  }

  private headers(json = true): HeadersInit {
    const h: Record<string, string> = {};
    if (json) h['Content-Type'] = 'application/json';
    if (this.accessToken) h['Authorization'] = `Bearer ${this.accessToken}`;
    return h;
  }

  async enrich(req: EnrichRequest, handlers: EnrichHandlers): Promise<void> {
    const all = req.indicators;
    if (all.length <= this.chunk) {
      await this.streamOnce(req, handlers);
      return;
    }
    // Split into sub-batches so a single Worker invocation never exceeds the subrequest cap.
    const total = all.length;
    const started = Date.now();
    let base = 0;
    let stopped = false;
    for (let i = 0; i < all.length && !stopped; i += this.chunk) {
      if (handlers.signal?.aborted) break;
      const chunk = all.slice(i, i + this.chunk);
      const done0 = base;
      await this.streamOnce(
        { indicators: chunk, options: req.options },
        {
          signal: handlers.signal,
          onResult: handlers.onResult,
          // Re-base per-chunk progress onto the whole batch; emit a single 'done' at the end.
          onProgress: (p) =>
            handlers.onProgress({
              done: done0 + p.done,
              total,
              inflight: p.inflight,
              rateLimitedUntil: p.rateLimitedUntil,
            }),
          onDone: () => {},
          onError: (m) => {
            stopped = true;
            handlers.onError(m);
          },
        },
      );
      base += chunk.length;
    }
    if (!stopped && !handlers.signal?.aborted) {
      handlers.onDone({ done: base, total, elapsedMs: Date.now() - started });
    }
  }

  /** One /api/enrich POST + NDJSON stream (a single Worker invocation). */
  private async streamOnce(req: EnrichRequest, handlers: EnrichHandlers): Promise<void> {
    let res: Response;
    try {
      res = await fetch(`${this.base}/api/enrich`, {
        method: 'POST',
        headers: { ...this.headers(), Accept: 'application/x-ndjson' },
        body: JSON.stringify(req),
        signal: handlers.signal,
      });
    } catch (e) {
      handlers.onError(`Could not reach proxy: ${(e as Error).message}`);
      return;
    }
    if (!res.ok || !res.body) {
      handlers.onError(`Proxy error ${res.status} ${res.statusText}`);
      return;
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx: number;
        while ((idx = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, idx).trim();
          buf = buf.slice(idx + 1);
          if (line) this.dispatch(JSON.parse(line) as EnrichEvent, handlers);
        }
      }
      const last = buf.trim();
      if (last) this.dispatch(JSON.parse(last) as EnrichEvent, handlers);
    } catch (e) {
      if ((e as Error).name !== 'AbortError') handlers.onError((e as Error).message);
    }
  }

  private dispatch(ev: EnrichEvent, h: EnrichHandlers): void {
    switch (ev.event) {
      case 'progress':
        h.onProgress(ev);
        break;
      case 'result':
        h.onResult(ev.result);
        break;
      case 'done':
        h.onDone(ev);
        break;
      case 'error':
        h.onError(ev.message);
        break;
    }
  }

  async intel471Search(ioc: string, type: EnrichableType): Promise<Intel471Search> {
    const res = await fetch(
      `${this.base}/api/intel471/search?ioc=${encodeURIComponent(ioc)}&type=${encodeURIComponent(type)}`,
      { headers: this.headers(false) },
    );
    if (!res.ok) return { error: `Intel 471 search failed: ${res.status}` };
    return (await res.json()) as Intel471Search;
  }

  async intel471Malware(uid: string, family?: string): Promise<Intel471Malware> {
    const q = `uid=${encodeURIComponent(uid)}${family ? `&family=${encodeURIComponent(family)}` : ''}`;
    const res = await fetch(`${this.base}/api/intel471/malware?${q}`, { headers: this.headers(false) });
    if (!res.ok) return { error: `Intel 471 malware lookup failed: ${res.status}` };
    return (await res.json()) as Intel471Malware;
  }

  async cyfirmaSearch(name: string): Promise<CyfirmaSearch> {
    const res = await fetch(`${this.base}/api/cyfirma/search?name=${encodeURIComponent(name)}`, {
      headers: this.headers(false),
    });
    if (!res.ok) return { error: `CYFIRMA search failed: ${res.status}` };
    return (await res.json()) as CyfirmaSearch;
  }

  async smartParse(text: string): Promise<ParsedIndicator[]> {
    const res = await fetch(`${this.base}/api/parse`, {
      method: 'POST',
      headers: this.headers(),
      body: JSON.stringify({ text }),
      signal: undefined,
    });
    if (!res.ok) throw new Error(`Parse failed: ${res.status}`);
    const data = (await res.json()) as ParseResponse;
    return data.indicators;
  }
}
