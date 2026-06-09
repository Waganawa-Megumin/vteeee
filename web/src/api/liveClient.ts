import type {
  AppSettings,
  EnrichEvent,
  EnrichRequest,
  ParsedIndicator,
  ParseResponse,
} from '@vteeee/shared';
import type { EnrichClient, EnrichHandlers } from './client';

/** Calls the server-side proxy (which holds the VT key). Streams NDJSON results. */
export class LiveClient implements EnrichClient {
  readonly mode = 'live' as const;
  private base: string;
  private accessToken?: string | null;

  constructor(settings: AppSettings) {
    this.base = settings.proxyBaseUrl!.replace(/\/$/, '');
    this.accessToken = settings.accessToken;
  }

  private headers(json = true): HeadersInit {
    const h: Record<string, string> = {};
    if (json) h['Content-Type'] = 'application/json';
    if (this.accessToken) h['Authorization'] = `Bearer ${this.accessToken}`;
    return h;
  }

  async enrich(req: EnrichRequest, handlers: EnrichHandlers): Promise<void> {
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
