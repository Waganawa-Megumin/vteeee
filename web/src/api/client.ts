import type {
  AppSettings,
  CyfirmaSearch,
  EnrichableType,
  EnrichRequest,
  Intel471Search,
  NormalizedResult,
  ParsedIndicator,
} from '@vteeee/shared';

export interface EnrichHandlers {
  onProgress: (p: { done: number; total: number; inflight: number; rateLimitedUntil: number | null }) => void;
  onResult: (r: NormalizedResult) => void;
  onDone: (d: { done: number; total: number; elapsedMs: number }) => void;
  onError: (message: string) => void;
  signal?: AbortSignal;
}

/** A hard boundary: DemoClient reads bundled fixtures, LiveClient calls the proxy. */
export interface EnrichClient {
  readonly mode: 'demo' | 'live';
  enrich(req: EnrichRequest, handlers: EnrichHandlers): Promise<void>;
  /** Smart-parse messy text into candidate indicators. */
  smartParse(text: string): Promise<ParsedIndicator[]>;
  /** On-demand Intel 471 Global Search — cross-entity counts for one IOC. */
  intel471Search(ioc: string, type: EnrichableType): Promise<Intel471Search>;
  /** On-demand CYFIRMA Threat-Actor deep-dive (broad search) by actor name. */
  cyfirmaSearch(name: string): Promise<CyfirmaSearch>;
}

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(t);
      resolve();
    });
  });
}

export async function makeClient(settings: AppSettings): Promise<EnrichClient> {
  if (settings.proxyBaseUrl) {
    const { LiveClient } = await import('./liveClient');
    return new LiveClient(settings);
  }
  const { DemoClient } = await import('./demoClient');
  return new DemoClient();
}
