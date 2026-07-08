import type {
  AppSettings,
  CyfirmaSearch,
  EnrichableType,
  EnrichRequest,
  Intel471Malware,
  Intel471Search,
  NormalizedResult,
  ParsedIndicator,
  RfActorProfile,
  RfMalwareProfile,
  RfRuleSearchParams,
  RfRuleSearchResult,
  RfSandboxIntel,
  ShodanContext,
  ShodanInternetDb,
  ShodanScanRequest,
  ShodanScanStatus,
  SocPrimeQueryOptions,
  SocPrimeQueryResult,
  SocPrimeRuleSearchParams,
  SocPrimeRuleSearchResult,
  ThreatVisionAdversary,
  UrlscanResult,
  UrlscanSubmission,
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
  /** On-demand Intel 471 malware family details (reports + profile) by family profile UID. */
  intel471Malware(uid: string, family?: string): Promise<Intel471Malware>;
  /** On-demand CYFIRMA Threat-Actor deep-dive (broad search) by actor name. */
  cyfirmaSearch(name: string): Promise<CyfirmaSearch>;
  /** On-demand TeamT5 ThreatVision adversary (APT group) profile by name. */
  threatvisionAdversary(name: string): Promise<ThreatVisionAdversary>;
  /** On-demand SOC Prime Uncoder AI — generate a SIEM hunting query from a block of IOCs. */
  socprimeQuery(text: string, opts: SocPrimeQueryOptions): Promise<SocPrimeQueryResult>;
  /** On-demand SOC Prime detection-rule search (Sigma rules → chosen SIEM format). */
  socprimeRules(params: SocPrimeRuleSearchParams): Promise<SocPrimeRuleSearchResult>;
  /** On-demand Recorded Future threat-actor profile (Threat API) by name. */
  rfActor(name: string): Promise<RfActorProfile>;
  /** On-demand Recorded Future malware profile (Connect API) by RF entity id or name. */
  rfMalware(ref: { id?: string; name?: string }): Promise<RfMalwareProfile>;
  /** On-demand Recorded Future sandbox summary (Malware Intelligence, read-only) for a hash. */
  rfSandbox(hash: string): Promise<RfSandboxIntel>;
  /** On-demand Recorded Future detection-rule search (Sigma / YARA / Snort). */
  rfRules(params: RfRuleSearchParams): Promise<RfRuleSearchResult>;
  /** On-demand urlscan.io scan submission ("魚拓") for a URL/domain. Returns the scan ids to poll. */
  urlscanSubmit(url: string, visibility?: string): Promise<UrlscanSubmission>;
  /** Poll a urlscan.io result by uuid (pending:true while still rendering). */
  urlscanResult(uuid: string): Promise<UrlscanResult>;
  /** Shodan InternetDB — current known ports/CVEs for an IP (free, no active scan). */
  shodanInternetDb(ip: string): Promise<ShodanInternetDb>;
  /** Request an on-demand Shodan re-scan of an IP (consumes scan credits). */
  shodanScan(ip: string): Promise<ShodanScanRequest>;
  /** Poll the status of a submitted Shodan scan (SUBMITTING → QUEUE → PROCESSING → DONE). */
  shodanScanStatus(id: string): Promise<ShodanScanStatus>;
  /** Re-fetch Shodan host banners on demand (e.g. after a re-scan). */
  shodanHost(ip: string): Promise<ShodanContext>;
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
