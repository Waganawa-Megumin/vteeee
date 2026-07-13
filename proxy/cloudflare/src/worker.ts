import {
  runEnrich,
  ndjson,
  smartParse,
  intel471GlobalSearch,
  intel471MalwareProfile,
  cyfirmaActorSearch,
  threatvisionAdversary,
  socprimeGenerateQuery,
  socprimeSearchRules,
  rfActorSearch,
  rfMalwareLookup,
  rfSandboxIntel,
  rfDetectionRules,
  urlscanSubmit,
  urlscanResult,
  shodanInternetDb,
  shodanScanRequest,
  shodanScanStatus,
  shodanHostLookup,
  shodanMonitorList,
  shodanMonitorAdd,
  shodanMonitorRemove,
  getSharedMonitors,
  putSharedMonitors,
  getSharedCampaigns,
  putSharedCampaigns,
  summarizeCampaign,
  assessCampaign,
  runAllScheduledEnrich,
  getUsers,
  putUsers,
  getSettings,
  putSettings,
  corsHeaders,
  originAllowed,
  checkAccess,
  checkAdmin,
  checkAdminToken,
  consumeDailyQuota,
  kvHistoryBackend,
  historyRoute,
  type KVLike,
  type ProxyEnv,
  type Storage,
} from '@vteeee/proxy-core';
import type { AppSettings, CampaignDigest, EnrichableType, EnrichRequest, UserRecord } from '@vteeee/shared';

interface Env {
  VT_API_KEY: string;
  ANTHROPIC_API_KEY?: string;
  SHODAN_API_KEY?: string;
  MAXMIND_ACCOUNT_ID?: string;
  MAXMIND_LICENSE_KEY?: string;
  MAXMIND_BASE_URL?: string;
  MAXMIND_EDITION?: string;
  MAXMIND_RPM?: string;
  DOMAINTOOLS_API_USERNAME?: string;
  DOMAINTOOLS_API_KEY?: string;
  DNSLYTICS_API_KEY?: string;
  DNSLYTICS_BASE_URL?: string;
  INTEL471_API_USER?: string;
  INTEL471_API_KEY?: string;
  INTEL471_BASE_URL?: string;
  INTEL471_RPM?: string;
  CYFIRMA_API_KEY?: string;
  CYFIRMA_BASE_URL?: string;
  CYFIRMA_RPM?: string;
  THREATVISION_CLIENT_ID?: string;
  THREATVISION_CLIENT_SECRET?: string;
  THREATVISION_ACCESS_TOKEN?: string;
  THREATVISION_BASE_URL?: string;
  THREATVISION_RPM?: string;
  RECORDEDFUTURE_API_KEY?: string;
  RECORDEDFUTURE_BASE_URL?: string;
  RECORDEDFUTURE_RPM?: string;
  SOCPRIME_API_KEY?: string;
  SOCPRIME_BASE_URL?: string;
  URLSCAN_API_KEY?: string;
  URLSCAN_BASE_URL?: string;
  URLSCAN_VISIBILITY?: string;
  URLSCAN_ALLOW_PUBLIC?: string;
  URLSCAN_TAGS?: string;
  ABUSEIPDB_API_KEY?: string;
  ABUSEIPDB_BASE_URL?: string;
  ABUSEIPDB_MAX_AGE_DAYS?: string;
  ABUSEIPDB_RPM?: string;
  ACCESS_TOKEN?: string;
  ADMIN_TOKEN?: string;
  ALLOWED_ORIGINS?: string;
  VT_RPM?: string;
  VT_MAX_RPM?: string;
  SHODAN_RPM?: string;
  DOMAINTOOLS_RPM?: string;
  DNSLYTICS_RPM?: string;
  CLAUDE_MODEL?: string;
  MAX_BATCH?: string;
  VT_DAILY?: string;
  PARSE_DAILY?: string;
  HISTORY_DAYS?: string;
  VTEEEE_KV: KVNamespace;
}

function build(env: Env): { proxy: ProxyEnv; allowed: string[]; store: Storage } {
  const allowed = (env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const store: Storage = {
    get: (k) => env.VTEEEE_KV.get(k),
    put: (k, v) => env.VTEEEE_KV.put(k, v),
  };
  const proxy: ProxyEnv = {
    vtApiKey: env.VT_API_KEY,
    anthropicApiKey: env.ANTHROPIC_API_KEY,
    shodanApiKey: env.SHODAN_API_KEY,
    maxmindAccountId: env.MAXMIND_ACCOUNT_ID,
    maxmindLicenseKey: env.MAXMIND_LICENSE_KEY,
    maxmindBaseUrl: env.MAXMIND_BASE_URL,
    maxmindEdition: env.MAXMIND_EDITION,
    maxmindRpm: env.MAXMIND_RPM ? Number(env.MAXMIND_RPM) : undefined,
    domaintoolsApiUsername: env.DOMAINTOOLS_API_USERNAME,
    domaintoolsApiKey: env.DOMAINTOOLS_API_KEY,
    dnslyticsApiKey: env.DNSLYTICS_API_KEY,
    dnslyticsBaseUrl: env.DNSLYTICS_BASE_URL,
    intel471ApiUser: env.INTEL471_API_USER,
    intel471ApiKey: env.INTEL471_API_KEY,
    intel471BaseUrl: env.INTEL471_BASE_URL,
    intel471Rpm: env.INTEL471_RPM ? Number(env.INTEL471_RPM) : undefined,
    cyfirmaApiKey: env.CYFIRMA_API_KEY,
    cyfirmaBaseUrl: env.CYFIRMA_BASE_URL,
    cyfirmaRpm: env.CYFIRMA_RPM ? Number(env.CYFIRMA_RPM) : undefined,
    threatvisionClientId: env.THREATVISION_CLIENT_ID,
    threatvisionClientSecret: env.THREATVISION_CLIENT_SECRET,
    threatvisionAccessToken: env.THREATVISION_ACCESS_TOKEN,
    threatvisionBaseUrl: env.THREATVISION_BASE_URL,
    threatvisionRpm: env.THREATVISION_RPM ? Number(env.THREATVISION_RPM) : undefined,
    recordedfutureApiKey: env.RECORDEDFUTURE_API_KEY,
    recordedfutureBaseUrl: env.RECORDEDFUTURE_BASE_URL,
    recordedfutureRpm: env.RECORDEDFUTURE_RPM ? Number(env.RECORDEDFUTURE_RPM) : undefined,
    socprimeApiKey: env.SOCPRIME_API_KEY,
    socprimeBaseUrl: env.SOCPRIME_BASE_URL,
    urlscanApiKey: env.URLSCAN_API_KEY,
    urlscanBaseUrl: env.URLSCAN_BASE_URL,
    urlscanVisibility: env.URLSCAN_VISIBILITY,
    urlscanAllowPublic: env.URLSCAN_ALLOW_PUBLIC === 'true',
    urlscanTags: env.URLSCAN_TAGS,
    abuseipdbApiKey: env.ABUSEIPDB_API_KEY,
    abuseipdbBaseUrl: env.ABUSEIPDB_BASE_URL,
    abuseipdbMaxAgeDays: env.ABUSEIPDB_MAX_AGE_DAYS ? Number(env.ABUSEIPDB_MAX_AGE_DAYS) : undefined,
    abuseipdbRpm: env.ABUSEIPDB_RPM ? Number(env.ABUSEIPDB_RPM) : undefined,
    accessToken: env.ACCESS_TOKEN,
    adminToken: env.ADMIN_TOKEN,
    allowedOrigins: allowed,
    defaultRpm: Number(env.VT_RPM ?? 4),
    maxRpm: Number(env.VT_MAX_RPM ?? 1000),
    shodanRpm: env.SHODAN_RPM ? Number(env.SHODAN_RPM) : undefined,
    domaintoolsRpm: env.DOMAINTOOLS_RPM ? Number(env.DOMAINTOOLS_RPM) : undefined,
    dnslyticsRpm: env.DNSLYTICS_RPM ? Number(env.DNSLYTICS_RPM) : undefined,
    claudeModel: env.CLAUDE_MODEL,
    xTool: 'vteeee',
    maxBatch: Number(env.MAX_BATCH ?? 1000),
    dailyCap: Number(env.VT_DAILY ?? 500),
    parseDailyCap: Number(env.PARSE_DAILY ?? 200),
  };
  return { proxy, allowed, store };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { proxy, allowed, store } = build(env);
    const origin = request.headers.get('origin');
    const cors = corsHeaders(origin, allowed);
    const auth = request.headers.get('authorization');
    const url = new URL(request.url);
    const json = (body: unknown, status = 200): Response =>
      new Response(JSON.stringify(body), {
        status,
        headers: { ...cors, 'content-type': 'application/json' },
      });

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

    try {
      if (url.pathname === '/health')
        return json({
          ok: true,
          vtKey: Boolean(proxy.vtApiKey),
          claude: Boolean(proxy.anthropicApiKey),
          shodan: Boolean(proxy.shodanApiKey),
          maxmind: Boolean(proxy.maxmindAccountId && proxy.maxmindLicenseKey),
          domaintools: Boolean(proxy.domaintoolsApiUsername && proxy.domaintoolsApiKey),
          dnslytics: Boolean(proxy.dnslyticsApiKey),
          intel471: Boolean(proxy.intel471ApiUser && proxy.intel471ApiKey),
          cyfirma: Boolean(proxy.cyfirmaApiKey),
          threatvision: Boolean(
            proxy.threatvisionAccessToken || (proxy.threatvisionClientId && proxy.threatvisionClientSecret),
          ),
          socprime: Boolean(proxy.socprimeApiKey),
          recordedfuture: Boolean(proxy.recordedfutureApiKey),
          urlscan: Boolean(proxy.urlscanApiKey),
          abuseipdb: Boolean(proxy.abuseipdbApiKey),
        });

      if (url.pathname === '/api/enrich' && request.method === 'POST') {
        if (origin && !originAllowed(origin, allowed)) return json({ error: 'origin not allowed' }, 403);
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.vtApiKey) return json({ error: 'VT_API_KEY not configured' }, 500);
        const body = (await request.json()) as EnrichRequest;
        const inds = body.indicators;
        if (!Array.isArray(inds) || inds.length === 0) return json({ error: 'no indicators provided' }, 400);
        if (inds.length > proxy.maxBatch)
          return json({ error: `too many indicators in one request (max ${proxy.maxBatch})` }, 400);
        if (!(await consumeDailyQuota(store, 'vt', proxy.dailyCap, inds.length)))
          return json({ error: `daily lookup quota (${proxy.dailyCap}) would be exceeded` }, 429);
        const enc = new TextEncoder();
        const stream = new ReadableStream<Uint8Array>({
          async start(controller) {
            try {
              for await (const ev of runEnrich(body, proxy, request.signal)) {
                controller.enqueue(enc.encode(ndjson(ev)));
              }
            } catch (e) {
              controller.enqueue(enc.encode(ndjson({ event: 'error', message: (e as Error).message })));
            }
            controller.close();
          },
        });
        return new Response(stream, {
          headers: { ...cors, 'content-type': 'application/x-ndjson', 'cache-control': 'no-store' },
        });
      }

      if (url.pathname === '/api/parse' && request.method === 'POST') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!(await consumeDailyQuota(store, 'parse', proxy.parseDailyCap, 1)))
          return json({ error: 'daily smart-parse quota reached' }, 429);
        const body = (await request.json()) as { text?: string; maxIndicators?: number };
        return json(await smartParse(body.text ?? '', proxy, body.maxIndicators));
      }

      // On-demand Intel 471 Global Search (cross-entity counts) for one IOC.
      if (url.pathname === '/api/intel471/search' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.intel471ApiUser || !proxy.intel471ApiKey) return json({ error: 'Intel 471 not configured' }, 400);
        const ioc = url.searchParams.get('ioc') ?? '';
        const iocType = (url.searchParams.get('type') ?? 'unknown') as EnrichableType;
        if (!ioc) return json({ error: 'ioc required' }, 400);
        return json((await intel471GlobalSearch(ioc, iocType, proxy, request.signal)) ?? { error: 'unavailable' });
      }

      // On-demand Intel 471 malware family details (reports + profile) by malware family profile UID.
      if (url.pathname === '/api/intel471/malware' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.intel471ApiUser || !proxy.intel471ApiKey) return json({ error: 'Intel 471 not configured' }, 400);
        const uid = url.searchParams.get('uid') ?? '';
        const family = url.searchParams.get('family') ?? undefined;
        if (!uid) return json({ error: 'uid required' }, 400);
        return json((await intel471MalwareProfile(uid, proxy, request.signal, family)) ?? { error: 'unavailable' });
      }

      // On-demand CYFIRMA Threat-Actor deep-dive (broad search) by actor name.
      if (url.pathname === '/api/cyfirma/search' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.cyfirmaApiKey) return json({ error: 'CYFIRMA not configured' }, 400);
        const name = url.searchParams.get('name') ?? '';
        if (!name) return json({ error: 'name required' }, 400);
        return json((await cyfirmaActorSearch(name, proxy, request.signal)) ?? { error: 'unavailable' });
      }

      // On-demand ThreatVision adversary (APT group) profile by name.
      if (url.pathname === '/api/threatvision/adversary' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!(proxy.threatvisionAccessToken || (proxy.threatvisionClientId && proxy.threatvisionClientSecret)))
          return json({ error: 'ThreatVision not configured' }, 400);
        const name = url.searchParams.get('name') ?? '';
        if (!name) return json({ error: 'name required' }, 400);
        return json((await threatvisionAdversary(name, proxy, request.signal)) ?? { error: 'unavailable' });
      }

      // On-demand Recorded Future threat-actor profile (Threat API) by actor name.
      if (url.pathname === '/api/rf/actor' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.recordedfutureApiKey) return json({ error: 'Recorded Future not configured' }, 400);
        const name = url.searchParams.get('name') ?? '';
        if (!name) return json({ error: 'name required' }, 400);
        return json((await rfActorSearch(name, proxy, request.signal)) ?? { error: 'unavailable' });
      }

      // On-demand Recorded Future malware profile (Connect API) by RF entity id or name.
      if (url.pathname === '/api/rf/malware' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.recordedfutureApiKey) return json({ error: 'Recorded Future not configured' }, 400);
        const id = url.searchParams.get('id') ?? undefined;
        const name = url.searchParams.get('name') ?? undefined;
        if (!id && !name) return json({ error: 'id or name required' }, 400);
        return json((await rfMalwareLookup({ id, name }, proxy, request.signal)) ?? { error: 'unavailable' });
      }

      // On-demand Recorded Future sandbox summary (Malware Intelligence, read-only query) for a hash.
      if (url.pathname === '/api/rf/sandbox' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.recordedfutureApiKey) return json({ error: 'Recorded Future not configured' }, 400);
        const hash = url.searchParams.get('hash') ?? '';
        if (!hash) return json({ error: 'hash required' }, 400);
        return json((await rfSandboxIntel(hash, proxy, request.signal)) ?? { error: 'unavailable' });
      }

      // On-demand Recorded Future detection-rule search (Sigma / YARA / Snort).
      if (url.pathname === '/api/rf/rules' && request.method === 'POST') {
        if (origin && !originAllowed(origin, allowed)) return json({ error: 'origin not allowed' }, 403);
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.recordedfutureApiKey) return json({ error: 'Recorded Future not configured' }, 400);
        const p = (await request.json()) as {
          types?: string[];
          title?: string;
          entities?: string[];
          limit?: number;
        };
        return json(
          (await rfDetectionRules(
            { types: p.types, title: p.title, entities: p.entities, limit: p.limit },
            proxy,
            request.signal,
          )) ?? { error: 'unavailable' },
        );
      }

      // On-demand urlscan.io submission — "web魚拓" for a URL/domain (sandboxed, unlisted).
      if (url.pathname === '/api/urlscan' && request.method === 'POST') {
        if (origin && !originAllowed(origin, allowed)) return json({ error: 'origin not allowed' }, 403);
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.urlscanApiKey) return json({ error: 'urlscan not configured' }, 400);
        const b = (await request.json()) as { url?: string; visibility?: string };
        if (!b.url) return json({ error: 'url required' }, 400);
        return json((await urlscanSubmit(b.url, proxy, b.visibility, request.signal)) ?? { error: 'unavailable' });
      }

      // Poll a urlscan result by uuid (404 while rendering → { pending: true }).
      if (url.pathname === '/api/urlscan/result' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.urlscanApiKey) return json({ error: 'urlscan not configured' }, 400);
        const uuid = url.searchParams.get('uuid') ?? '';
        if (!uuid) return json({ error: 'uuid required' }, 400);
        return json((await urlscanResult(uuid, proxy, request.signal)) ?? { error: 'unavailable' });
      }

      // Shodan InternetDB — current known ports/CVEs for an IP (free, no key, no active scan).
      if (url.pathname === '/api/shodan/internetdb' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        const ip = url.searchParams.get('ip') ?? '';
        if (!ip) return json({ error: 'ip required' }, 400);
        return json((await shodanInternetDb(ip, request.signal)) ?? { found: false, error: 'unavailable' });
      }

      // Request an on-demand Shodan re-scan of an IP (consumes scan credits).
      if (url.pathname === '/api/shodan/scan' && request.method === 'POST') {
        if (origin && !originAllowed(origin, allowed)) return json({ error: 'origin not allowed' }, 403);
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.shodanApiKey) return json({ error: 'Shodan not configured' }, 400);
        const b = (await request.json()) as { ip?: string };
        if (!b.ip) return json({ error: 'ip required' }, 400);
        return json((await shodanScanRequest(b.ip, proxy, request.signal)) ?? { error: 'unavailable' });
      }

      // Poll the status of a submitted Shodan scan (SUBMITTING → QUEUE → PROCESSING → DONE).
      if (url.pathname === '/api/shodan/scan-status' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.shodanApiKey) return json({ error: 'Shodan not configured' }, 400);
        const id = url.searchParams.get('id') ?? '';
        if (!id) return json({ error: 'id required' }, 400);
        return json((await shodanScanStatus(id, proxy, request.signal)) ?? { error: 'unavailable' });
      }

      // Shared IP-Mon watchlist (IPs + vteeee enrichment snapshots) in KV — team-shared.
      if (url.pathname === '/api/monitor' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        return json(await getSharedMonitors(store));
      }
      if (url.pathname === '/api/monitor' && request.method === 'PUT') {
        if (origin && !originAllowed(origin, allowed)) return json({ error: 'origin not allowed' }, 403);
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        await putSharedMonitors(store, await request.json());
        return json({ ok: true });
      }
      // CP-Mon shared campaigns (attack-campaign IOC watchlists + enrichment timelines).
      if (url.pathname === '/api/campaigns' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        return json(await getSharedCampaigns(store));
      }
      if (url.pathname === '/api/campaigns' && request.method === 'PUT') {
        if (origin && !originAllowed(origin, allowed)) return json({ error: 'origin not allowed' }, 403);
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        await putSharedCampaigns(store, await request.json());
        return json({ ok: true });
      }
      // CP-Mon 電光掲示板: Claude-written one-line key message from a compact campaign digest.
      if (url.pathname === '/api/campaign-summary' && request.method === 'POST') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!(await consumeDailyQuota(store, 'parse', proxy.parseDailyCap, 1)))
          return json({ error: 'daily smart-parse quota reached' }, 429);
        const digest = (await request.json()) as CampaignDigest;
        return json(await summarizeCampaign(digest, proxy));
      }
      // CP-Mon CTI assessment report (Claude analytical report from a rich campaign digest).
      if (url.pathname === '/api/campaign-assessment' && request.method === 'POST') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!(await consumeDailyQuota(store, 'parse', proxy.parseDailyCap, 1)))
          return json({ error: 'daily smart-parse quota reached' }, 429);
        return json(await assessCampaign(await request.json(), proxy));
      }
      // Manual trigger for the server-side auto re-enrich (also runs on the Cloudflare cron below).
      // Admin-token gated. Node deployments point an external daily cron at this endpoint.
      if (url.pathname === '/api/cron/auto-enrich' && request.method === 'POST') {
        if (!checkAdmin(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        return json(await runAllScheduledEnrich(store, proxy));
      }

      // Shodan Monitor — list the watched IPs (network alerts named vteeee:<ip>).
      if (url.pathname === '/api/shodan/monitor' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.shodanApiKey) return json({ error: 'Shodan not configured' }, 400);
        return json(await shodanMonitorList(proxy, request.signal));
      }

      // Shodan Monitor — add/remove an IP (create/delete its alert).
      if (url.pathname === '/api/shodan/monitor' && request.method === 'POST') {
        if (origin && !originAllowed(origin, allowed)) return json({ error: 'origin not allowed' }, 403);
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.shodanApiKey) return json({ error: 'Shodan not configured' }, 400);
        const b = (await request.json()) as { ip?: string; action?: string };
        if (!b.ip) return json({ error: 'ip required' }, 400);
        return json(
          b.action === 'remove'
            ? await shodanMonitorRemove(b.ip, proxy, request.signal)
            : await shodanMonitorAdd(b.ip, proxy, request.signal),
        );
      }

      // Re-fetch Shodan host banners on demand (e.g. after a re-scan).
      if (url.pathname === '/api/shodan/host' && request.method === 'GET') {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.shodanApiKey) return json({ error: 'Shodan not configured' }, 400);
        const ip = url.searchParams.get('ip') ?? '';
        if (!ip) return json({ error: 'ip required' }, 400);
        return json((await shodanHostLookup(ip, proxy, request.signal)) ?? { found: false, error: 'unavailable' });
      }

      // On-demand SOC Prime Uncoder AI — generate a SIEM hunting query from a block of IOCs.
      if (url.pathname === '/api/socprime/ioc-query' && request.method === 'POST') {
        if (origin && !originAllowed(origin, allowed)) return json({ error: 'origin not allowed' }, 403);
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.socprimeApiKey) return json({ error: 'SOC Prime not configured' }, 400);
        const b = (await request.json()) as {
          text?: string;
          siemType?: string;
          iocsPerQuery?: number;
          includeSourceIp?: boolean;
          includeIocTypes?: string[];
        };
        if (!b.text || !b.siemType) return json({ error: 'text and siemType required' }, 400);
        return json(
          (await socprimeGenerateQuery(
            b.text,
            {
              siemType: b.siemType,
              iocsPerQuery: b.iocsPerQuery,
              includeSourceIp: b.includeSourceIp,
              includeIocTypes: b.includeIocTypes,
            },
            proxy,
            request.signal,
          )) ?? { error: 'unavailable' },
        );
      }

      // On-demand SOC Prime detection-rule search (Sigma rules → chosen SIEM format).
      if (url.pathname === '/api/socprime/rules' && request.method === 'POST') {
        if (origin && !originAllowed(origin, allowed)) return json({ error: 'origin not allowed' }, 403);
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.socprimeApiKey) return json({ error: 'SOC Prime not configured' }, 400);
        const p = (await request.json()) as {
          siemType?: string;
          query?: string;
          actor?: string;
          tool?: string;
          techniqueId?: string;
          sigmaLevel?: string;
          sigmaType?: string;
          pageSize?: number;
          pageNumber?: number;
        };
        if (!p.siemType) return json({ error: 'siemType required' }, 400);
        return json(
          (await socprimeSearchRules(
            {
              siemType: p.siemType,
              query: p.query,
              actor: p.actor,
              tool: p.tool,
              techniqueId: p.techniqueId,
              sigmaLevel: p.sigmaLevel,
              sigmaType: p.sigmaType,
              pageSize: p.pageSize,
              pageNumber: p.pageNumber,
            },
            proxy,
            request.signal,
          )) ?? { error: 'unavailable' },
        );
      }

      if (url.pathname === '/api/admin/users') {
        if (!checkAdmin(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (request.method === 'GET') return json(await getUsers(store));
        if (request.method === 'PUT') {
          const b = (await request.json()) as { users?: UserRecord[] };
          await putUsers(store, b.users ?? []);
          return json({ ok: true });
        }
      }

      if (url.pathname === '/api/admin/settings') {
        if (!checkAdmin(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (request.method === 'GET') return json(await getSettings(store));
        if (request.method === 'PUT') {
          const b = (await request.json()) as { settings?: AppSettings };
          if (b.settings) await putSettings(store, b.settings);
          return json({ ok: true });
        }
      }

      if (url.pathname === '/api/history' || url.pathname.startsWith('/api/history/')) {
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        const id = url.pathname.startsWith('/api/history/')
          ? decodeURIComponent(url.pathname.slice('/api/history/'.length)) || null
          : null;
        const user = request.headers.get('x-vteeee-user') ?? undefined;
        const ip =
          request.headers.get('cf-connecting-ip') ??
          request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ??
          undefined;
        const adminView = checkAdminToken(request.headers.get('x-vteeee-admin'), proxy);
        if (request.method === 'DELETE' && !id && !adminView)
          return json({ error: 'admin token required to clear all history' }, 403);
        const hbody =
          request.method === 'POST' || request.method === 'PUT' ? await request.json() : undefined;
        const envDays = Number(env.HISTORY_DAYS ?? 30);
        let retentionDays = envDays;
        if (request.method === 'POST') {
          const rd = (hbody as { retentionDays?: number } | undefined)?.retentionDays;
          if (typeof rd === 'number' && rd >= 0) retentionDays = Math.min(rd, 366);
        }
        const r = await historyRoute(
          request.method,
          id,
          hbody,
          kvHistoryBackend(env.VTEEEE_KV as unknown as KVLike),
          { retentionDays, user, ip, adminView },
        );
        return json(r.body, r.status);
      }

      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: (e as Error).message }, 500);
    }
  },

  /** Cloudflare Cron Trigger (see wrangler.toml [triggers]): once a day, server-side re-enrich every
   *  IP opted into auto-enrich and write the fresh snapshots back to the shared watchlist, so every
   *  client picks them up on next sync — no browser needs to be open. */
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const { proxy, store } = build(env);
    ctx.waitUntil(
      runAllScheduledEnrich(store, proxy).then(
        () => undefined,
        () => undefined,
      ),
    );
  },
};
