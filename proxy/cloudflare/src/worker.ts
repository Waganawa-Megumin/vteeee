import {
  runEnrich,
  ndjson,
  smartParse,
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
import type { AppSettings, EnrichRequest, UserRecord } from '@vteeee/shared';

interface Env {
  VT_API_KEY: string;
  ANTHROPIC_API_KEY?: string;
  SHODAN_API_KEY?: string;
  ACCESS_TOKEN?: string;
  ADMIN_TOKEN?: string;
  ALLOWED_ORIGINS?: string;
  VT_RPM?: string;
  VT_MAX_RPM?: string;
  SHODAN_RPM?: string;
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
    accessToken: env.ACCESS_TOKEN,
    adminToken: env.ADMIN_TOKEN,
    allowedOrigins: allowed,
    defaultRpm: Number(env.VT_RPM ?? 4),
    maxRpm: Number(env.VT_MAX_RPM ?? 1000),
    shodanRpm: env.SHODAN_RPM ? Number(env.SHODAN_RPM) : undefined,
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
};
