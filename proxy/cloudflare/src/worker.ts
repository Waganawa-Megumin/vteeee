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
  type ProxyEnv,
  type Storage,
} from '@vteeee/proxy-core';
import type { AppSettings, EnrichRequest, UserRecord } from '@vteeee/shared';

interface Env {
  VT_API_KEY: string;
  ANTHROPIC_API_KEY?: string;
  ACCESS_TOKEN?: string;
  ADMIN_TOKEN?: string;
  ALLOWED_ORIGINS?: string;
  VT_RPM?: string;
  VT_MAX_RPM?: string;
  CLAUDE_MODEL?: string;
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
    accessToken: env.ACCESS_TOKEN,
    adminToken: env.ADMIN_TOKEN,
    allowedOrigins: allowed,
    defaultRpm: Number(env.VT_RPM ?? 4),
    maxRpm: Number(env.VT_MAX_RPM ?? 1000),
    claudeModel: env.CLAUDE_MODEL,
    xTool: 'vteeee',
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
      if (url.pathname === '/health') return json({ ok: true, vtKey: Boolean(proxy.vtApiKey) });

      if (url.pathname === '/api/enrich' && request.method === 'POST') {
        if (origin && !originAllowed(origin, allowed)) return json({ error: 'origin not allowed' }, 403);
        if (!checkAccess(auth, proxy)) return json({ error: 'unauthorized' }, 401);
        if (!proxy.vtApiKey) return json({ error: 'VT_API_KEY not configured' }, 500);
        const body = (await request.json()) as EnrichRequest;
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

      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: (e as Error).message }, 500);
    }
  },
};
