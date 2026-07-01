import express, { type Request, type Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import {
  runEnrich,
  ndjson,
  smartParse,
  intel471GlobalSearch,
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
  historyRoute,
  type ProxyEnv,
  type Storage,
} from '@vteeee/proxy-core';
import { fileHistoryBackend } from './historyFile';

// Load local secrets from .dev.vars / .env if present (Node 20.12+).
for (const f of ['.dev.vars', '.env']) {
  try {
    if (fs.existsSync(f)) process.loadEnvFile(f);
  } catch {
    /* ignore */
  }
}

const PORT = Number(process.env.PORT ?? 8787);
const allowedOrigins = (process.env.ALLOWED_ORIGINS ?? 'http://localhost:5173')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const env: ProxyEnv = {
  vtApiKey: process.env.VT_API_KEY ?? '',
  anthropicApiKey: process.env.ANTHROPIC_API_KEY || undefined,
  shodanApiKey: process.env.SHODAN_API_KEY || undefined,
  domaintoolsApiUsername: process.env.DOMAINTOOLS_API_USERNAME || undefined,
  domaintoolsApiKey: process.env.DOMAINTOOLS_API_KEY || undefined,
  dnslyticsApiKey: process.env.DNSLYTICS_API_KEY || undefined,
  dnslyticsBaseUrl: process.env.DNSLYTICS_BASE_URL || undefined,
  intel471ApiUser: process.env.INTEL471_API_USER || undefined,
  intel471ApiKey: process.env.INTEL471_API_KEY || undefined,
  intel471BaseUrl: process.env.INTEL471_BASE_URL || undefined,
  intel471Rpm: process.env.INTEL471_RPM ? Number(process.env.INTEL471_RPM) : undefined,
  accessToken: process.env.ACCESS_TOKEN || undefined,
  adminToken: process.env.ADMIN_TOKEN || undefined,
  allowedOrigins,
  defaultRpm: Number(process.env.VT_RPM ?? 4),
  maxRpm: Number(process.env.VT_MAX_RPM ?? 1000),
  shodanRpm: process.env.SHODAN_RPM ? Number(process.env.SHODAN_RPM) : undefined,
  domaintoolsRpm: process.env.DOMAINTOOLS_RPM ? Number(process.env.DOMAINTOOLS_RPM) : undefined,
  dnslyticsRpm: process.env.DNSLYTICS_RPM ? Number(process.env.DNSLYTICS_RPM) : undefined,
  claudeModel: process.env.CLAUDE_MODEL || undefined,
  xTool: process.env.VT_X_TOOL ?? 'vteeee',
  maxBatch: Number(process.env.MAX_BATCH ?? 1000),
  dailyCap: Number(process.env.VT_DAILY ?? 500),
  parseDailyCap: Number(process.env.PARSE_DAILY ?? 200),
};

// JSON file storage for users/settings.
const DATA_DIR = process.env.DATA_DIR ?? path.join(process.cwd(), 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const store: Storage = {
  async get(key) {
    const f = path.join(DATA_DIR, `${key}.json`);
    return fs.existsSync(f) ? fs.readFileSync(f, 'utf8') : null;
  },
  async put(key, value) {
    fs.writeFileSync(path.join(DATA_DIR, `${key}.json`), value);
  },
};

const history = fileHistoryBackend(DATA_DIR);

const app = express();
app.use(express.json({ limit: '8mb' }));

app.use((req, res, next) => {
  const origin = req.headers.origin ?? null;
  for (const [k, v] of Object.entries(corsHeaders(origin, allowedOrigins))) res.setHeader(k, v);
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
});

function requireAccess(req: Request, res: Response): boolean {
  const origin = req.headers.origin ?? null;
  if (origin && !originAllowed(origin, allowedOrigins)) {
    res.status(403).json({ error: 'origin not allowed' });
    return false;
  }
  if (!checkAccess(req.headers.authorization, env)) {
    res.status(401).json({ error: 'unauthorized' });
    return false;
  }
  return true;
}

function requireAdmin(req: Request, res: Response): boolean {
  if (!checkAdmin(req.headers.authorization, env)) {
    res.status(401).json({ error: 'unauthorized' });
    return false;
  }
  return true;
}

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    vtKey: Boolean(env.vtApiKey),
    claude: Boolean(env.anthropicApiKey),
    shodan: Boolean(env.shodanApiKey),
    domaintools: Boolean(env.domaintoolsApiUsername && env.domaintoolsApiKey),
    dnslytics: Boolean(env.dnslyticsApiKey),
    intel471: Boolean(env.intel471ApiUser && env.intel471ApiKey),
  });
});

app.get('/api/intel471/search', async (req, res) => {
  if (!requireAccess(req, res)) return;
  if (!env.intel471ApiUser || !env.intel471ApiKey) {
    res.status(400).json({ error: 'Intel 471 not configured' });
    return;
  }
  const ioc = (req.query.ioc as string) || '';
  const type = ((req.query.type as string) || 'unknown') as import('@vteeee/shared').EnrichableType;
  if (!ioc) {
    res.status(400).json({ error: 'ioc required' });
    return;
  }
  res.json((await intel471GlobalSearch(ioc, type, env)) ?? { error: 'unavailable' });
});

app.post('/api/enrich', async (req, res) => {
  if (!requireAccess(req, res)) return;
  if (!env.vtApiKey) {
    res.status(500).json({ error: 'VT_API_KEY not configured' });
    return;
  }
  const inds = req.body?.indicators;
  if (!Array.isArray(inds) || inds.length === 0) {
    res.status(400).json({ error: 'no indicators provided' });
    return;
  }
  if (inds.length > env.maxBatch) {
    res.status(400).json({ error: `too many indicators in one request (max ${env.maxBatch})` });
    return;
  }
  if (!(await consumeDailyQuota(store, 'vt', env.dailyCap, inds.length))) {
    res.status(429).json({
      error: `daily lookup quota (${env.dailyCap}) would be exceeded — reduce the list or try again tomorrow`,
    });
    return;
  }
  res.setHeader('Content-Type', 'application/x-ndjson');
  res.setHeader('Cache-Control', 'no-store');
  res.flushHeaders();
  const ac = new AbortController();
  // Abort only if the client disconnects before we finish streaming.
  res.on('close', () => {
    if (!res.writableEnded) ac.abort();
  });
  try {
    for await (const ev of runEnrich(req.body, env, ac.signal)) {
      res.write(ndjson(ev));
    }
  } catch (e) {
    res.write(ndjson({ event: 'error', message: (e as Error).message }));
  }
  res.end();
});

app.post('/api/parse', async (req, res) => {
  if (!requireAccess(req, res)) return;
  if (!(await consumeDailyQuota(store, 'parse', env.parseDailyCap, 1))) {
    res.status(429).json({ error: 'daily smart-parse quota reached' });
    return;
  }
  try {
    res.json(await smartParse(req.body?.text ?? '', env, req.body?.maxIndicators));
  } catch (e) {
    res.status(500).json({ error: (e as Error).message });
  }
});

app.get('/api/admin/users', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(await getUsers(store));
});
app.put('/api/admin/users', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  await putUsers(store, req.body?.users ?? []);
  res.json({ ok: true });
});
app.get('/api/admin/settings', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  res.json(await getSettings(store));
});
app.put('/api/admin/settings', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  await putSettings(store, req.body?.settings);
  res.json({ ok: true });
});

async function handleHistory(req: Request, res: Response, id: string | null) {
  if (!requireAccess(req, res)) return;
  const user = (req.headers['x-vteeee-user'] as string | undefined) || undefined;
  const ip =
    (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim() ||
    req.socket.remoteAddress ||
    undefined;
  const adminView = checkAdminToken((req.headers['x-vteeee-admin'] as string | undefined) ?? null, env);
  if (req.method === 'DELETE' && !id && !adminView) {
    res.status(403).json({ error: 'admin token required to clear all history' });
    return;
  }
  let retentionDays = Number(process.env.HISTORY_DAYS ?? 30);
  if (req.method === 'POST' && typeof req.body?.retentionDays === 'number') {
    retentionDays = Math.min(Math.max(req.body.retentionDays, 0), 366);
  }
  const r = await historyRoute(req.method, id, req.body, history, { retentionDays, user, ip, adminView });
  res.status(r.status).json(r.body);
}
app.all('/api/history', (req, res) => void handleHistory(req, res, null));
app.all('/api/history/:id', (req, res) => void handleHistory(req, res, req.params.id));

app.listen(PORT, () => {
  console.log(`vteeee proxy listening on :${PORT}`);
  console.log(`  allowed origins: ${allowedOrigins.join(', ')}`);
  console.log(`  VT key: ${env.vtApiKey ? 'set' : 'MISSING'} · Claude: ${env.anthropicApiKey ? 'set' : 'off (regex fallback)'} · Shodan: ${env.shodanApiKey ? 'set' : 'off'} · DomainTools: ${env.domaintoolsApiUsername && env.domaintoolsApiKey ? 'set' : 'off'} · DNSLytics: ${env.dnslyticsApiKey ? 'set' : 'off'} · Intel471: ${env.intel471ApiUser && env.intel471ApiKey ? 'set' : 'off'}`);
});
