import express, { type Request, type Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
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

// In-memory daily quota guard (single process). Resets at local midnight.
const DAILY_CAP = Number(process.env.VT_DAILY ?? 500);
let dailyCount = 0;
let dailyDay = new Date().toDateString();
function consumeQuota(): boolean {
  const d = new Date().toDateString();
  if (d !== dailyDay) {
    dailyDay = d;
    dailyCount = 0;
  }
  if (dailyCount >= DAILY_CAP) return false;
  dailyCount++;
  return true;
}

const env: ProxyEnv = {
  vtApiKey: process.env.VT_API_KEY ?? '',
  anthropicApiKey: process.env.ANTHROPIC_API_KEY || undefined,
  accessToken: process.env.ACCESS_TOKEN || undefined,
  adminToken: process.env.ADMIN_TOKEN || undefined,
  allowedOrigins,
  defaultRpm: Number(process.env.VT_RPM ?? 4),
  maxRpm: Number(process.env.VT_MAX_RPM ?? 1000),
  claudeModel: process.env.CLAUDE_MODEL || undefined,
  xTool: process.env.VT_X_TOOL ?? 'vteeee',
  consumeQuota,
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

const app = express();
app.use(express.json({ limit: '4mb' }));

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
  res.json({ ok: true, vtKey: Boolean(env.vtApiKey), claude: Boolean(env.anthropicApiKey) });
});

app.post('/api/enrich', async (req, res) => {
  if (!requireAccess(req, res)) return;
  if (!env.vtApiKey) {
    res.status(500).json({ error: 'VT_API_KEY not configured' });
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

app.listen(PORT, () => {
  console.log(`vteeee proxy listening on :${PORT}`);
  console.log(`  allowed origins: ${allowedOrigins.join(', ')}`);
  console.log(`  VT key: ${env.vtApiKey ? 'set' : 'MISSING'} · Claude: ${env.anthropicApiKey ? 'set' : 'off (regex fallback)'}`);
});
