import type { HistoryRecord, HistorySummary } from '@vteeee/shared';

const PREFIX = 'hist:';
const MIN_TTL = 60;
const NOTE_PREVIEW = 160;

/** Minimal structural type matching Cloudflare KV (no @cloudflare/workers-types dependency). */
export interface KVLike {
  put(
    key: string,
    value: string,
    options?: { expirationTtl?: number; expiration?: number; metadata?: Record<string, unknown> },
  ): Promise<void>;
  get(key: string): Promise<string | null>;
  list(options?: {
    prefix?: string;
    limit?: number;
    cursor?: string;
  }): Promise<{ keys: { name: string; metadata?: unknown }[]; list_complete: boolean; cursor?: string }>;
  delete(key: string): Promise<void>;
}

export interface HistoryBackend {
  save(rec: HistoryRecord, ttlSeconds: number): Promise<void>;
  list(limit: number): Promise<HistorySummary[]>;
  get(id: string): Promise<HistoryRecord | null>;
  update(id: string, patch: { tags?: string[]; note?: string }, retentionDays: number): Promise<HistorySummary | null>;
  del(id: string): Promise<void>;
  clear(): Promise<void>;
}

export function summarize(rec: HistoryRecord): HistorySummary {
  let malicious = 0;
  let suspicious = 0;
  for (const r of rec.results) {
    if (r.verdict === 'malicious') malicious++;
    else if (r.verdict === 'suspicious') suspicious++;
  }
  return {
    id: rec.id,
    createdAt: rec.createdAt,
    mode: rec.mode,
    total: rec.results.length,
    malicious,
    suspicious,
    inputPreview: rec.input.replace(/\s+/g, ' ').trim().slice(0, 90),
    tags: rec.tags?.slice(0, 8),
    note: rec.note ? rec.note.slice(0, NOTE_PREVIEW) : undefined,
  };
}

const keyFor = (id: string) => `${PREFIX}${id}`;

/** KV-backed history: full records (incl. raw) in the value, summary in metadata for cheap listing. */
export function kvHistoryBackend(kv: KVLike): HistoryBackend {
  async function putRecord(rec: HistoryRecord, ttlSeconds: number): Promise<void> {
    await kv.put(keyFor(rec.id), JSON.stringify(rec), {
      expirationTtl: Math.max(MIN_TTL, Math.floor(ttlSeconds)),
      metadata: summarize(rec) as unknown as Record<string, unknown>,
    });
  }

  return {
    save: (rec, ttl) => putRecord(rec, ttl),

    async list(limit) {
      const res = await kv.list({ prefix: PREFIX, limit: Math.min(Math.max(limit, 1), 1000) });
      return res.keys
        .map((k) => k.metadata as HistorySummary | undefined)
        .filter((m): m is HistorySummary => !!m)
        .sort((a, b) => b.createdAt - a.createdAt)
        .slice(0, limit);
    },

    async get(id) {
      const v = await kv.get(keyFor(id));
      return v ? (JSON.parse(v) as HistoryRecord) : null;
    },

    async update(id, patch, retentionDays) {
      const v = await kv.get(keyFor(id));
      if (!v) return null;
      const rec = JSON.parse(v) as HistoryRecord;
      if (patch.tags) rec.tags = patch.tags.slice(0, 32);
      if (patch.note !== undefined) rec.note = patch.note.slice(0, 4000);
      // Preserve the original expiry window from createdAt.
      const ttl = Math.max(MIN_TTL, Math.floor(rec.createdAt / 1000 + retentionDays * 86400 - Date.now() / 1000));
      await putRecord(rec, ttl);
      return summarize(rec);
    },

    del: (id) => kv.delete(keyFor(id)),

    async clear() {
      const res = await kv.list({ prefix: PREFIX, limit: 1000 });
      await Promise.all(res.keys.map((k) => kv.delete(k.name)));
    },
  };
}

/** Route /api/history* against a backend. Auth/CORS are handled by the caller. */
export async function historyRoute(
  method: string,
  id: string | null,
  body: unknown,
  backend: HistoryBackend,
  opts: { retentionDays: number; maxList?: number },
): Promise<{ status: number; body: unknown }> {
  if (method === 'POST') {
    if (opts.retentionDays <= 0) return { status: 200, body: { skipped: true } };
    const rec = (body ?? {}) as Partial<HistoryRecord> & { retentionDays?: number };
    if (!Array.isArray(rec.results)) return { status: 400, body: { error: 'invalid record' } };
    const full: HistoryRecord = {
      id: rec.id ?? Math.random().toString(36).slice(2) + Date.now().toString(36),
      createdAt: typeof rec.createdAt === 'number' ? rec.createdAt : Date.now(),
      mode: rec.mode === 'live' ? 'live' : 'demo',
      input: typeof rec.input === 'string' ? rec.input : '',
      stats:
        rec.stats ?? {
          total: rec.results.length,
          unique: rec.results.length,
          duplicates: 0,
          unknown: 0,
          private: 0,
          enrichable: rec.results.length,
        },
      results: rec.results,
      tags: rec.tags,
      note: rec.note,
    };
    await backend.save(full, opts.retentionDays * 86400);
    return { status: 200, body: { id: full.id } };
  }

  if (method === 'GET' && id) {
    const r = await backend.get(id);
    return r ? { status: 200, body: r } : { status: 404, body: { error: 'not found' } };
  }
  if (method === 'GET') return { status: 200, body: { entries: await backend.list(opts.maxList ?? 100) } };

  if (method === 'PUT' && id) {
    const patch = (body ?? {}) as { tags?: string[]; note?: string };
    const s = await backend.update(id, patch, opts.retentionDays);
    return s ? { status: 200, body: s } : { status: 404, body: { error: 'not found' } };
  }

  if (method === 'DELETE' && id) {
    await backend.del(id);
    return { status: 200, body: { ok: true } };
  }
  if (method === 'DELETE') {
    await backend.clear();
    return { status: 200, body: { ok: true } };
  }
  return { status: 405, body: { error: 'method not allowed' } };
}
