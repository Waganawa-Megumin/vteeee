import type { HistoryRecord, HistorySummary } from '@vteeee/shared';
import type { HistorySource } from '../lib/history';

export interface HistoryCtx {
  /** Login username (for owner tagging + per-user scoping). */
  user?: string;
  /** Admin token — when present and valid, the proxy returns everyone's history. */
  adminToken?: string | null;
}

function headers(token: string | null | undefined, ctx?: HistoryCtx): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) h['Authorization'] = `Bearer ${token}`;
  if (ctx?.user) h['X-Vteeee-User'] = ctx.user;
  if (ctx?.adminToken) h['X-Vteeee-Admin'] = ctx.adminToken;
  return h;
}

/** Shared history backed by the proxy (Cloudflare KV / Node file store). */
export function remoteHistorySource(
  base: string,
  token?: string | null,
  ctx?: HistoryCtx,
): HistorySource {
  const b = base.replace(/\/$/, '');
  return {
    shared: true,
    async list() {
      const r = await fetch(`${b}/api/history`, { headers: headers(token, ctx) });
      if (!r.ok) return [];
      return ((await r.json()) as { entries: HistorySummary[] }).entries ?? [];
    },
    async get(id) {
      const r = await fetch(`${b}/api/history/${encodeURIComponent(id)}`, { headers: headers(token, ctx) });
      return r.ok ? ((await r.json()) as HistoryRecord) : null;
    },
    async update(id, patch) {
      await fetch(`${b}/api/history/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: headers(token, ctx),
        body: JSON.stringify(patch),
      });
    },
    async del(id) {
      await fetch(`${b}/api/history/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: headers(token, ctx),
      });
    },
    async clear() {
      await fetch(`${b}/api/history`, { method: 'DELETE', headers: headers(token, ctx) });
    },
  };
}

export async function saveRemote(
  base: string,
  token: string | null | undefined,
  rec: HistoryRecord,
  retentionDays: number,
  user?: string,
): Promise<void> {
  await fetch(`${base.replace(/\/$/, '')}/api/history`, {
    method: 'POST',
    headers: headers(token, { user }),
    body: JSON.stringify({ ...rec, retentionDays }),
  });
}
