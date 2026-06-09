import type { HistoryRecord, HistorySummary } from '@vteeee/shared';
import type { HistorySource } from '../lib/history';

function headers(token?: string | null): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) h['Authorization'] = `Bearer ${token}`;
  return h;
}

/** Shared history backed by the proxy (Cloudflare KV / Node file store). */
export function remoteHistorySource(base: string, token?: string | null): HistorySource {
  const b = base.replace(/\/$/, '');
  return {
    shared: true,
    async list() {
      const r = await fetch(`${b}/api/history`, { headers: headers(token) });
      if (!r.ok) return [];
      return ((await r.json()) as { entries: HistorySummary[] }).entries ?? [];
    },
    async get(id) {
      const r = await fetch(`${b}/api/history/${encodeURIComponent(id)}`, { headers: headers(token) });
      return r.ok ? ((await r.json()) as HistoryRecord) : null;
    },
    async update(id, patch) {
      await fetch(`${b}/api/history/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: headers(token),
        body: JSON.stringify(patch),
      });
    },
    async del(id) {
      await fetch(`${b}/api/history/${encodeURIComponent(id)}`, { method: 'DELETE', headers: headers(token) });
    },
    async clear() {
      await fetch(`${b}/api/history`, { method: 'DELETE', headers: headers(token) });
    },
  };
}

export async function saveRemote(
  base: string,
  token: string | null | undefined,
  rec: HistoryRecord,
  retentionDays: number,
): Promise<void> {
  await fetch(`${base.replace(/\/$/, '')}/api/history`, {
    method: 'POST',
    headers: headers(token),
    body: JSON.stringify({ ...rec, retentionDays }),
  });
}
