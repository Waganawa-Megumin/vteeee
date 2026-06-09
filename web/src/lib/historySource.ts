import type { AppSettings, HistoryRecord, Session } from '@vteeee/shared';
import { localHistorySource, saveLocal, type HistorySource } from './history';
import { remoteHistorySource, saveRemote } from '../api/historyClient';

/** Live (proxy URL set) → shared KV history; otherwise → local per-browser history. */
export function historySource(settings: AppSettings, session: Session | null): HistorySource {
  if (settings.proxyBaseUrl) {
    return remoteHistorySource(settings.proxyBaseUrl, settings.accessToken, {
      user: session?.username,
      adminToken: session?.role === 'admin' ? settings.adminToken : undefined,
    });
  }
  return localHistorySource(settings.historyRetentionDays ?? 30);
}

export async function saveHistory(
  rec: HistoryRecord,
  settings: AppSettings,
  session: Session | null,
): Promise<void> {
  const days = settings.historyRetentionDays ?? 30;
  if (days <= 0) return;
  const owned: HistoryRecord = { ...rec, owner: session?.username };
  if (settings.proxyBaseUrl) {
    try {
      await saveRemote(settings.proxyBaseUrl, settings.accessToken, owned, days, session?.username);
    } catch {
      /* don't block the UI on a history write */
    }
  } else {
    saveLocal(owned, days);
  }
}
