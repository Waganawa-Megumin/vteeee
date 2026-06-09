import type { AppSettings, HistoryRecord } from '@vteeee/shared';
import { localHistorySource, saveLocal, type HistorySource } from './history';
import { remoteHistorySource, saveRemote } from '../api/historyClient';

/** Live (proxy URL set) → shared KV history; otherwise → local per-browser history. */
export function historySource(settings: AppSettings): HistorySource {
  if (settings.proxyBaseUrl) return remoteHistorySource(settings.proxyBaseUrl, settings.accessToken);
  return localHistorySource(settings.historyRetentionDays ?? 30);
}

export async function saveHistory(rec: HistoryRecord, settings: AppSettings): Promise<void> {
  const days = settings.historyRetentionDays ?? 30;
  if (days <= 0) return;
  if (settings.proxyBaseUrl) {
    try {
      await saveRemote(settings.proxyBaseUrl, settings.accessToken, rec, days);
    } catch {
      /* don't block the UI on a history write */
    }
  } else {
    saveLocal(rec, days);
  }
}
