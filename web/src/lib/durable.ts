// Durable client-side storage helpers.
//
// Browsers (especially mobile Safari's ITP) can evict localStorage after ~7 days
// of inactivity — which is exactly why saved settings/tokens "disappear". Two
// mitigations, both best-effort and safe no-ops where unsupported:
//
//   1) Ask the browser to mark our storage *persistent*. On Chrome/Firefox this
//      is often auto-granted for engaged / bookmarked / installed sites and then
//      exempts us from eviction entirely.
//   2) Mirror critical config into IndexedDB and rehydrate localStorage from it,
//      so a localStorage-only clear (some privacy tools, partial evictions)
//      doesn't lose the tokens.

const DB_NAME = 'vteeee';
const STORE = 'kv';

function openDb(): Promise<IDBDatabase | null> {
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export async function idbGet(key: string): Promise<string | null> {
  const db = await openDb();
  if (!db) return null;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(key);
      req.onsuccess = () => resolve((req.result as string | undefined) ?? null);
      req.onerror = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
}

export async function idbSet(key: string, value: string): Promise<void> {
  const db = await openDb();
  if (!db) return;
  await new Promise<void>((resolve) => {
    try {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(value, key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
    } catch {
      resolve();
    }
  });
}

/**
 * Read a key from IndexedDB and, if present, write it back into localStorage so
 * subsequent synchronous reads succeed. Returns the value (or null).
 */
export async function rehydrateFromIdb(key: string): Promise<string | null> {
  const v = await idbGet(key);
  if (v) {
    try {
      localStorage.setItem(key, v);
    } catch {
      /* ignore */
    }
  }
  return v;
}

/** Ask the browser to keep our storage from being evicted. Safe no-op if unsupported. */
export async function requestPersistentStorage(): Promise<boolean> {
  try {
    const sm = navigator.storage;
    if (sm?.persist) {
      if (sm.persisted && (await sm.persisted())) return true;
      return await sm.persist();
    }
  } catch {
    /* ignore */
  }
  return false;
}
