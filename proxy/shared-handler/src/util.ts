function abortError(): Error {
  const e = new Error('Aborted');
  e.name = 'AbortError';
  return e;
}

export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(abortError());
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => {
      clearTimeout(t);
      reject(abortError());
    });
  });
}

export function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

/** Exponential backoff with jitter, capped at 60s. */
export function backoffMs(attempt: number): number {
  const base = 2000 * 2 ** attempt;
  return Math.min(base + Math.random() * 500, 60_000);
}

/** Simple push/close async queue so a worker pool can stream events to a generator. */
export class AsyncQueue<T> {
  private items: T[] = [];
  private resolvers: ((r: IteratorResult<T>) => void)[] = [];
  private closed = false;

  push(item: T): void {
    if (this.closed) return;
    const r = this.resolvers.shift();
    if (r) r({ value: item, done: false });
    else this.items.push(item);
  }

  close(): void {
    this.closed = true;
    let r;
    while ((r = this.resolvers.shift())) r({ value: undefined as never, done: true });
  }

  [Symbol.asyncIterator](): AsyncIterator<T> {
    return {
      next: () =>
        new Promise<IteratorResult<T>>((resolve) => {
          if (this.items.length) resolve({ value: this.items.shift() as T, done: false });
          else if (this.closed) resolve({ value: undefined as never, done: true });
          else this.resolvers.push(resolve);
        }),
    };
  }
}
