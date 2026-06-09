import { sleep } from './util';

/** Token-bucket limiter: capacity = rpm, refills rpm tokens per 60s. */
export class RateLimiter {
  private tokens: number;
  private lastRefill: number;

  constructor(private rpm: number) {
    this.tokens = rpm;
    this.lastRefill = Date.now();
  }

  private refill(): void {
    const now = Date.now();
    const minutes = (now - this.lastRefill) / 60_000;
    if (minutes > 0) {
      this.tokens = Math.min(this.rpm, this.tokens + minutes * this.rpm);
      this.lastRefill = now;
    }
  }

  async acquire(signal?: AbortSignal): Promise<void> {
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = ((1 - this.tokens) / this.rpm) * 60_000;
      await sleep(Math.min(Math.max(waitMs, 50), 2000), signal);
    }
  }
}
