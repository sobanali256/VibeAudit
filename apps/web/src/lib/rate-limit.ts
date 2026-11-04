import "server-only";

/**
 * Fixed-window counters in process memory. Good enough for one web process behind Caddy;
 * the real back-pressure is the queue cap (countOpenAudits). Old windows are swept lazily so
 * the map stays bounded by active clients.
 */
export class RateLimiter {
  private hits = new Map<string, { n: number; resetAt: number }>();
  private lastSweep = 0;

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly maxKeys = 10_000,
  ) {}

  /** Returns 0 if allowed, else seconds until the window resets. */
  take(key: string, now = Date.now()): number {
    if (now - this.lastSweep > this.windowMs) {
      for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k);
      this.lastSweep = now;
    }
    let h = this.hits.get(key);
    if (!h || h.resetAt <= now) {
      if (!h && this.hits.size >= this.maxKeys) {
        // Full: evict the oldest window (Map keeps insertion order) rather than refusing
        // everyone new, which would let a key-flooder lock out all other clients.
        const oldest = this.hits.keys().next().value;
        if (oldest !== undefined) this.hits.delete(oldest);
      }
      h = { n: 0, resetAt: now + this.windowMs };
      this.hits.delete(key); // re-insert at the end so eviction order stays oldest-first
      this.hits.set(key, h);
    }
    if (h.n >= this.limit) return Math.max(1, Math.ceil((h.resetAt - now) / 1000));
    h.n++;
    return 0;
  }
}

const g = globalThis as typeof globalThis & { __vibeauditLimits?: Record<string, RateLimiter> };
g.__vibeauditLimits ??= {
  create: new RateLimiter(5, 10 * 60_000),
  approve: new RateLimiter(20, 60_000),
  read: new RateLimiter(120, 60_000),
};
export const limits = g.__vibeauditLimits;
