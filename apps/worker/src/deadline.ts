/**
 * Whole-audit wall-clock cap (AUDIT_TIMEOUT_MS). Stage caps bound each container, but not the
 * sum, nor the VM 1 side (LLM review, OSV, vision): without this, a slow repo plus slow
 * upstreams can hold the single audit slot far longer than intended.
 *
 * The clock is paused while the audit waits for the human's approval (that wait has its own
 * TTL), so the cap measures the time the audit is actually working. When it runs out, `expiry`
 * rejects with AuditTimeout and `onExpire` runs (the pipeline stops the sandbox there).
 *
 * `commit()` is the point of no return for a finishing audit: after it the deadline no longer
 * fires, so a timeout can never race a completed report into the database (and vice versa).
 */
export class AuditTimeout extends Error {
  constructor(readonly limitMs: number) {
    super(`the audit exceeded its ${Math.round(limitMs / 60_000)} min time limit and was stopped`);
    this.name = "AuditTimeout";
  }
}

export class AuditClock {
  /** Rejects with AuditTimeout when the clock runs out. Never resolves. */
  readonly expiry: Promise<never>;
  private reject!: (e: Error) => void;
  private remaining: number;
  private armedAt = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private committed = false;
  private stopped = false;
  private _expired = false;

  constructor(
    readonly limitMs: number,
    private readonly onExpire: () => void = () => {},
  ) {
    this.remaining = limitMs;
    this.expiry = new Promise<never>((_, reject) => {
      this.reject = reject;
    });
    // Nobody may be racing it when it fires (e.g. the audit already failed): not unhandled.
    this.expiry.catch(() => {});
  }

  get expired(): boolean {
    return this._expired;
  }

  /** Start (or resume) counting. No-op when already running, expired, committed or stopped. */
  start(): void {
    if (this.timer || this._expired || this.committed || this.stopped) return;
    this.armedAt = Date.now();
    this.timer = setTimeout(() => this.fire(), Math.max(0, this.remaining));
  }

  /** Stop counting until the next start(); the time used so far is kept. */
  pause(): void {
    if (!this.timer) return;
    clearTimeout(this.timer);
    this.timer = undefined;
    this.remaining -= Date.now() - this.armedAt;
  }

  /** Throw AuditTimeout if the clock has run out. Call before any step with side effects. */
  check(): void {
    if (this._expired) throw new AuditTimeout(this.limitMs);
  }

  /**
   * Claim the right to finish normally. Returns false (and changes nothing) if the clock already
   * ran out; otherwise the deadline is disarmed for good.
   */
  commit(): boolean {
    if (this._expired) return false;
    this.committed = true;
    this.clear();
    return true;
  }

  /** Disarm without expiring (the audit is over either way). */
  stop(): void {
    this.stopped = true;
    this.clear();
  }

  private clear(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
  }

  private fire(): void {
    this.timer = undefined;
    if (this.committed || this.stopped || this._expired) return;
    this._expired = true;
    try {
      this.onExpire();
    } catch {
      // the timeout itself must still land
    }
    this.reject(new AuditTimeout(this.limitMs));
  }
}
