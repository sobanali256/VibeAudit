import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AuditClock, AuditTimeout } from "./deadline";

describe("AuditClock", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("expires after the limit: runs onExpire, rejects expiry, check() throws", async () => {
    const onExpire = vi.fn();
    const c = new AuditClock(1000, onExpire);
    const got = c.expiry.catch((e) => e);
    c.start();
    vi.advanceTimersByTime(999);
    expect(c.expired).toBe(false);
    expect(() => c.check()).not.toThrow();
    vi.advanceTimersByTime(1);
    expect(c.expired).toBe(true);
    expect(onExpire).toHaveBeenCalledOnce();
    expect(await got).toBeInstanceOf(AuditTimeout);
    expect(() => c.check()).toThrow(AuditTimeout);
  });

  it("pause() keeps the time used; start() resumes with the rest", () => {
    const c = new AuditClock(1000);
    c.start();
    vi.advanceTimersByTime(600);
    c.pause();
    vi.advanceTimersByTime(60_000); // approval wait: not counted
    expect(c.expired).toBe(false);
    c.start();
    vi.advanceTimersByTime(399);
    expect(c.expired).toBe(false);
    vi.advanceTimersByTime(1);
    expect(c.expired).toBe(true);
  });

  it("start() twice doesn't double-arm or reset the clock", () => {
    const c = new AuditClock(1000);
    c.start();
    vi.advanceTimersByTime(500);
    c.start();
    vi.advanceTimersByTime(500);
    expect(c.expired).toBe(true);
  });

  it("commit() disarms the deadline for good", () => {
    const onExpire = vi.fn();
    const c = new AuditClock(1000, onExpire);
    c.start();
    vi.advanceTimersByTime(900);
    expect(c.commit()).toBe(true);
    c.start(); // e.g. a late resume: must not re-arm
    vi.advanceTimersByTime(10_000);
    expect(c.expired).toBe(false);
    expect(onExpire).not.toHaveBeenCalled();
  });

  it("commit() after expiry refuses", () => {
    const c = new AuditClock(10);
    c.start();
    vi.advanceTimersByTime(10);
    expect(c.commit()).toBe(false);
    expect(c.expired).toBe(true);
  });

  it("stop() disarms without expiring; expiry rejection is never unhandled", () => {
    const c = new AuditClock(10);
    c.start();
    c.stop();
    vi.advanceTimersByTime(100);
    expect(c.expired).toBe(false);
  });

  it("a throwing onExpire still expires the clock", async () => {
    const c = new AuditClock(10, () => {
      throw new Error("boom");
    });
    const got = c.expiry.catch((e) => e);
    c.start();
    vi.advanceTimersByTime(10);
    expect(await got).toBeInstanceOf(AuditTimeout);
  });

  it("resume with no time left fires at once", () => {
    const c = new AuditClock(100);
    c.start();
    vi.advanceTimersByTime(100);
    expect(c.expired).toBe(true);
    const d = new AuditClock(100);
    d.start();
    vi.advanceTimersByTime(99);
    d.pause();
    d.start();
    vi.advanceTimersByTime(1);
    expect(d.expired).toBe(true);
  });

  it("the timeout races a hanging pipeline", async () => {
    const c = new AuditClock(1000);
    c.start();
    const hang = new Promise<void>(() => {});
    const race = Promise.race([hang, c.expiry]).catch((e) => e);
    vi.advanceTimersByTime(1000);
    expect(await race).toBeInstanceOf(AuditTimeout);
  });
});
