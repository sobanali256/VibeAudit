import { MAX_CONCURRENT_AUDITS, QUEUED_MAX_AGE_MS, WORKER_LEASE_MS } from "@vibeaudit/shared";
import { CHANNEL_QUEUE, type Sql, claimNextAudit, failStaleAudits } from "@vibeaudit/db";
import { Sandbox, cliDocker } from "./sandbox";
import { runAudit } from "./pipeline";
import type { LlmClient } from "./llm";
import type { OsvClient } from "./deps";

export interface LoopConfig {
  sql: Sql;
  dockerHost: string;
  proxyUrl: string;
  githubToken?: string;
  /** LLM client for the static review stage (optional). */
  llm?: LlmClient;
  osv?: OsvClient;
  /** Fallback poll even without a NOTIFY (also drives the stale-audit sweep). */
  pollMs?: number;
}

/**
 * The worker's main loop. One audit at a time (MAX_CONCURRENT_AUDITS): claim, run it to
 * completion, then look for the next. A LISTEN on the queue channel wakes it promptly when a
 * new audit is enqueued or a slot frees; a timer is the backstop and also sweeps crashed
 * audits. Returns a stop() to shut down cleanly.
 */
export async function runLoop(cfg: LoopConfig): Promise<() => Promise<void>> {
  const { sql } = cfg;
  const pollMs = cfg.pollMs ?? 15_000;
  let stopped = false;
  let running = false;
  let wake: () => void = () => {};

  const listener = await sql.listen(CHANNEL_QUEUE, () => wake());

  async function tick() {
    if (stopped || running) return;
    running = true;
    try {
      await failStaleAudits(sql, WORKER_LEASE_MS, QUEUED_MAX_AGE_MS).catch((e) => console.error("[worker] sweep:", e?.message));
      // Drain the queue while slots are free (one at a time here).
      for (;;) {
        if (stopped) break;
        const audit = await claimNextAudit(sql, MAX_CONCURRENT_AUDITS);
        if (!audit) break;
        console.log(`[worker] running audit ${audit.id}`);
        const sandbox = new Sandbox(audit.id, cfg.proxyUrl, cliDocker(cfg.dockerHost));
        await runAudit(audit, { sql, sandbox, proxyUrl: cfg.proxyUrl, token: cfg.githubToken, llm: cfg.llm, osv: cfg.osv });
        console.log(`[worker] finished audit ${audit.id}`);
      }
    } finally {
      running = false;
    }
  }

  const timer = setInterval(() => void tick().catch((e) => console.error("[worker] tick:", e?.message)), pollMs);
  wake = () => void tick().catch((e) => console.error("[worker] wake:", e?.message));
  void tick();

  return async function stop() {
    stopped = true;
    clearInterval(timer);
    await listener.unlisten().catch(() => {});
  };
}
