import { AUDIT_LABEL, AUDIT_STAGES } from "@vibeaudit/shared";
import { createDb, migrate } from "@vibeaudit/db";
import { loadConfig } from "./config";
import { runLoop } from "./loop";
import { createLlm } from "./llm";
import { createOsv } from "./deps";
import { clearProxyState } from "./proxy-state";
import { cliDocker } from "./sandbox";

// Entry point for the audit worker (runs on VM 1). It consumes the job queue and drives the
// sandbox host (VM 2) over SSH via the Docker API, one audit at a time.
async function main() {
  const config = loadConfig();
  const sql = createDb(config.DATABASE_URL);
  const applied = await migrate(sql);
  // A crash could have left a dead audit's allowlist on disk; start from "block all".
  await clearProxyState().catch(() => {});
  // Same for VM 2: a restart mid-audit (a deploy) leaves its containers running, and killing the
  // docker CLI doesn't stop them. One audit at a time, so anything labelled now is stale; remove
  // it before the next audit's containers (a 5 GB build among them) start next to it.
  await sweepStaleContainers(config.SANDBOX_DOCKER_HOST);
  console.log(
    `[worker] starting; sandbox=${config.SANDBOX_DOCKER_HOST} migrations=${applied.length ? applied.join(",") : "up-to-date"} stages=${AUDIT_STAGES.join(" > ")}`,
  );

  const llm = createLlm({
    baseUrl: config.VULTR_INFERENCE_BASE_URL,
    apiKey: config.VULTR_INFERENCE_API_KEY,
    model: config.PLANNER_MODEL,
  });

  // Screenshot verifier: same endpoint and key, the multimodal model. Optional.
  const vision = config.VISION_MODEL
    ? createLlm({ baseUrl: config.VULTR_INFERENCE_BASE_URL, apiKey: config.VULTR_INFERENCE_API_KEY, model: config.VISION_MODEL })
    : undefined;

  const stop = await runLoop({
    sql,
    dockerHost: config.SANDBOX_DOCKER_HOST,
    proxyUrl: config.SANDBOX_PROXY_URL,
    githubToken: config.GITHUB_TOKEN,
    llm,
    osv: createOsv(),
    vision,
  });

  const shutdown = async (sig: string) => {
    console.log(`[worker] ${sig}, shutting down`);
    await stop();
    await sql.end({ timeout: 5 });
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

async function sweepStaleContainers(dockerHost: string): Promise<void> {
  try {
    const docker = cliDocker(dockerHost);
    const ps = await docker(["ps", "-aq", "--filter", `label=${AUDIT_LABEL}`], { timeoutMs: 30_000 });
    const ids = ps.stdout.split("\n").map((s) => s.trim()).filter(Boolean);
    if (ids.length) {
      await docker(["rm", "-f", ...ids], { timeoutMs: 60_000 });
      console.log(`[worker] removed ${ids.length} stale sandbox container(s)`);
    }
  } catch (e) {
    // VM 2 unreachable at startup: the janitor timer there is the backstop.
    console.error("[worker] stale container sweep failed:", e instanceof Error ? e.message : e);
  }
}

main().catch((err) => {
  console.error("[worker] fatal:", err instanceof Error ? err.message : err);
  process.exit(1);
});
