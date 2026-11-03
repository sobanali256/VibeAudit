import { AUDIT_STAGES } from "@vibeaudit/shared";
import { loadConfig } from "./config";

// Entry point for the audit worker (runs on VM 1). It consumes the job queue and
// drives the sandbox host over SSH. Job queue and pipeline stages land next.
async function main() {
  const config = loadConfig();
  console.log(
    `[worker] starting; sandbox=${config.SANDBOX_DOCKER_HOST} stages=${AUDIT_STAGES.join(" > ")}`,
  );
}

main().catch((err) => {
  console.error("[worker] fatal:", err instanceof Error ? err.message : err);
  process.exit(1);
});
