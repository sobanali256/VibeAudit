import { chmod, mkdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { ProxyState } from "@vibeaudit/shared";

/**
 * The worker and the egress proxy both run on VM 1; the worker writes the proxy's state file
 * here (atomic tmp+rename, group-readable by `vibeaudit`). The proxy re-reads it on every
 * change. Writing an invalid state would make the proxy fail closed (block everything), so we
 * validate with the shared ProxyState schema — the same rules the proxy enforces — first.
 */
const STATE_PATH = process.env.VIBEAUDIT_PROXY_STATE ?? "/var/lib/vibeaudit/proxy/state.json";

export async function writeProxyState(state: ProxyState, path = STATE_PATH): Promise<void> {
  const parsed = ProxyState.parse(state); // throws before the proxy ever sees a bad file
  const dir = dirname(path);
  const tmp = join(dir, `.state.${process.pid}.${Date.now()}.tmp`);
  await mkdir(dir, { recursive: true });
  await writeFile(tmp, JSON.stringify(parsed), { mode: 0o640 });
  await chmod(tmp, 0o640);
  await rename(tmp, path); // atomic within the same directory
}

/** Remove the state file: the proxy then blocks all egress (no active audit). */
export async function clearProxyState(path = STATE_PATH): Promise<void> {
  await rm(path, { force: true });
}
