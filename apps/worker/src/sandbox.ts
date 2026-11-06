import { execFile } from "node:child_process";
import type { Readable } from "node:stream";
import {
  AUDIT_ID_RE,
  AUDIT_LABEL,
  type ContainerRole,
  WORKSPACE_MOUNT,
  containerArgs,
} from "@vibeaudit/shared";

/**
 * Thin, injection-safe wrapper around the Docker CLI pointed at VM 2 (the sandbox host) over
 * SSH. The worker holds only `docker system dial-stdio` access to VM 2, so EVERYTHING here is
 * a Docker API call: no host commands run on VM 2. Repo code only ever runs via `run()` under
 * runsc with the flags from containerArgs().
 *
 * One Sandbox instance == one audit. setup() then run()s then teardown(), which the pipeline
 * calls in a finally so containers/network/workspace never outlive the audit.
 */

const SETUP_IMAGE = "busybox:1.37";
const WS_HOST_ROOT = "/srv/vibeaudit/ws"; // the size-capped fs created by infra/sbx/setup.sh
const KERN_LOG = "/var/log/kern.log"; // rsyslog on VM 2; holds the VIBEAUDIT-DROP lines
const MAX_OUTPUT = 256 * 1024; // per-exec stdout/stderr cap (logs are evidence, not bulk data)
/** Hard ceiling for a run that asks for more (the browser pass returns screenshots). */
const MAX_OUTPUT_CEILING = 8 * 1024 * 1024;

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Output passed the cap and the CLI was killed (the container may still be running). */
  truncated?: boolean;
}

/** A docker command runner. Default shells out to the real CLI; tests inject a fake. */
export type DockerExec = (args: string[], opts?: { input?: Readable; timeoutMs?: number; maxOutput?: number }) => Promise<ExecResult>;

export function cliDocker(dockerHost: string): DockerExec {
  const base = ["-H", dockerHost];
  return (args, opts = {}) =>
    new Promise((resolve, reject) => {
      const child = execFile(
        "docker",
        [...base, ...args],
        { maxBuffer: Math.min(opts.maxOutput ?? MAX_OUTPUT, MAX_OUTPUT_CEILING), timeout: opts.timeoutMs ?? 0, killSignal: "SIGKILL" },
        (err, stdout, stderr) => {
          const timedOut = !!(err && (err as NodeJS.ErrnoException & { killed?: boolean }).killed && opts.timeoutMs);
          if (err && (err as NodeJS.ErrnoException).code === "ENOENT") return reject(err); // docker not installed
          resolve({
            code: typeof (err as { code?: number })?.code === "number" ? (err as { code: number }).code : err ? 1 : 0,
            stdout: stdout.toString(),
            stderr: stderr.toString(),
            timedOut,
            truncated: (err as NodeJS.ErrnoException | null)?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
          });
        },
      );
      if (opts.input) {
        opts.input.pipe(child.stdin!);
        opts.input.on("error", () => child.kill("SIGKILL"));
      }
    });
}

export interface RunSpec {
  role: ContainerRole;
  image: string;
  /** argv passed to the container (no shell unless you invoke one explicitly). */
  cmd: string[];
  env?: Record<string, string>;
  timeoutMs: number;
  /** name->ip pins (e.g. the app container's IP for the browser container). */
  hosts?: Record<string, string>;
  /** stable container name (so we can look up its IP); defaults to role-based. */
  name?: string;
  /** stream piped to the container's stdin (e.g. the repo tarball into `tar -x`). */
  input?: Readable;
  /** stdout/stderr cap for this run (default 256 KB, ceiling 8 MB). */
  maxOutput?: number;
  /** read-only stages (install/build) run GET/HEAD-only; this just tags the proxy stage. */
  /** The build step: the larger build memory cap (app role only). */
  build?: boolean;
}

export class Sandbox {
  readonly network: string;
  readonly workspaceHostPath: string;
  /** Host bridge interface of the audit network (iptables logs drops by it). Set by setup(). */
  bridge: string | null = null;
  private tornDown = false;
  private aborting: Promise<void> | undefined;

  constructor(
    readonly auditId: string,
    private readonly proxyUrl: string,
    private readonly docker: DockerExec,
  ) {
    if (!AUDIT_ID_RE.test(auditId)) throw new Error("invalid audit id");
    this.network = `va-${auditId}`;
    this.workspaceHostPath = `${WS_HOST_ROOT}/${auditId}`;
  }

  /** Create the per-audit network and workspace subdir (owned by the in-container user). */
  async setup(): Promise<void> {
    this.live();
    // NOT --internal: the container must still reach the VM 1 proxy (off-bridge). The
    // DOCKER-USER egress lock is the control — it allows only tcp to the proxy and drops
    // the rest. An internal network would block the proxy too and break all egress.
    const net = await this.docker(["network", "create", "--label", `${AUDIT_LABEL}=${this.auditId}`, this.network]);
    if (net.code !== 0 && !/already exists/.test(net.stderr)) {
      throw new SandboxError(`network create failed: ${net.stderr.trim()}`);
    }
    let netId = net.code === 0 ? net.stdout.trim() : "";
    if (!/^[0-9a-f]{12,64}$/.test(netId)) {
      const ins = await this.docker(["network", "inspect", "-f", "{{.Id}}", this.network]);
      netId = ins.stdout.trim();
    }
    // Docker names a user bridge br-<first 12 of the network id> unless overridden.
    this.bridge = /^[0-9a-f]{12,64}$/.test(netId) ? `br-${netId.slice(0, 12)}` : null;
    // Run as the workspace owner (1000). Root would need CAP_DAC_OVERRIDE, which we drop.
    const mk = await this.docker([
      "run", "--rm", "--runtime=runsc", "--network", "none", "--cap-drop", "ALL",
      "--label", `${AUDIT_LABEL}=${this.auditId}`,
      "-v", `${WS_HOST_ROOT}:/ws`, "--user", "1000:1000", SETUP_IMAGE,
      "sh", "-c",
      `mkdir -p /ws/${this.auditId}/app /ws/${this.auditId}/home /ws/${this.auditId}/.cache`,
    ], { timeoutMs: 30_000 });
    if (mk.code !== 0) throw new SandboxError(`workspace create failed: ${mk.stderr.trim()}`);
  }

  async run(spec: RunSpec): Promise<ExecResult> {
    this.live();
    const name = spec.name ?? `va-${this.auditId}-${spec.role}`;
    const args = [
      "run", "--rm", spec.input ? "-i" : "--init",
      ...containerArgs({
        auditId: this.auditId,
        role: spec.role,
        network: this.network,
        proxyUrl: this.proxyUrl,
        workspaceHostPath: spec.role === "app" ? this.workspaceHostPath : undefined,
        hosts: spec.hosts,
        name,
        build: spec.build,
      }),
    ];
    for (const [k, v] of Object.entries(spec.env ?? {})) args.push(`--env=${k}=${v}`);
    args.push(spec.image, ...spec.cmd);
    const r = await this.docker(args, { input: spec.input, timeoutMs: spec.timeoutMs, maxOutput: spec.maxOutput });
    // Killing the CLI (timeout, output cap) doesn't stop the container: `--rm` only fires on
    // exit. Remove it now so it can't keep burning CPU or block a reuse of its name.
    if (r.timedOut || r.truncated) await this.docker(["rm", "-f", name], { timeoutMs: 30_000 }).catch(() => {});
    return r;
  }

  /** Start a long-running container (the app server) detached. Returns its name. */
  async start(spec: Omit<RunSpec, "input" | "timeoutMs">): Promise<string> {
    this.live();
    const name = spec.name ?? `va-${this.auditId}-${spec.role}`;
    const args = [
      "run", "-d", "--init",
      ...containerArgs({
        auditId: this.auditId,
        role: spec.role,
        network: this.network,
        proxyUrl: this.proxyUrl,
        workspaceHostPath: spec.role === "app" ? this.workspaceHostPath : undefined,
        hosts: spec.hosts,
        name,
      }),
    ];
    for (const [k, v] of Object.entries(spec.env ?? {})) args.push(`--env=${k}=${v}`);
    args.push(spec.image, ...spec.cmd);
    const r = await this.docker(args, { timeoutMs: 60_000 });
    if (r.code !== 0) throw new SandboxError(`start failed: ${r.stderr.trim()}`);
    return name;
  }

  async logs(name: string, tail = 200): Promise<string> {
    const r = await this.docker(["logs", "--tail", String(tail), name]);
    return (r.stdout + r.stderr).slice(-MAX_OUTPUT);
  }

  /** Whether a container is still running (false once it has exited, or if it's gone). */
  async isRunning(name: string): Promise<boolean> {
    const r = await this.docker(["inspect", "-f", "{{.State.Running}}", name]);
    return r.code === 0 && r.stdout.trim() === "true";
  }

  /** The container's IPv4 on the audit network (to pin as a host for the browser container). */
  async ipOf(name: string): Promise<string | null> {
    // `index` (not dotted access): the network name has hyphens, which a Go template
    // field selector can't parse.
    const r = await this.docker([
      "inspect", "-f", `{{(index .NetworkSettings.Networks "${this.network}").IPAddress}}`, name,
    ]);
    const ip = r.stdout.trim();
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) ? ip : null;
  }

  /**
   * What isolation a running container actually got, straight from dockerd. Returns the raw
   * `docker inspect` JSON object (parse it with parseInspectControls) or null.
   */
  async inspect(name: string): Promise<unknown> {
    const r = await this.docker(["inspect", "--type", "container", name], { timeoutMs: 15_000 });
    if (r.code !== 0) return null;
    try {
      const arr: unknown = JSON.parse(r.stdout);
      return Array.isArray(arr) ? (arr[0] ?? null) : null;
    } catch {
      return null;
    }
  }

  /** Refuse to start repo-facing containers once the audit was stopped or torn down. */
  private live(): void {
    if (this.aborting || this.tornDown) throw new SandboxError("the audit was stopped");
  }

  /**
   * Stop the audit's containers now (whole-audit timeout). Every later setup/run/start throws,
   * and killing the containers makes any in-flight `docker run` return at once. Two sweeps,
   * because a run already past live() may create its container just after the first `ps`.
   * The network and workspace stay until teardown(). Idempotent; never throws.
   */
  abort(): Promise<void> {
    this.aborting ??= (async () => {
      for (const pause of [0, 2000]) {
        if (pause) await new Promise((r) => setTimeout(r, pause));
        try {
          const ids = await this.docker(["ps", "-aq", "--filter", `label=${AUDIT_LABEL}=${this.auditId}`], { timeoutMs: 30_000 });
          const list = ids.stdout.split("\n").map((s) => s.trim()).filter(Boolean);
          if (list.length) await this.docker(["rm", "-f", ...list], { timeoutMs: 60_000 });
        } catch {
          // best effort: teardown and the VM 2 janitor are the backstops
        }
      }
    })();
    return this.aborting;
  }

  /**
   * iptables drop lines for this audit's bridge from VM 2's kernel log. Read by a throwaway
   * container (ours, not repo code) with only that file mounted read-only, since the worker
   * reaches VM 2 through the Docker API alone. Group adm (4) can read kern.log; no caps.
   */
  async firewallLog(maxLines = 1000): Promise<string> {
    if (!this.bridge) return "";
    const r = await this.docker([
      "run", "--rm", "--name", `va-${this.auditId}-fwlog`, "--label", `${AUDIT_LABEL}=${this.auditId}`,
      "--runtime=runsc", "--network", "none", "--cap-drop", "ALL", "--read-only",
      "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "128m",
      "--user", "0:4", "-v", `${KERN_LOG}:/k.log:ro`, SETUP_IMAGE,
      // The bridge name is [0-9a-f-] only (checked in setup), safe to interpolate.
      "sh", "-c", `grep -F "IN=${this.bridge} " /k.log | tail -n ${Math.trunc(maxLines)}`,
    ], { timeoutMs: 15_000 });
    return r.code === 0 || r.code === 1 ? r.stdout : "";
  }

  async teardown(): Promise<void> {
    if (this.tornDown) return;
    this.tornDown = true;
    try {
      // Bounded: a hung Docker call here would hold the single audit slot.
      const ids = await this.docker(["ps", "-aq", "--filter", `label=${AUDIT_LABEL}=${this.auditId}`], { timeoutMs: 30_000 });
      const list = ids.stdout.split("\n").map((s) => s.trim()).filter(Boolean);
      if (list.length) await this.docker(["rm", "-f", ...list], { timeoutMs: 60_000 });
      const net = await this.docker(["network", "rm", this.network], { timeoutMs: 30_000 });
      // A container created after the `ps` (a slow run that was already starting when the
      // audit was stopped) keeps the network busy: sweep once more and retry.
      if (net.code !== 0 && /active endpoints|in use/i.test(net.stderr)) {
        const late = await this.docker(["ps", "-aq", "--filter", `label=${AUDIT_LABEL}=${this.auditId}`], { timeoutMs: 30_000 });
        const more = late.stdout.split("\n").map((s) => s.trim()).filter(Boolean);
        if (more.length) await this.docker(["rm", "-f", ...more], { timeoutMs: 60_000 });
        await this.docker(["network", "rm", this.network], { timeoutMs: 30_000 });
      }
      await this.docker([
        "run", "--rm", "--runtime=runsc", "--network", "none", "--cap-drop", "ALL",
        "--label", `${AUDIT_LABEL}=${this.auditId}`,
        "-v", `${WS_HOST_ROOT}:/ws`, "--user", "1000:1000", SETUP_IMAGE,
        "rm", "-rf", `/ws/${this.auditId}`,
      ], { timeoutMs: 30_000 });
    } catch {
      // Teardown is best-effort; the janitor is the backstop.
    }
  }
}

export class SandboxError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SandboxError";
  }
}

export { WORKSPACE_MOUNT };
