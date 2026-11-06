import { z } from "zod";
import { AUDIT_LABEL, AuditStage } from "./audit";
import { FAKE_HOSTS } from "./env-fakes";
import {
  AUDIT_ID_RE,
  ENV_VAR_RE,
  HEADER_NAME_RE,
  HOST_RE,
  KEY_PROVIDERS,
  KEY_STAGES,
  SECRET_VALUE_RE,
} from "./ids";

export { AUDIT_ID_RE, ENV_VAR_RE, HOST_RE, KEY_PROVIDERS, KEY_STAGES } from "./ids";

/**
 * Contract between the worker and the egress proxy on VM 1
 * (infra/cp/proxy/vibeaudit_proxy.py). Keep the two in sync; sandbox.contract.test.ts checks.
 */

/** The value a sandbox sees for a test key. The proxy swaps it for the real key on the wire. */
export function keyPlaceholder(envVar: string, auditId: string): string {
  if (!ENV_VAR_RE.test(envVar)) throw new Error(`invalid env var name: ${envVar}`);
  if (!AUDIT_ID_RE.test(auditId)) throw new Error(`invalid audit id: ${auditId}`);
  return `sk-PLACEHOLDER-${envVar}-${auditId}`;
}

/** Hosts a key for `envVar` may be sent to, or null if we don't know the provider. */
export function keyHosts(envVar: string): readonly string[] | null {
  return Object.hasOwn(KEY_PROVIDERS, envVar) ? KEY_PROVIDERS[envVar]! : null;
}

export const SecretValue = z.string().regex(SECRET_VALUE_RE, "8-512 printable ASCII chars, no spaces");

export const ProxyKeySpec = z.object({
  value: SecretValue,
  /** Exact hostnames this key may be sent to (from KEY_PROVIDERS, never from the planner). */
  hosts: z.array(z.string().regex(HOST_RE)).min(1),
  /** Request headers the placeholder may appear in (lowercase). Default on the proxy side. */
  headers: z.array(z.string().regex(HEADER_NAME_RE)).min(1).optional(),
});
export type ProxyKeySpec = z.infer<typeof ProxyKeySpec>;

/**
 * Written atomically (tmp + rename, mode 0640 group vibeaudit) to
 * /var/lib/vibeaudit/proxy/state.json and deleted when the audit ends. Absent = block all.
 * One file = one active audit; see MAX_CONCURRENT_AUDITS.
 */
export const ProxyState = z
  .object({
    auditId: z.string().regex(AUDIT_ID_RE),
    stage: AuditStage,
    keys: z.record(z.string().regex(ENV_VAR_RE), ProxyKeySpec).default({}),
    /** Fake secrets planted in the sandbox env. Seen leaving in any encoding = exfil event. */
    canaries: z.array(SecretValue).default([]),
  })
  .superRefine((s, ctx) => {
    // Keys only during stages that run the app. Never during install/build, where
    // hostile install scripts run and github.com/npm are reachable.
    if (Object.keys(s.keys).length > 0 && !(KEY_STAGES as readonly string[]).includes(s.stage)) {
      ctx.addIssue({ code: "custom", path: ["keys"], message: `no test keys in stage ${s.stage}` });
    }
  });
export type ProxyState = z.infer<typeof ProxyState>;

/** One line of /var/lib/vibeaudit/proxy/events.jsonl. host/path come from the sandbox: untrusted. */
export const ProxyEvent = z.object({
  ts: z.number(),
  auditId: z.string().nullable(),
  stage: z.string().nullable(),
  kind: z.enum(["allowed", "blocked", "exfil", "client_rejected"]),
  method: z.string().optional(),
  host: z.string().optional(),
  port: z.number().int().optional(),
  path: z.string().optional(),
  reason: z.string().optional(),
  swapped: z.array(z.string()).nullable().optional(),
  var: z.string().optional(),
  canary: z.string().optional(),
  peer: z.string().optional(),
  repeat: z.number().int().optional(),
});
export type ProxyEvent = z.infer<typeof ProxyEvent>;

/**
 * The containment log shown in the report: every time the sandbox tried something and a
 * control stopped it (or let it through, for allowed egress). `stage` is null for proxy
 * events that arrived while no audit state was active (e.g. a straggling container).
 */
export const ContainmentEntry = z.discriminatedUnion("source", [
  z.object({
    source: z.literal("proxy"),
    at: z.string(), // ISO time
    stage: AuditStage.nullable(),
    verdict: z.enum(["allowed", "blocked", "exfil"]),
    method: z.string().optional(),
    host: z.string().optional(),
    path: z.string().optional(),
    reason: z.string().optional(),
    /** Env var whose test key was swapped in, or whose placeholder was smuggled. */
    keyVar: z.string().optional(),
    repeat: z.number().int().optional(),
  }),
  z.object({
    /** VM 2 iptables (VIBEAUDIT-DROP log lines): direct connections that never reached the proxy. */
    source: z.literal("firewall"),
    at: z.string(),
    stage: AuditStage.nullable(),
    direction: z.enum(["egress", "host"]),
    proto: z.string(),
    dst: z.string(),
    dport: z.number().int().optional(),
  }),
  z.object({
    source: z.literal("limit"),
    at: z.string(),
    stage: AuditStage,
    limit: z.enum(["pids", "memory", "cpu_time", "stage_timeout", "audit_timeout", "disk"]),
    detail: z.string(),
  }),
]);
export type ContainmentEntry = z.infer<typeof ContainmentEntry>;

/** Which container a stage runs in. */
export type ContainerRole = "app" | "browser";

/**
 * Resource caps for audit containers on VM 2 (2 vCPU / 8 GB, one audit at a time).
 * - pids: under runsc the host pids cgroup also counts gVisor's sentry threads (~30 idle).
 * - memory: the rootfs overlay is memory-backed, so rootfs writes count here too. Package
 *   caches are pointed at the workspace volume to keep them out of it.
 * - cpus: < 2 so dockerd/sshd (the worker's control channel) always get CPU.
 * - buildMemoryBytes: the build step alone (nothing else runs on VM 2 then). Real Next.js builds
 *   type-check large dependency typings and need more than the app cap; the rest stays for the host.
 */
export const CONTAINER_LIMITS = {
  pids: 1024,
  cpus: { app: 1.5, browser: 1 },
  memoryBytes: { app: 3 * 1024 ** 3, browser: 2 * 1024 ** 3 },
  buildMemoryBytes: 5 * 1024 ** 3,
  shmBytes: { app: 64 * 1024 ** 2, browser: 512 * 1024 ** 2 },
  /**
   * Workspace (repo + node_modules + build output). The worker must back it with a real
   * quota on VM 2 (a loop-mounted ext4 image of this size), not tmpfs (which would be
   * sentry memory under runsc) and not a plain volume (ext4 doesn't enforce size opts).
   */
  workspaceBytes: 6 * 1024 ** 3,
} as const;

export const WORKSPACE_MOUNT = "/workspace";
export const PROXY_CA_PATH_HOST = "/opt/vibeaudit/proxy-ca-cert.pem";
export const PROXY_CA_PATH_CONTAINER = "/etc/vibeaudit/proxy-ca.pem";

export interface ContainerArgsInput {
  auditId: string;
  role: ContainerRole;
  /** Per-audit docker network name. */
  network: string;
  /** Egress proxy URL as seen from containers, e.g. http://10.1.96.4:8080. */
  proxyUrl: string;
  /** Host path of this audit's quota-backed workspace (app role only). */
  workspaceHostPath?: string;
  /** Extra name -> IP pins (Docker's embedded DNS doesn't answer under runsc). */
  hosts?: Record<string, string>;
  name?: string;
  /** The build step's larger memory cap (app role only; see CONTAINER_LIMITS.buildMemoryBytes). */
  build?: boolean;
}

/**
 * `docker run` flags for every audit container. The worker builds argv only through this,
 * so no stage can forget gVisor, caps, limits, the network, the janitor label or the proxy.
 * Env vars for the app (canaries/placeholders) are added by the caller.
 */
export function containerArgs(i: ContainerArgsInput): string[] {
  if (!AUDIT_ID_RE.test(i.auditId)) throw new Error("invalid audit id");
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$/.test(i.network)) throw new Error("invalid network name");
  if (i.build && i.role !== "app") throw new Error("only the app container builds");
  const mem = i.build ? CONTAINER_LIMITS.buildMemoryBytes : CONTAINER_LIMITS.memoryBytes[i.role];
  const args = [
    "--runtime=runsc",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--user=1000:1000",
    "--restart=no",
    `--pids-limit=${CONTAINER_LIMITS.pids}`,
    `--cpus=${CONTAINER_LIMITS.cpus[i.role]}`,
    `--memory=${mem}`,
    `--memory-swap=${mem}`,
    `--shm-size=${CONTAINER_LIMITS.shmBytes[i.role]}`,
    `--network=${i.network}`,
    `--label=${AUDIT_LABEL}=${i.auditId}`,
  ];
  // Only the app container routes egress through the proxy. The browser/probe container
  // talks to the app DIRECTLY on the audit network, so it must NOT get *_PROXY (or curl/Node
  // would send app requests to the proxy, which rejects the app's internal IP). Its external
  // egress is still blocked at the network layer by the DOCKER-USER lock.
  if (i.role === "app") {
    args.push(
      `--volume=${PROXY_CA_PATH_HOST}:${PROXY_CA_PATH_CONTAINER}:ro`,
      `--env=HTTP_PROXY=${i.proxyUrl}`,
      `--env=HTTPS_PROXY=${i.proxyUrl}`,
      `--env=http_proxy=${i.proxyUrl}`,
      `--env=https_proxy=${i.proxyUrl}`,
      "--env=NO_PROXY=localhost,127.0.0.1",
      "--env=NODE_USE_ENV_PROXY=1",
      `--env=NODE_EXTRA_CA_CERTS=${PROXY_CA_PATH_CONTAINER}`,
      `--env=npm_config_cafile=${PROXY_CA_PATH_CONTAINER}`,
      `--env=SSL_CERT_FILE=${PROXY_CA_PATH_CONTAINER}`,
      // Yarn Berry ignores HTTP(S)_PROXY. (No YARN_HTTPS_CA_FILE_PATH: Yarn 2/3 reject it as an
      // unknown setting, and Berry trusts NODE_EXTRA_CA_CERTS already.)
      `--env=YARN_HTTP_PROXY=${i.proxyUrl}`,
      `--env=YARN_HTTPS_PROXY=${i.proxyUrl}`,
    );
  }
  if (i.name) args.push(`--name=${i.name}`);
  for (const [name, ip] of Object.entries(i.hosts ?? {})) {
    if (!/^[a-z0-9-]{1,63}$/.test(name) || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) throw new Error("invalid host pin");
    args.push(`--add-host=${name}:${ip}`);
  }
  if (i.role === "app") {
    // Fake env values point at these (env-fakes.ts): pinned to loopback, a connection fails at
    // once in the container, with no DNS lookup and nothing for the firewall to log.
    for (const h of FAKE_HOSTS) args.push(`--add-host=${h}:127.0.0.1`);
    if (!i.workspaceHostPath) throw new Error("app containers need a workspace");
    args.push(
      `--volume=${i.workspaceHostPath}:${WORKSPACE_MOUNT}`,
      `--workdir=${WORKSPACE_MOUNT}/app`,
      // Keep package caches on the quota'd workspace, not the memory-backed rootfs.
      `--env=HOME=${WORKSPACE_MOUNT}/home`,
      `--env=npm_config_cache=${WORKSPACE_MOUNT}/.cache/npm`,
      `--env=PNPM_STORE_DIR=${WORKSPACE_MOUNT}/.cache/pnpm`,
      `--env=YARN_CACHE_FOLDER=${WORKSPACE_MOUNT}/.cache/yarn`,
    );
  }
  return args;
}
