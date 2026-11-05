import { z } from "zod";
import { AUDIT_ID_RE, ENV_VAR_RE, KEY_PROVIDERS, SECRET_VALUE_RE } from "./ids";

import { AUDIT_STAGES } from "./stages";

export { AUDIT_STAGES };
export const AuditStage = z.enum(AUDIT_STAGES);
export type AuditStage = z.infer<typeof AuditStage>;

export const AuditStatus = z.enum([
  "queued",
  "running",
  "awaiting_approval",
  "completed",
  "static_only",
  "failed",
  "cancelled",
]);
export type AuditStatus = z.infer<typeof AuditStatus>;

export const AuditSource = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("github"),
    owner: z.string(),
    repo: z.string(),
    ref: z.string().optional(),
    /** Path after the ref in a /tree/ or /blob/ URL; intake uses it to resolve slash-y refs. */
    subpath: z.string().optional(),
  }),
  z.object({
    kind: z.literal("zip"),
    filename: z.string(),
    sizeBytes: z.number().int().nonnegative(),
  }),
]);
export type AuditSource = z.infer<typeof AuditSource>;

/** Per-stage wall-clock caps (ms). The whole audit is capped separately. */
export const STAGE_TIMEOUTS_MS = {
  install: 4 * 60_000,
  buildPerTry: 3 * 60_000,
  run: 6 * 60_000,
} as const;
export const MAX_BUILD_TRIES = 3;
export const AUDIT_TIMEOUT_MS = 20 * 60_000;

/** Intake limits (zip-bomb / abuse protection). */
export const MAX_ARCHIVE_BYTES = 20 * 1024 * 1024;
export const MAX_UNPACKED_BYTES = 200 * 1024 * 1024;

/** GitHub tarball intake gets the same caps as zip uploads. */
export const MAX_GITHUB_TARBALL_BYTES = MAX_ARCHIVE_BYTES;
/** Entry-count cap for any archive (zip or tarball), against inode-exhaustion bombs. */
export const MAX_ARCHIVE_ENTRIES = 50_000;

/**
 * VM 2 runs one audit at a time (2 vCPU / 8 GB). Extra audits wait in the queue.
 * The egress proxy also has a single state file (one active audit): raising this needs a
 * per-audit proxy contract first.
 */
export const MAX_CONCURRENT_AUDITS = 1;
/**
 * The VM 2 janitor (infra/sbx/janitor.sh, every 5 min) force-removes any audit container older
 * than this. Networks and workspaces get JANITOR_IDLE_MAX_AGE_MS, since they legitimately live
 * through the approval wait plus the audit. Keep both in sync with the script's defaults.
 */
export const JANITOR_MAX_AGE_MS = 30 * 60_000;
export const JANITOR_IDLE_MAX_AGE_MS = 90 * 60_000;
/** Intake back-pressure: new audits are refused while this many are queued or active. */
export const MAX_OPEN_AUDITS = 10;
/** A worker lease (heartbeat) older than this means the worker crashed; the audit is failed. */
export const WORKER_LEASE_MS = 90_000;
/** A queued audit never picked up within this is cancelled, so the queue can't wedge. */
export const QUEUED_MAX_AGE_MS = 60 * 60_000;
/** Label put on every container/network/volume the worker creates, for the janitor. */
export const AUDIT_LABEL = "vibeaudit.audit";

/**
 * Human-approval step (between `plan` and the first stage that runs repo code).
 * The worker parks the audit in `awaiting_approval` with this request and waits.
 */
export const ApprovalRequest = z.object({
  auditId: z.string().regex(AUDIT_ID_RE),
  /** Changes whenever the request is regenerated; a decision must echo it. */
  requestId: z.string().min(8),
  /** What the planner intends to run, shown verbatim to the user. */
  plan: z.object({
    framework: z.enum(["nextjs", "vite", "express", "unknown"]),
    packageManager: z.enum(["npm", "pnpm", "yarn", "bun"]),
    installCommand: z.string(),
    buildCommand: z.string().nullable(),
    startCommand: z.string().nullable(),
    port: z.number().int().positive().nullable(),
  }),
  /**
   * Env vars the app reads, and what the sandbox gets for each. `placeholder` is only
   * offered for vars in KEY_PROVIDERS; their hosts come from that table, not the planner.
   */
  env: z.array(
    z
      .object({
        name: z.string().regex(ENV_VAR_RE),
        provide: z.enum(["canary", "placeholder", "empty"]),
      })
      .refine((e) => e.provide !== "placeholder" || Object.hasOwn(KEY_PROVIDERS, e.name), {
        message: "placeholder only for known key providers",
      }),
  ),
  /** Install scripts (postinstall etc.) found in the dependency tree. */
  installScripts: z.array(z.object({ pkg: z.string(), script: z.string() })),
  expiresAt: z.string().datetime({ offset: true }),
});
export type ApprovalRequest = z.infer<typeof ApprovalRequest>;

/** The user's decision. Contains NO secrets, so it can be stored and shown freely. */
export const ApprovalDecision = z.discriminatedUnion("decision", [
  z.object({
    decision: z.literal("approve"),
    auditId: z.string().regex(AUDIT_ID_RE),
    requestId: z.string().min(8),
    /** Run with install scripts disabled (`--ignore-scripts`). */
    ignoreScripts: z.boolean().default(false),
    /** Env vars the user supplied a test key for (values travel separately). */
    testKeyVars: z.array(z.string().regex(ENV_VAR_RE)).default([]),
  }),
  z.object({ decision: z.literal("static_only"), auditId: z.string().regex(AUDIT_ID_RE), requestId: z.string().min(8) }),
  z.object({ decision: z.literal("cancel"), auditId: z.string().regex(AUDIT_ID_RE), requestId: z.string().min(8) }),
]);
export type ApprovalDecision = z.infer<typeof ApprovalDecision>;

/**
 * Real test keys, submitted with an approval. Kept apart from ApprovalDecision so they
 * never land in audit rows, API responses, logs or progress events. Stored only on VM 1,
 * used only to write proxy state, deleted when the audit ends.
 */
export const ApprovalSecrets = z.object({
  testKeys: z.record(
    z.string().regex(ENV_VAR_RE).refine((v) => Object.hasOwn(KEY_PROVIDERS, v), "unknown key provider"),
    z.string().regex(SECRET_VALUE_RE, "8-512 printable ASCII chars, no spaces"),
  ),
});
export type ApprovalSecrets = z.infer<typeof ApprovalSecrets>;
