import { z } from "zod";

/** Pipeline stages, in order. The proxy allowlist is keyed on these too. */
export const AUDIT_STAGES = [
  "intake",
  "plan",
  "approve",
  "static",
  "install",
  "build",
  "run",
  "dynamic",
  "verify",
  "report",
] as const;
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
