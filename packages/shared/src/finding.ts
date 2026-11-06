import { z } from "zod";

export const Severity = z.enum(["critical", "high", "medium", "low", "info"]);
export type Severity = z.infer<typeof Severity>;

export const FindingCategory = z.enum([
  "secret_exposure",
  "missing_auth",
  "open_data",
  "unsafe_defaults",
  "fragile_setup",
  "vulnerable_dependency",
  /** Repo or dependency code doing something hostile at install/build time. */
  "supply_chain",
]);
export type FindingCategory = z.infer<typeof FindingCategory>;

/** Every finding must carry at least one piece of evidence. */
export const Evidence = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("code"),
    file: z.string(),
    line: z.number().int().positive().optional(),
    snippet: z.string(),
  }),
  z.object({
    kind: z.literal("http"),
    method: z.string(),
    url: z.string(),
    status: z.number().int(),
    headers: z.record(z.string(), z.string()).optional(),
    bodyExcerpt: z.string().optional(),
  }),
  z.object({
    kind: z.literal("screenshot"),
    path: z.string(),
    /** The vision model's verdict, when one ran. */
    verdict: z.string().optional(),
  }),
  z.object({
    kind: z.literal("bundle"),
    asset: z.string(),
    /** The canary string or secret pattern found in the client bundle. */
    match: z.string(),
  }),
  z.object({
    /** A connection the sandbox's egress controls stopped (from the containment log). */
    kind: z.literal("network"),
    control: z.enum(["proxy", "firewall"]),
    at: z.string(),
    stage: z.string().nullable(),
    /** e.g. "tcp 192.0.2.1:443" or "GET evil.example/x". */
    target: z.string(),
    detail: z.string().optional(),
  }),
]);
export type Evidence = z.infer<typeof Evidence>;

export const Finding = z.object({
  id: z.string(),
  severity: Severity,
  category: FindingCategory,
  title: z.string(),
  description: z.string(),
  /** true = proven at runtime / verified; false = static suspicion only. */
  confirmed: z.boolean(),
  evidence: z.array(Evidence).min(1),
  fix: z.string().optional(),
  /**
   * Other checks that independently reported the same problem and were merged into this one
   * (e.g. the LLM code review suspected what a probe then proved). Their own findings are
   * dropped so nothing is counted twice.
   */
  corroboratedBy: z
    .array(
      z.object({
        source: z.enum(["llm_review"]),
        title: z.string().max(200),
        severity: Severity,
        /** Where the review pointed (model output: a citation, not proof). */
        file: z.string().max(300).optional(),
        line: z.number().int().positive().optional(),
      }),
    )
    .max(10)
    .optional(),
  source: z.enum(["gitleaks", "secret_scan", "dep_audit", "llm_review", "probe", "vision", "proxy", "install_scan"]),
});
export type Finding = z.infer<typeof Finding>;
