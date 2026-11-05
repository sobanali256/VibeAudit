import { z } from "zod";
import { AuditSource, AuditStatus } from "./audit";
import { Finding } from "./finding";
import { ContainmentEntry } from "./sandbox";

/** Lighthouse category scores (0-100) plus the few metrics we surface. */
export const LighthouseSection = z.object({
  url: z.string(),
  scores: z.object({
    performance: z.number().min(0).max(100),
    accessibility: z.number().min(0).max(100),
    bestPractices: z.number().min(0).max(100),
    seo: z.number().min(0).max(100),
  }),
  metrics: z
    .object({
      lcpMs: z.number().nonnegative(),
      cls: z.number().nonnegative(),
      tbtMs: z.number().nonnegative(),
    })
    .partial(),
  /** Path of the screenshot taken during the run (evidence store). */
  screenshot: z.string().optional(),
});
export type LighthouseSection = z.infer<typeof LighthouseSection>;

/** One page the browser pass visited, logged out. Title/paths come from the app: untrusted. */
export const PageVisit = z.object({
  path: z.string(),
  /** Main document HTTP status (0 = no response). */
  status: z.number().int(),
  /** Where the page ended up (a redirect to /login shows here); null if it left the app. */
  finalPath: z.string().nullable(),
  title: z.string(),
  /** Artifact name of the screenshot, served at /api/audits/<id>/artifacts/<name>. */
  screenshot: z.string().optional(),
  /** What the vision model saw, when it ran. */
  verdict: z.string().optional(),
});
export type PageVisit = z.infer<typeof PageVisit>;

export const Report = z.object({
  auditId: z.string(),
  source: AuditSource,
  status: AuditStatus,
  /** 0-100. Static-only reports are scored on static findings alone and say so. */
  score: z.number().min(0).max(100),
  mode: z.enum(["runtime", "static_only"]),
  /** Why we fell back to static-only, if we did (unsupported stack, build failed...). */
  staticOnlyReason: z.string().optional(),
  findings: z.array(Finding),
  containment: z.array(ContainmentEntry),
  /** Pages the browser pass visited (runtime audits only). */
  pages: z.array(PageVisit).optional(),
  lighthouse: LighthouseSection.optional(),
  startedAt: z.string(),
  finishedAt: z.string(),
});
export type Report = z.infer<typeof Report>;
