// Pure report helpers shared by the web report (client) and the Markdown/PDF exports (server).
// No React, no server-only imports, no `@/` paths (the root vitest config has no alias).
import type { ContainmentEntry, Finding, Severity } from "@vibeaudit/shared";

export const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const CATEGORY: Record<Finding["category"], string> = {
  secret_exposure: "Secret exposure",
  missing_auth: "Missing auth",
  open_data: "Open data",
  unsafe_defaults: "Unsafe defaults",
  fragile_setup: "Fragile setup",
  vulnerable_dependency: "Vulnerable dependency",
  supply_chain: "Supply chain",
};

export const LH_LABEL: Record<string, string> = {
  performance: "Performance",
  accessibility: "Accessibility",
  bestPractices: "Best practices",
  seo: "SEO",
};

/** Artifact names the worker writes (browser screenshots and replay frames). */
export const ARTIFACT_NAME_RE = /^[a-z0-9-]{1,40}\.jpg$/;

/** Checks that prove a finding by running the app, as opposed to confirming it from the code. */
const RUNTIME_SOURCES = new Set<Finding["source"]>(["probe", "proxy", "vision"]);
export type Proof = "runtime" | "code" | "suspicion";
export function proofOf(f: Finding): Proof {
  // A planted marker found in the bundle the sandbox built is proof too, though its source is the scanner.
  if (f.confirmed && (RUNTIME_SOURCES.has(f.source) || f.evidence.some((e) => e.kind === "bundle"))) return "runtime";
  return f.confirmed ? "code" : "suspicion";
}
export const PROOF_LABEL: Record<Proof, string> = { runtime: "Proven at runtime", code: "Confirmed in the code", suspicion: "Static suspicion" };

export const isDep = (f: Finding) => f.source === "dep_audit" && f.category === "vulnerable_dependency";
export const isAttempt = (e: ContainmentEntry) => !(e.source === "proxy" && e.verdict === "allowed");
/** Supply-chain findings that look hostile (the red banner). */
export const isHostile = (f: Finding) => f.category === "supply_chain" && (f.severity === "critical" || f.severity === "high");

/** Most severe first, proven before unproven. */
export const sortFindings = (findings: Finding[]) =>
  [...findings].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || Number(b.confirmed) - Number(a.confirmed));

/** Planted canaries are fakes, but a report never prints one whole. */
export const maskCanaries = (s: string) => s.replace(/AKIAVIBE[0-9A-F]{4,}/gi, "AKIAVIBE…");
