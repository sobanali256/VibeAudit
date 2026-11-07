// Helpers shared by the Markdown and PDF exports. Pure (runs in the browser for "Copy Markdown"
// and under vitest): relative imports only, no server-only.
import type { Evidence, Finding, Report, SandboxControls } from "@vibeaudit/shared";
import { ARTIFACT_NAME_RE, isDep, isHostile, maskCanaries, SEV_ORDER, sortFindings } from "../report-model";

/** Same as AUDIT_ID_RE in @vibeaudit/shared (copied: importing values from there pulls zod into the client bundle). */
const AUDIT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

/** Hard caps so a hostile or huge report can't produce an unbounded file. */
export const EXPORT_LIMITS = {
  findings: 500,
  evidencePerFinding: 10,
  containmentRows: 300,
  allowedRows: 100,
  pages: 50,
  images: 16,
  imageBytes: 2 * 1024 * 1024,
  /** Stop adding findings once the text output passes this many characters. */
  budgetChars: 1_000_000,
  text: { snippet: 4000, body: 2000, short: 1000, title: 300 },
} as const;

/**
 * Untrusted text -> safe plain text: canaries masked, newlines normalised, control characters and
 * lone surrogates dropped, length capped. Everything from the report goes through this first.
 */
export function clean(s: string | undefined | null, max: number = EXPORT_LIMITS.text.short): string {
  if (!s) return "";
  let t = maskCanaries(String(s)).replace(/\r\n?/g, "\n");
  // C0/C1 controls (keep \n and \t), lone surrogates, bidi overrides (they reorder text visually).
  t = t.replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F‪-‮⁦-⁩]/g, "");
  t = t.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "�");
  if (t.length > max) t = `${t.slice(0, max)}… [truncated]`;
  return t;
}

export function sourceLabel(r: Report): string {
  if (r.source.kind === "github") return `${r.source.owner}/${r.source.repo}${r.source.ref ? ` (${r.source.ref})` : ""}`;
  return r.source.filename;
}

export function modeLabel(r: Report): string {
  if (r.status === "failed") return "Partial results (the audit stopped early)";
  return r.mode === "runtime" ? "Runtime audit" : "Static-only audit";
}

export function modeSentence(r: Report): string {
  if (r.status === "failed") return "The audit stopped early. What was found before it stopped, and everything the sandbox tried, is below.";
  if (r.mode === "static_only" && r.staticOnlyReason) return `The app wasn't run: ${r.staticOnlyReason}. Findings come from the code alone.`;
  if (r.mode === "static_only") return "The app wasn't run. Findings come from the code alone.";
  return "The app was installed, built and run in the sandbox, then probed over the network.";
}

/** ISO time as "2026-11-06 14:00:03 UTC" (the files are read anywhere: no local time zones). */
export function utc(iso: string): string {
  const d = new Date(iso);
  // Never echo the raw value: it comes from VM 2 and is not guaranteed to be a date.
  return Number.isNaN(d.getTime()) ? "unknown time" : `${d.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

/** Download filename: [A-Za-z0-9._-] only, length-capped, falls back to the audit id. */
export function exportFilename(r: Report, ext: "md" | "pdf"): string {
  const id = AUDIT_ID_RE.test(r.auditId) ? r.auditId : "report";
  const base = r.source.kind === "github" ? `${r.source.owner}-${r.source.repo}` : r.source.filename.replace(/\.zip$/i, "");
  const slug = base.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 60);
  return slug ? `vibeaudit-${slug}-${id}.${ext}` : `vibeaudit-${id}.${ext}`;
}

export const reportUrl = (origin: string, auditId: string) => `${origin}/audit/${encodeURIComponent(auditId)}`;
export function artifactLink(origin: string, auditId: string, name: string): string | null {
  return ARTIFACT_NAME_RE.test(name) ? `${origin}/api/audits/${encodeURIComponent(auditId)}/artifacts/${name}` : null;
}

/** The report split the way the web view splits it. */
export function partition(r: Report) {
  const all = sortFindings(r.findings);
  const app = all.filter((f) => !isDep(f));
  const deps = all.filter(isDep);
  return {
    app,
    deps,
    hostile: all.filter(isHostile),
    counts: SEV_ORDER.map((s) => [s, all.filter((f) => f.severity === s).length] as const).filter(([, n]) => n),
  };
}

/** The isolation receipt as [ok, label, value] rows (same checks as the web's ControlsReceipt). */
export function receiptRows(c: SandboxControls): [boolean, string, string][] {
  const gb = (b: number) => `${(b / 1024 ** 3).toFixed(b % 1024 ** 3 ? 1 : 0)} GB`;
  const rootUser = /^(root|0)(:|$)/.test(c.user);
  return [
    [c.runtime === "runsc", "gVisor user-space kernel", `runtime ${c.runtime}`],
    [!rootUser, "Non-root user", `user ${c.user}`],
    [
      !c.privileged && c.capDrop.includes("ALL") && c.capAdd.length === 0,
      "No Linux capabilities",
      c.privileged ? "privileged" : `drop ${c.capDrop.join(",") || "none"}${c.capAdd.length ? `, add ${c.capAdd.join(",")}` : ""}`,
    ],
    [c.noNewPrivileges, "No privilege escalation", c.noNewPrivileges ? "no-new-privileges" : "not set"],
    [c.pidsLimit !== null, "Process cap", c.pidsLimit !== null ? `${c.pidsLimit} pids` : "none"],
    [c.memoryBytes > 0, "Memory cap", c.memoryBytes ? gb(c.memoryBytes) : "none"],
    [c.cpus > 0, "CPU cap", c.cpus ? `${c.cpus} CPUs` : "none"],
    [c.egressProxy, "All web traffic via the egress proxy", `network ${c.network}`],
    [
      !c.mounts.some((m) => /docker\.sock/.test(m.destination)),
      "No Docker socket mounted",
      c.mounts.map((m) => `${m.destination} (${m.rw ? "rw" : "ro"})`).join(", ") || "no mounts",
    ],
  ];
}

export function plantedText(c: SandboxControls): string {
  const n = c.planted;
  return `${n.canaries} canary secret${n.canaries === 1 ? "" : "s"}${n.placeholders ? ` and ${n.placeholders} test-key placeholder${n.placeholders === 1 ? "" : "s"} (swapped for the real key by the proxy, outside the sandbox)` : ""}. By design, no real secret is ever put in a sandbox.`;
}

export const evidenceShown = (f: Finding): Evidence[] => f.evidence.slice(0, EXPORT_LIMITS.evidencePerFinding);

/** Screenshots the PDF embeds: finding evidence first, then visited pages; deduped and capped. */
export function screenshotNames(r: Report): string[] {
  const out: string[] = [];
  const add = (n: string | undefined) => {
    if (n && ARTIFACT_NAME_RE.test(n) && !out.includes(n) && out.length < EXPORT_LIMITS.images) out.push(n);
  };
  const { app, deps } = partition(r);
  for (const f of [...app, ...deps].slice(0, EXPORT_LIMITS.findings))
    for (const e of evidenceShown(f)) if (e.kind === "screenshot") add(e.path);
  for (const p of (r.pages ?? []).slice(0, EXPORT_LIMITS.pages)) add(p.screenshot);
  return out;
}

/** The vision model's verdict, labelled unless it already says what it is. */
export const verdictText = (v: string) => (/vision/i.test(v) ? v : `Vision check: ${v}`);
