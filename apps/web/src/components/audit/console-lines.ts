import type { Report } from "@vibeaudit/shared";
import { describeAttempt } from "./attempts";

/**
 * The attack console's script: what the repo's own code tried inside the sandbox (and what
 * stopped it), then the requests VibeAudit sent to the running app (and what came back).
 * Built only from the stored report. Response bodies, hosts and paths come from the app or the
 * sandbox: they're cut short here and rendered as text only.
 */
export type LineKind = "comment" | "cmd" | "out" | "proven" | "blocked" | "dim";
export interface Line {
  kind: LineKind;
  text: string;
}

const MAX_BODY_LINES = 3;
const MAX_BODY_CHARS = 160;
const MAX_PROBES = 12;
const MAX_ATTEMPTS = 10;
/** Runtime proof only: these checks sent real requests to the running app. */
const PROBE_SOURCES = new Set(["probe", "vision"]);

const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** Bidi overrides and control characters from the app could reorder a line visually: drop them. */
const clean = (t: string) => t.replace(/[\u0000-\u0008\u000b-\u001f\u007f‪-‮⁦-⁩]/g, "");

function bodyLines(body: string): string[] {
  const flat = clean(body.replace(/\r/g, "")).slice(0, MAX_BODY_CHARS * 2);
  // JSON on one line reads badly in a terminal: break after commas between objects.
  const parts = flat.split(/\n|(?<=\},)(?=\{)/).map((l) => l.trim()).filter(Boolean);
  const out = parts.slice(0, MAX_BODY_LINES).map((l) => (l.length > MAX_BODY_CHARS ? `${l.slice(0, MAX_BODY_CHARS)}…` : l));
  if (parts.length > MAX_BODY_LINES || body.length > flat.length) out.push("…");
  return out;
}

const STAGE_NOTE: Record<string, string> = {
  install: "# install: the install scripts (the repo's and its dependencies') run inside the sandbox",
  build: "# build: the build runs inside the sandbox",
  run: "# run: the app's own code, running inside the sandbox",
  dynamic: "# run: the app's own code, running inside the sandbox",
};

export function consoleLines(report: Report): Line[] {
  const lines: Line[] = [];

  // What the code in the sandbox tried and a control stopped: everything blocked at install or
  // build, plus any secret smuggled out while the app ran. Not every block is hostile (a package
  // fetching a binary off-allowlist is blocked too), so the wording stays neutral.
  const all = report.containment.filter(
    (e) =>
      ((e.stage === "install" || e.stage === "build") && !(e.source === "proxy" && e.verdict === "allowed")) ||
      (e.source === "proxy" && e.verdict === "exfil"),
  );
  const count = all.reduce((n, e) => n + (e.source === "proxy" ? (e.repeat ?? 1) : 1), 0);
  const attempts = all.slice(0, MAX_ATTEMPTS).flatMap((e) => {
    const a = describeAttempt(e);
    return a ? [{ e, a }] : [];
  });
  let stage: string | null | undefined;
  for (const { e, a } of attempts) {
    if (e.stage !== stage) {
      stage = e.stage;
      lines.push({ kind: "comment", text: STAGE_NOTE[e.stage ?? ""] ?? "# inside the sandbox" });
    }
    lines.push({ kind: "cmd", text: clean(a.attempt) });
    lines.push({ kind: "blocked", text: `✗ stopped by ${a.control}` });
    lines.push({ kind: "dim", text: clean(a.evidence) });
  }
  if (count > attempts.length) lines.push({ kind: "dim", text: `… and ${count - attempts.length} more in the containment log below` });

  const probes = report.findings
    .filter((f) => f.confirmed && PROBE_SOURCES.has(f.source))
    .flatMap((f) => f.evidence.flatMap((e) => (e.kind === "http" ? [{ f, e }] : [])).slice(0, 1))
    .slice(0, MAX_PROBES);
  if (probes.length) {
    if (lines.length) lines.push({ kind: "dim", text: "" });
    lines.push({ kind: "comment", text: "# probe: VibeAudit attacks the running app from inside the audit network (app = the sandboxed container)" });
    for (const { f, e } of probes) {
      const url = `http://app${e.url.startsWith("/") ? e.url : `/${e.url}`}`;
      if (f.source === "vision") {
        // The browser pass, not curl: say so.
        lines.push({ kind: "cmd", text: `chromium --headless ${url}   # no cookies, no login` });
      } else {
        const parts = ["curl -si"];
        if (e.method !== "GET") parts.push(`-X ${e.method}`);
        for (const h of e.request?.headers ?? []) parts.push(`-H ${q(h)}`);
        if (e.request?.body) parts.push(`-d ${q(e.request.body)}`);
        parts.push(url);
        lines.push({ kind: "cmd", text: parts.join(" ") });
      }
      lines.push({ kind: "out", text: `HTTP/1.1 ${e.status}` });
      for (const [k, v] of Object.entries(e.headers ?? {})) lines.push({ kind: "out", text: `${k}: ${v}` });
      if (e.bodyExcerpt) for (const l of bodyLines(e.bodyExcerpt)) lines.push({ kind: "out", text: l });
      const seen = f.evidence.find((x) => x.kind === "screenshot");
      if (seen?.kind === "screenshot" && seen.verdict) for (const l of bodyLines(seen.verdict)) lines.push({ kind: "out", text: l });
      lines.push({ kind: "proven", text: `✓ proven: ${clean(f.title)}` });
    }
  }

  if (lines.length) {
    lines.push({ kind: "dim", text: "" });
    const parts = [
      probes.length ? `${probes.length} attack${probes.length === 1 ? "" : "s"} proven` : null,
      count ? `${count} attempt${count === 1 ? "" : "s"} by the code stopped by the sandbox` : null,
    ].filter(Boolean);
    lines.push({ kind: "comment", text: `# ${parts.join(", ")}. Containers, network and workspace destroyed.` });
  }
  return lines;
}
