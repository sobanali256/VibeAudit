import type { Finding, Report } from "@vibeaudit/shared";
import { describe, expect, it } from "vitest";
import { consoleLines } from "./console-lines";

const at = "2026-11-06T10:00:00.000Z";
const base: Report = { auditId: "a", source: { kind: "github", owner: "o", repo: "r" } as never, status: "completed", score: 0, mode: "runtime", findings: [], containment: [], startedAt: at, finishedAt: at };
const http = (o: Partial<Extract<Finding["evidence"][number], { kind: "http" }>> = {}) => ({ kind: "http" as const, method: "GET", url: "/api/users", status: 200, ...o });
const finding = (o: Partial<Finding>): Finding => ({ id: "f-users", severity: "critical", category: "missing_auth", title: "User records exposed", description: "", confirmed: true, evidence: [http()], source: "probe", ...o });
const text = (r: Report) => consoleLines(r).map((l) => `${l.kind}|${l.text}`);

describe("consoleLines", () => {
  it("is empty when there's nothing proven and nothing contained", () => {
    expect(consoleLines(base)).toEqual([]);
    expect(consoleLines({ ...base, findings: [finding({ confirmed: false })] })).toEqual([]);
    expect(consoleLines({ ...base, findings: [finding({ source: "llm_review" })] })).toEqual([]);
  });

  it("rebuilds each proving request with what was sent and what came back", () => {
    const forged = finding({
      id: "f-admin-header",
      title: "Admin action authorized by a client-supplied header",
      evidence: [http({ method: "POST", url: "/api/admin/delete-user", bodyExcerpt: '{"ok":true}', request: { headers: ["x-user-role: admin"], body: '{"id":3}' } })],
    });
    expect(text({ ...base, findings: [forged] })).toEqual([
      "comment|# probe: VibeAudit attacks the running app from inside the audit network (app = the sandboxed container)",
      `cmd|curl -si -X POST -H 'x-user-role: admin' -d '{"id":3}' http://app/api/admin/delete-user`,
      "out|HTTP/1.1 200",
      'out|{"ok":true}',
      "proven|✓ proven: Admin action authorized by a client-supplied header",
      "dim|",
      "comment|# 1 attack proven. Containers, network and workspace destroyed.",
    ]);
  });

  it("quotes request values for the shell and cuts long bodies", () => {
    const f = finding({ evidence: [http({ request: { body: "it's" }, bodyExcerpt: "x".repeat(400) })] });
    const lines = text({ ...base, findings: [f] });
    expect(lines[1]).toBe("cmd|curl -si -d 'it'\\''s' http://app/api/users");
    expect(lines.find((l) => l.startsWith("out|xxx"))!.length).toBeLessThan(200);
  });

  it("labels the browser pass as Chromium, not curl, and shows the vision verdict", () => {
    const f = finding({ id: "f-open-page-1", source: "vision", title: "Admin page open", evidence: [{ kind: "screenshot", path: "page-2.jpg", verdict: "Admin table visible" }, http({ url: "/admin" })] });
    const lines = text({ ...base, findings: [f] });
    expect(lines[1]).toBe("cmd|chromium --headless http://app/admin   # no cookies, no login");
    expect(lines).toContain("out|Admin table visible");
  });

  it("lists install-time attempts with the control that stopped each, before the probes", () => {
    const r: Report = {
      ...base,
      containment: [
        { source: "proxy", at, stage: "install", verdict: "allowed", host: "registry.npmjs.org" },
        { source: "firewall", at, stage: "install", direction: "egress", proto: "tcp", dst: "169.254.169.254", dport: 80 },
        { source: "proxy", at, stage: "run", verdict: "blocked", host: "api.openai.com:443", reason: "host not allowed in stage run" },
      ],
      findings: [finding({})],
    };
    const lines = text(r);
    expect(lines[0]).toBe("comment|# install: the install scripts (the repo's and its dependencies') run inside the sandbox");
    expect(lines[1]).toMatch(/^cmd\|Reach the cloud metadata service/);
    expect(lines[2]).toBe("blocked|✗ stopped by VM 2 firewall: egress lock");
    expect(lines.filter((l) => l.startsWith("cmd|")).length).toBe(2); // the allowed and the run-stage rows aren't attempts
    expect(lines.at(-1)).toBe("comment|# 1 attack proven, 1 attempt by the code stopped by the sandbox. Containers, network and workspace destroyed.");
  });
});

describe("consoleLines (review fixes)", () => {
  it("adds a header per stage, includes run-time exfil, counts everything and strips bidi controls", () => {
    const r: Report = {
      ...base,
      containment: [
        { source: "firewall", at, stage: "install", direction: "egress", proto: "tcp", dst: "192.0.2.1", dport: 443 },
        { source: "proxy", at, stage: "build", verdict: "blocked", host: "github.com", reason: "host not allowed in stage build", repeat: 3 },
        { source: "proxy", at, stage: "run", verdict: "exfil", host: "evil‮.example", path: "/x" },
      ],
    };
    const lines = text(r);
    expect(lines.filter((l) => l.startsWith("comment|# install") || l.startsWith("comment|# build") || l.startsWith("comment|# run"))).toHaveLength(3);
    expect(lines.join("\n")).not.toContain("‮");
    expect(lines.at(-1)).toBe("comment|# 5 attempts by the code stopped by the sandbox. Containers, network and workspace destroyed.");
  });
});
