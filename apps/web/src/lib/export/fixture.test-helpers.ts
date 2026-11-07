import type { Finding, Report } from "@vibeaudit/shared";

export function finding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f-1",
    severity: "high",
    category: "missing_auth",
    title: "Admin console open",
    description: "Anyone can open /admin.",
    confirmed: true,
    evidence: [{ kind: "code", file: "server.js", line: 3, snippet: "app.get('/admin')" }],
    source: "probe",
    ...over,
  };
}

export function report(over: Partial<Report> = {}): Report {
  return {
    auditId: "abc123xyz",
    source: { kind: "github", owner: "acme", repo: "shop" },
    status: "completed",
    score: 42,
    mode: "runtime",
    findings: [finding()],
    containment: [],
    startedAt: "2026-11-06T10:00:00.000Z",
    finishedAt: "2026-11-06T10:05:00.000Z",
    ...over,
  };
}
