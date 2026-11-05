import { describe, it, expect } from "vitest";
import type { Finding } from "@vibeaudit/shared";
import { _probeForTest as probe } from "./pipeline";
import { isReservedEnv } from "./pipeline";
import type { Sandbox, ExecResult, RunSpec } from "./sandbox";

// A curl stdout line as our probe expects it: response headers, a blank line, the body, then
// the "-w" sentinel and numeric status appended by curl.
function curl(status: number, headers: string[], body: string): string {
  return `HTTP/1.1 ${status}\r\n${headers.join("\r\n")}\r\n\r\n${body}\n__VA_STATUS__:${status}`;
}

// Route a canned response by the request path (last argv) and method (-X ...).
function fakeSandbox(routes: (path: string, method: string) => ExecResult | undefined): Sandbox {
  return {
    auditId: "testaud",
    async run(spec: RunSpec): Promise<ExecResult> {
      const cmd = spec.cmd;
      const path = new URL(cmd[cmd.length - 1]!).pathname;
      const xi = cmd.indexOf("-X");
      const method = xi >= 0 ? cmd[xi + 1]! : "GET";
      return routes(path, method) ?? { code: 0, stdout: curl(404, [], "not found"), stderr: "", timedOut: false };
    },
  } as unknown as Sandbox;
}

// Minimal `sql` that satisfies addEvent: callable as a tag returning [{id}], plus .json().
const fakeSql = Object.assign(async () => [{ id: "ev" }], { json: (v: unknown) => v }) as never;

async function runProbe(routes: (path: string, method: string) => ExecResult | undefined): Promise<Finding[]> {
  const findings: Finding[] = [];
  await probe(fakeSandbox(routes), "testaud", "10.0.0.2", 3000, findings, fakeSql);
  return findings;
}

const ok = (status: number, headers: string[], body: string): ExecResult => ({ code: 0, stdout: curl(status, headers, body), stderr: "", timedOut: false });

describe("probe", () => {
  it("surfaces every planted flaw of the vulnerable demo", async () => {
    const findings = await runProbe((path, method) => {
      if (path === "/api/users") return ok(200, ["Access-Control-Allow-Origin: *", "Content-Type: application/json"], '[{"id":1,"email":"a@example.com","passwordHash":"5f4dcc3b"}]');
      if (path === "/api/debug") return ok(200, [], '{"env":{"PATH":"/usr/bin"},"cwd":"/srv/app"}');
      if (path === "/api/notes/1") return ok(200, [], '{"id":1,"ownerId":1,"text":"alice secret"}');
      if (path === "/api/notes/2") return ok(200, [], '{"id":2,"ownerId":2,"text":"bob private"}');
      if (path === "/api/admin/delete-user" && method === "POST") return ok(200, [], '{"ok":true}');
      if (path === "/api/chat" && method === "POST") return ok(502, [], '{"error":"upstream blocked"}');
      if (path === "/api/crash") return ok(500, [], "<pre>Error: boom\n    at /srv/app/server.js:42</pre>");
      return undefined;
    });
    const ids = findings.map((f) => f.id).sort();
    expect(ids).toEqual(["f-admin-header", "f-chat", "f-cors", "f-crash", "f-debug", "f-idor", "f-users"]);
    // Spot-check a couple of severities/categories.
    expect(findings.find((f) => f.id === "f-admin-header")!.severity).toBe("critical");
    expect(findings.find((f) => f.id === "f-cors")!.category).toBe("unsafe_defaults");
    // Every finding carries http evidence from the probe.
    for (const f of findings) {
      expect(f.source).toBe("probe");
      expect(f.confirmed).toBe(true);
      expect(f.evidence.length).toBeGreaterThan(0);
    }
  });

  it("reports nothing against a clean app (all 404 / no telltale bodies)", async () => {
    const findings = await runProbe(() => undefined); // every route -> 404
    expect(findings).toEqual([]);
  });

  it("does not flag /api/chat when the endpoint is absent (404) or auth-gated (401/403)", async () => {
    const gated = await runProbe((path, method) => (path === "/api/chat" && method === "POST" ? ok(401, [], "unauthorized") : undefined));
    expect(gated.find((f) => f.id === "f-chat")).toBeUndefined();
  });

  it("does not flag CORS when the header is a specific origin", async () => {
    const findings = await runProbe((path) => (path === "/api/users" ? ok(200, ["Access-Control-Allow-Origin: https://trusted.example"], "[]") : undefined));
    expect(findings.find((f) => f.id === "f-cors")).toBeUndefined();
  });

  it("does not flag /api/chat when every path answers the same (error page on all routes, SPA fallback)", async () => {
    const broken = await runProbe(() => ok(500, [], "<pre>Error [ERR_MODULE_NOT_FOUND]: Cannot find module dist/server/server.js</pre>"));
    expect(broken.find((f) => f.id === "f-chat")).toBeUndefined();
    const spa = await runProbe(() => ok(200, ["Content-Type: text/html"], `<!doctype html><script>window.process={env:{}};var password="";</script><div id=root data-x='"text"'></div>`));
    expect(spa.find((f) => f.id === "f-chat")).toBeUndefined();
    // An SPA fallback doesn't "prove" the GET probes either (its HTML mentions process/password).
    for (const id of ["f-users", "f-debug", "f-idor"]) expect(spa.find((f) => f.id === id), id).toBeUndefined();
  });

  it("still catches real flaws behind fallbacks", async () => {
    const html = ok(200, ["Content-Type: text/html", "Access-Control-Allow-Origin: *"], '<!doctype html><p class="text-success">hi</p>');
    // Unknown POSTs 405, chat answers: flagged.
    const m405 = await runProbe((path, method) => (method === "POST" ? (path === "/api/chat" ? ok(200, [], '{"reply":"pong"}') : ok(405, [], "")) : undefined));
    expect(m405.some((f) => f.id === "f-chat")).toBe(true);
    // All-methods HTML fallback; chat swallows the upstream error into 200 JSON: flagged.
    const all = await runProbe((path) => (path === "/api/chat" ? ok(200, [], '{"error":"upstream failed"}') : html));
    expect(all.some((f) => f.id === "f-chat")).toBe(true);
    // ...but the fallback's HTML never proves the admin action or CORS.
    expect(all.find((f) => f.id === "f-admin-header")).toBeUndefined();
    expect(all.find((f) => f.id === "f-cors")).toBeUndefined();
    // GET SPA fallback, real JSON API underneath: still flagged.
    const api = await runProbe((path, method) =>
      method === "GET" && path === "/api/users" ? ok(200, [], '[{"id":1,"passwordHash":"x"}]') : method === "GET" ? html : undefined,
    );
    expect(api.some((f) => f.id === "f-users")).toBe(true);
  });

  it("does not flag /api/chat on a non-response (timeout / connection failure, http_code 000)", async () => {
    const findings = await runProbe((path, method) =>
      path === "/api/chat" && method === "POST" ? { code: 28, stdout: "\n__VA_STATUS__:000", stderr: "", timedOut: true } : undefined,
    );
    expect(findings.find((f) => f.id === "f-chat")).toBeUndefined();
  });

  it("keeps the body intact when it contains a blank line", async () => {
    const findings = await runProbe((path) =>
      path === "/api/debug" ? ok(200, [], "line one\n\nline two with env and process") : undefined,
    );
    const debug = findings.find((f) => f.id === "f-debug");
    expect(debug).toBeDefined();
    const ev = debug!.evidence[0]!;
    expect(ev.kind === "http" && ev.bodyExcerpt).toContain("line two");
  });

  it("keeps collecting after one probe throws", async () => {
    const findings = await runProbe((path) => {
      if (path === "/api/users") throw new Error("network blip");
      if (path === "/api/debug") return ok(200, [], '{"env":{}}');
      return undefined;
    });
    // users errored, but debug still surfaced.
    expect(findings.map((f) => f.id)).toContain("f-debug");
    expect(findings.find((f) => f.id === "f-users")).toBeUndefined();
  });
});

describe("isReservedEnv", () => {
  it("reserves the names the sandbox sets itself", () => {
    for (const n of ["HTTPS_PROXY", "http_proxy", "NO_PROXY", "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS", "YARN_HTTPS_PROXY", "npm_config_cafile", "SSL_CERT_FILE", "PORT", "DO_NOT_TRACK", "NEXT_TELEMETRY_DISABLED", "PNPM_STORE_DIR", "NPM_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"]) {
      expect(isReservedEnv(n), n).toBe(true);
    }
  });
  it("leaves ordinary app secrets alone", () => {
    for (const n of ["OPENAI_API_KEY", "DATABASE_URL", "STRIPE_SECRET_KEY", "PROXY_SECRET", "constructor", "toString"]) expect(isReservedEnv(n), n).toBe(false);
  });
});
