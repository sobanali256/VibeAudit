import type { Finding } from "@vibeaudit/shared";
import { describe, expect, it } from "vitest";
import { corroborate, routeOf } from "./corroborate";

const code = (file: string, line: number, snippet = "x") => ({ kind: "code" as const, file, line, snippet });
const http = (url: string) => ({ kind: "http" as const, method: "GET", url, status: 200 });

const probe = (id: string, title: string, url: string, o: Partial<Finding> = {}): Finding => ({
  id, title, source: "probe", severity: "critical", category: "missing_auth", description: "", confirmed: true, evidence: [http(url)], ...o,
});
const review = (title: string, description: string, o: Partial<Finding> = {}): Finding => ({
  id: `llm-${title.length}`, title, description, source: "llm_review", severity: "high", category: "missing_auth", confirmed: false,
  evidence: [code("server.js", 10)], ...o,
});

const ids = (fs: Finding[]) => fs.map((f) => f.id);

describe("corroborate", () => {
  it("folds a review finding into the probe that proved the same route, citing (not appending) its code", () => {
    const users = probe("f-users", "User records exposed without authentication", "/api/users");
    const r = review("Unauthenticated user dump", "GET /api/users returns every user with no auth check.", { severity: "critical" });
    const xss = review("XSS via innerHTML", "Notes are rendered with innerHTML.", { category: "unsafe_defaults" });
    const out = corroborate([users, r, xss]);
    expect(ids(out)).toEqual(["f-users", xss.id]);
    expect(out[0]!.corroboratedBy).toEqual([{ source: "llm_review", title: r.title, severity: "critical", file: "server.js", line: 10 }]);
    expect(out[0]!.evidence).toEqual(users.evidence);
  });

  it("needs the probed route in the review's text or code", () => {
    const users = probe("f-users", "User records exposed without authentication", "/api/users");
    const elsewhere = review("Users list exposed", "GET /api/admin/members lists accounts publicly.", { severity: "critical" });
    expect(ids(corroborate([users, elsewhere]))).toEqual(["f-users", elsewhere.id]);
    const inCode = review("Users list exposed", "The route returns every user.", { severity: "critical", evidence: [code("server.js", 5, 'app.get("/api/users", (req, res) =>')] });
    // The route only in its code (or file path) is not enough: Next.js puts every /api/users/[id] finding there.
    expect(ids(corroborate([users, inCode]))).toEqual(["f-users", inCode.id]);
  });

  it("leaves distinct issues that only share topic words alone", () => {
    const targets = [
      probe("f-users", "User records exposed without authentication", "/api/users"),
      probe("f-debug", "Debug endpoint dumps the environment", "/api/debug", { severity: "high", category: "secret_exposure" }),
      probe("f-chat", "AI proxy endpoint has no authentication or rate limit", "/api/chat", { severity: "high" }),
      probe("f-admin-header", "Admin action authorized by a client-supplied header", "/api/admin/delete-user"),
      probe("f-idor", "Any record readable by id (IDOR)", "/api/notes/1", { severity: "high" }),
    ];
    const distinct = [
      review("Weak password hashing with MD5", "Passwords for users are hashed with MD5 in /api/users signup.", { category: "unsafe_defaults" }),
      review("DELETE /api/users/:id lets anyone delete accounts", "No auth on DELETE /api/users/:id.", { severity: "critical" }),
      review("JWT secret falls back to a hardcoded default", "process.env.JWT_SECRET || 'dev' is used in /api/debug too.", { severity: "critical", category: "secret_exposure" }),
      review("Stored XSS in chat messages", "Anyone can inject script via /api/chat messages.", { category: "unsafe_defaults" }),
      review("OpenAI API key hardcoded", "The key in /api/chat handler is hardcoded; anyone with repo access sees it.", { category: "secret_exposure" }),
      review("Missing security headers on admin routes", "No CSP header on /api/admin/delete-user.", { severity: "low", category: "unsafe_defaults" }),
      review("Missing ownership check on PUT /api/profile", "Any user can overwrite another profile.", { severity: "critical" }),
      review("Full OpenAI error object logged", "The /api/chat handler logs the whole error.", { severity: "low", category: "unsafe_defaults" }),
    ];
    const out = corroborate([...targets, ...distinct]);
    expect(out).toHaveLength(targets.length + distinct.length);
    expect(out.every((f) => !f.corroboratedBy)).toBe(true);
  });

  it("never merges a more severe review finding into a weaker one (score and malicious cap stay)", () => {
    const weak = { id: "f-install-1", title: "Install script could not be fully checked", source: "install_scan", severity: "low", category: "supply_chain", description: "", confirmed: false, evidence: [code("node_modules", 1)] } as Finding;
    const crit = review("postinstall.js harvests env vars and posts them out", "The postinstall hook reads process.env and sends it to a remote server.", { severity: "critical", category: "secret_exposure" });
    expect(ids(corroborate([weak, crit]))).toEqual(["f-install-1", crit.id]);
  });

  it("routes install-time review findings: exfil, then egress, then the install-script finding", () => {
    const t = (id: string, title: string, source: Finding["source"]) =>
      ({ id, title, source, severity: "critical", category: "supply_chain", description: "", confirmed: true, evidence: [code("scripts/setup.js", 1)] }) as Finding;
    const out = corroborate([
      t("f-install-1", "Install script reads secrets", "install_scan"),
      t("f-exfil-1", "Secret exfiltration attempt", "proxy"),
      t("f-egress-direct", "Install-time code opened a direct network connection", "proxy"),
      review("Postinstall exfiltrates an env value via a registry search", "", { severity: "critical", category: "secret_exposure" }),
      review("Postinstall probes the cloud metadata service", "", { category: "unsafe_defaults" }),
      review("Install script enumerates credential-like environment variables", "", { category: "secret_exposure", evidence: [code("scripts/setup.js", 7)] }),
      review("Server binds to all interfaces", "", { severity: "low", category: "unsafe_defaults" }),
      review("Default admin password created on install", "", { category: "unsafe_defaults" }),
    ]);
    expect(ids(out)).toHaveLength(5);
    expect(out.find((x) => x.id === "f-exfil-1")!.corroboratedBy).toHaveLength(1);
    expect(out.find((x) => x.id === "f-egress-direct")!.corroboratedBy![0]!.title).toMatch(/metadata/);
    expect(out.find((x) => x.id === "f-install-1")!.corroboratedBy![0]!.title).toMatch(/enumerates/);
    expect(out.some((x) => x.title === "Default admin password created on install")).toBe(true);
  });

  it("merges a secret review finding only into the secret finding about the same file", () => {
    const sec = { category: "secret_exposure" as const, source: "secret_scan" as const, severity: "high" as const, confirmed: true, description: "" };
    const s1 = { ...sec, id: "f-secret-1", title: "Secret committed in .env", evidence: [code(".env", 1)] } as Finding;
    const s2 = { ...sec, id: "f-secret-2", title: "Hardcoded credential exposed to the browser", evidence: [code("public/app.js", 3)] } as Finding;
    const same = review("Secrets hardcoded in client bundle", "", { category: "secret_exposure", evidence: [code("public/app.js", 4)] });
    const other = review("API key hardcoded in the client", "", { category: "secret_exposure", evidence: [code("src/lib/pay.ts", 2)] });
    const out = corroborate([s1, s2, same, other]);
    expect(ids(out)).toEqual(["f-secret-1", "f-secret-2", other.id]);
    expect(out[1]!.corroboratedBy).toHaveLength(1);
  });

  it("ignores '(unknown)' review files in the citation and doesn't mutate its input", () => {
    const input = [probe("f-cors", "Wildcard CORS policy", "/", { severity: "medium", category: "unsafe_defaults" }), review("Wildcard CORS policy", "", { severity: "medium", category: "unsafe_defaults", evidence: [code("(unknown)", 1)] })];
    const before = JSON.stringify(input);
    const out = corroborate(input);
    expect(out[0]!.corroboratedBy).toEqual([{ source: "llm_review", title: "Wildcard CORS policy", severity: "medium" }]);
    expect(JSON.stringify(input)).toBe(before);
  });

  it("routeOf strips ids and hosts", () => {
    expect(routeOf("/api/notes/1")).toBe("/api/notes");
    expect(routeOf("http://10.0.0.2:3000/api/users?x=1")).toBe("/api/users");
    expect(routeOf("/")).toBeNull();
  });
});

describe("corroborate anchors (review round 2)", () => {
  const users = probe("f-users", "User records exposed without authentication", "/api/users");
  const idor = probe("f-idor", "Any record readable by id (IDOR)", "/api/notes/1", { severity: "high" });
  const page = { ...probe("f-open-page-1", "Admin page open to logged-out visitors", "/admin", { severity: "high", source: "vision" }) } as Finding;

  it("matches the route as a whole path and checks the HTTP method", () => {
    const same = review("IDOR on notes", "GET /api/notes/:id returns any note without an ownership check.");
    const del = review("Missing ownership check on DELETE /api/notes/:id", "Anyone can delete another user's note.");
    const longer = review("Admin API has no auth", "The /api/admin/users route is public to anyone.", { severity: "high" });
    const userDel = review("DELETE /api/users/:id lets any user delete accounts", "Users list and delete without auth.", { severity: "critical" });
    const out = corroborate([users, idor, page, same, del, longer, userDel]);
    expect(ids(out)).toEqual(["f-users", "f-idor", "f-open-page-1", del.id, longer.id, userDel.id]);
  });

  it("keeps a reflected-origin CORS bug apart from the wildcard probe", () => {
    const cors = probe("f-cors", "Wildcard CORS policy", "/", { severity: "medium", category: "unsafe_defaults" });
    const reflect = review("CORS reflects any origin with credentials", "", { severity: "medium", category: "unsafe_defaults" });
    expect(ids(corroborate([cors, reflect]))).toEqual(["f-cors", reflect.id]);
  });

  it("keeps the root's own install hook apart from a dependency's", () => {
    const dep = { id: "f-install-1", title: "Dependency foo makes network connections", source: "install_scan", severity: "high", category: "supply_chain", description: "", confirmed: false, evidence: [code("node_modules/foo/install.js", 3)] } as Finding;
    const root = review("Root postinstall downloads a binary without integrity check", "", { severity: "medium", category: "unsafe_defaults", evidence: [code("package.json", 5)] });
    expect(ids(corroborate([dep, root]))).toEqual(["f-install-1", root.id]);
  });
});

describe("corroborate read vs write (review round 3)", () => {
  const users = probe("f-users", "User records exposed without authentication", "/api/users");
  it("merges a plural-verb dump but not an account-deletion bug on the same route", () => {
    const dump = review("Unauthenticated GET /api/users dumps all users", "", { severity: "critical" });
    const del = review("Account deletion without auth", "The /api/users/:id handler deletes accounts for unauthenticated callers.", { severity: "critical" });
    expect(ids(corroborate([users, dump, del]))).toEqual(["f-users", del.id]);
  });
});
