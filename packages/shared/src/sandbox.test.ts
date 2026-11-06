import { describe, expect, it } from "vitest";
import { AUDIT_LABEL, ApprovalDecision, ApprovalRequest, ApprovalSecrets } from "./audit";
import {
  CONTAINER_LIMITS,
  ContainmentEntry,
  ProxyEvent,
  ProxyState,
  containerArgs,
  keyHosts,
  keyPlaceholder,
} from "./sandbox";

describe("keyPlaceholder", () => {
  it("builds the placeholder", () => {
    expect(keyPlaceholder("OPENAI_API_KEY", "a1b2")).toBe("sk-PLACEHOLDER-OPENAI_API_KEY-a1b2");
  });
  it.each([
    ["openai_key", "a1"],
    ["OPENAI KEY", "a1"],
    ["OPENAI_API_KEY", "a/b"],
    ["OPENAI_API_KEY", ""],
    ["OPENAI_API_KEY", "a1\n"],
  ])("rejects %j / %j", (v, id) => {
    expect(() => keyPlaceholder(v, id)).toThrow();
  });
});

describe("keyHosts", () => {
  it("comes from the provider table only", () => {
    expect(keyHosts("OPENAI_API_KEY")).toEqual(["api.openai.com"]);
    expect(keyHosts("MY_CUSTOM_KEY")).toBeNull();
    expect(keyHosts("constructor")).toBeNull();
    expect(keyHosts("__proto__")).toBeNull();
  });
});

const key = { value: "sk-1234567890", hosts: ["api.openai.com"] };

describe("ProxyState", () => {
  it("accepts a valid state and defaults keys/canaries", () => {
    const s = ProxyState.parse({ auditId: "a1", stage: "install" });
    expect(s.keys).toEqual({});
    expect(s.canaries).toEqual([]);
  });
  it("accepts keys in run-time stages", () => {
    for (const stage of ["run", "dynamic", "verify"]) {
      expect(ProxyState.safeParse({ auditId: "a1", stage, keys: { OPENAI_API_KEY: key } }).success).toBe(true);
    }
  });
  it.each([
    ["bad audit id", { auditId: "a b", stage: "install" }],
    ["unknown stage", { auditId: "a1", stage: "bogus" }],
    ["keys during install", { auditId: "a1", stage: "install", keys: { OPENAI_API_KEY: key } }],
    ["keys during build", { auditId: "a1", stage: "build", keys: { OPENAI_API_KEY: key } }],
    ["short value", { auditId: "a1", stage: "run", keys: { OPENAI_API_KEY: { ...key, value: "short" } } }],
    ["space in value", { auditId: "a1", stage: "run", keys: { OPENAI_API_KEY: { ...key, value: "sk-12345 6789" } } }],
    ["NEL in value", { auditId: "a1", stage: "run", keys: { OPENAI_API_KEY: { ...key, value: "sk-123456789\u0085" } } }],
    ["control char", { auditId: "a1", stage: "run", keys: { OPENAI_API_KEY: { ...key, value: "sk-123456789\u001f" } } }],
    ["astral chars", { auditId: "a1", stage: "run", keys: { OPENAI_API_KEY: { ...key, value: "😀😀😀😀" } } }],
    ["wildcard host", { auditId: "a1", stage: "run", keys: { OPENAI_API_KEY: { ...key, hosts: ["*.openai.com"] } } }],
    ["no hosts", { auditId: "a1", stage: "run", keys: { OPENAI_API_KEY: { ...key, hosts: [] } } }],
    ["uppercase header", { auditId: "a1", stage: "run", keys: { OPENAI_API_KEY: { ...key, headers: ["Authorization"] } } }],
    ["empty headers", { auditId: "a1", stage: "run", keys: { OPENAI_API_KEY: { ...key, headers: [] } } }],
    ["lowercase var", { auditId: "a1", stage: "run", keys: { lower: key } }],
    ["non-ascii canary", { auditId: "a1", stage: "install", canaries: ["AKIA😀😀😀😀"] }],
    ["short canary", { auditId: "a1", stage: "install", canaries: ["AKIA"] }],
  ])("rejects %s", (_name, s) => {
    expect(ProxyState.safeParse(s).success).toBe(false);
  });
});

describe("ProxyEvent", () => {
  // One line of each kind, exactly as the proxy writes them.
  const lines = [
    '{"ts":1793792529.9,"auditId":"t1","stage":"install","kind":"blocked","method":"POST","host":"registry.npmjs.org","port":443,"path":"/-/v1/login","reason":"POST not allowed in stage install"}',
    '{"ts":1793792696.6,"auditId":"t1","stage":"install","kind":"exfil","method":"GET","host":"registry.npmjs.org","port":443,"path":"/left-pad","reason":"canary secret in outbound request","canary":"AKIAVI\\u2026"}',
    '{"ts":1793792710.0,"auditId":"t1","stage":"run","kind":"allowed","method":"GET","host":"api.openai.com","port":443,"path":"/v1/models","swapped":["OPENAI_API_KEY"]}',
    '{"ts":1793792710.1,"auditId":"t1","stage":"run","kind":"allowed","method":"GET","host":"api.openai.com","port":443,"path":"/v1/x","swapped":null}',
    '{"ts":1793792711.0,"auditId":null,"stage":null,"kind":"client_rejected","peer":"10.1.96.9"}',
    '{"ts":1793792712.0,"auditId":"t1","stage":"run","kind":"blocked","reason":"raw TCP not allowed","repeat":120}',
  ];
  it.each(lines)("parses %s", (line) => {
    const e = ProxyEvent.parse(JSON.parse(line));
    if (e.kind === "client_rejected") expect(e.peer).toBe("10.1.96.9");
  });
});

describe("ContainmentEntry", () => {
  it("allows null stage for proxy events with no active audit", () => {
    expect(
      ContainmentEntry.safeParse({ source: "proxy", at: "2026-11-04T12:00:00Z", stage: null, verdict: "blocked" }).success,
    ).toBe(true);
  });
});

describe("approval", () => {
  const req = {
    auditId: "a1",
    requestId: "req-12345",
    plan: { framework: "nextjs", packageManager: "npm", installCommand: "npm ci", buildCommand: "npm run build", startCommand: "npm start", port: 3000 },
    env: [{ name: "OPENAI_API_KEY", provide: "placeholder" }, { name: "DATABASE_URL", provide: "canary" }],
    installScripts: [],
    expiresAt: "2026-11-04T13:00:00Z",
  };
  it("accepts placeholders only for known providers", () => {
    expect(ApprovalRequest.safeParse(req).success).toBe(true);
    const bad = { ...req, env: [{ name: "EVIL_KEY", provide: "placeholder" }] };
    expect(ApprovalRequest.safeParse(bad).success).toBe(false);
  });
  it("planner can't supply key hosts (stripped)", () => {
    const withHosts = { ...req, env: [{ name: "OPENAI_API_KEY", provide: "placeholder", hosts: ["evil.tld"] }] };
    const parsed = ApprovalRequest.parse(withHosts);
    expect(parsed.env[0]).not.toHaveProperty("hosts");
  });
  it("decision carries no secrets and binds to the request", () => {
    const d = ApprovalDecision.parse({ decision: "approve", auditId: "a1", requestId: "req-12345", testKeyVars: ["OPENAI_API_KEY"] });
    expect(JSON.stringify(d)).not.toMatch(/sk-/);
    expect(ApprovalDecision.safeParse({ decision: "approve", testKeyVars: [] }).success).toBe(false);
  });
  it("secrets: known providers only, proxy-compatible values", () => {
    expect(ApprovalSecrets.safeParse({ testKeys: { OPENAI_API_KEY: "sk-1234567890" } }).success).toBe(true);
    expect(ApprovalSecrets.safeParse({ testKeys: { openai_key: "sk-1234567890" } }).success).toBe(false);
    expect(ApprovalSecrets.safeParse({ testKeys: { MY_KEY: "sk-1234567890" } }).success).toBe(false);
    expect(ApprovalSecrets.safeParse({ testKeys: { OPENAI_API_KEY: "sk-123456789\u0085" } }).success).toBe(false);
  });
});

describe("containerArgs", () => {
  const base = { auditId: "a1", network: "va-a1", proxyUrl: "http://10.1.96.4:8080" };
  const app = containerArgs({ ...base, role: "app", workspaceHostPath: "/srv/ws/a1" });
  const browser = containerArgs({ ...base, role: "browser", hosts: { app: "172.30.0.2" } });

  it.each([
    ["app", app],
    ["browser", browser],
  ])("%s gets every mandatory flag", (_role, args) => {
    for (const f of [
      "--runtime=runsc",
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      "--user=1000:1000",
      "--restart=no",
      `--pids-limit=${CONTAINER_LIMITS.pids}`,
      "--network=va-a1",
      `--label=${AUDIT_LABEL}=a1`,
    ]) {
      expect(args).toContain(f);
    }
    const mem = args.find((a) => a.startsWith("--memory="));
    const swap = args.find((a) => a.startsWith("--memory-swap="));
    expect(mem).toBeDefined();
    expect(swap?.split("=")[1]).toBe(mem?.split("=")[1]);
    expect(args.some((a) => a.startsWith("--cpus="))).toBe(true);
    expect(args.some((a) => a.startsWith("--runtime=") && a !== "--runtime=runsc")).toBe(false);
  });
  it("only the app container routes through the proxy; browser talks to the app directly", () => {
    expect(app).toContain("--env=HTTPS_PROXY=http://10.1.96.4:8080");
    expect(browser.some((a) => /_PROXY=/i.test(a) && !a.startsWith("--env=NO_PROXY"))).toBe(false);
  });
  it("browser gets shm and host pins; app gets the workspace and cache dirs", () => {
    expect(browser).toContain("--add-host=app:172.30.0.2");
    expect(browser).toContain(`--shm-size=${CONTAINER_LIMITS.shmBytes.browser}`);
    expect(app).toContain("--volume=/srv/ws/a1:/workspace");
    expect(app.some((a) => a.startsWith("--env=npm_config_cache=/workspace/"))).toBe(true);
  });
  it("rejects bad input", () => {
    expect(() => containerArgs({ ...base, role: "app" })).toThrow();
    expect(() => containerArgs({ ...base, auditId: "a b", role: "browser" })).toThrow();
    expect(() => containerArgs({ ...base, network: "--privileged", role: "browser" })).toThrow();
    expect(() => containerArgs({ ...base, role: "browser", hosts: { app: "1.2.3.4 --privileged" } })).toThrow();
  });
  it("never uses all host CPUs", () => {
    expect(CONTAINER_LIMITS.cpus.app).toBeLessThan(2);
    expect(CONTAINER_LIMITS.cpus.browser).toBeLessThan(2);
  });
});

describe("fake host pins", () => {
  it("maps every fake host to loopback in app containers only", async () => {
    const { containerArgs } = await import("./sandbox");
    const { FAKE_HOSTS } = await import("./env-fakes");
    const base = { auditId: "abcdefghij0123456789", network: "va-x", proxyUrl: "http://10.1.96.4:8080" };
    const app = containerArgs({ ...base, role: "app", workspaceHostPath: "/srv/vibeaudit/ws/x" });
    for (const h of FAKE_HOSTS) expect(app).toContain(`--add-host=${h}:127.0.0.1`);
    const browser = containerArgs({ ...base, role: "browser" });
    expect(browser.some((a) => a.includes("vibeaudit-placeholder"))).toBe(false);
  });
});

describe("build memory profile", () => {
  it("gives only the app container's build step the larger cap", async () => {
    const { containerArgs, CONTAINER_LIMITS } = await import("./sandbox");
    const base = { auditId: "abcdefghij0123456789", network: "va-x", proxyUrl: "http://10.1.96.4:8080" };
    const build = containerArgs({ ...base, role: "app", workspaceHostPath: "/srv/vibeaudit/ws/x", build: true });
    expect(build).toContain(`--memory=${CONTAINER_LIMITS.buildMemoryBytes}`);
    expect(build).toContain(`--memory-swap=${CONTAINER_LIMITS.buildMemoryBytes}`);
    const app = containerArgs({ ...base, role: "app", workspaceHostPath: "/srv/vibeaudit/ws/x" });
    expect(app).toContain(`--memory=${CONTAINER_LIMITS.memoryBytes.app}`);
    expect(() => containerArgs({ ...base, role: "browser", build: true })).toThrow();
    expect(CONTAINER_LIMITS.buildMemoryBytes).toBeLessThanOrEqual(5 * 1024 ** 3); // VM 2 has 8 GB; the host keeps the rest
  });
});
