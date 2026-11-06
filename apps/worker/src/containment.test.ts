import { mkdtemp, rm, writeFile, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ContainmentEntry, Finding } from "@vibeaudit/shared";
import { egressFindings, mergeContainment, parseFirewallDrops, proxyLogOffset, readProxyEvents, stageAt, type StageMark } from "./containment";

const T0 = Date.parse("2026-11-04T12:00:00Z");
const marks: StageMark[] = [
  { stage: "intake", at: T0 },
  { stage: "install", at: T0 + 10_000 },
  { stage: "run", at: T0 + 20_000 },
];
const line = (o: Record<string, unknown>) => JSON.stringify(o) + "\n";
const ts = (ms: number) => ms / 1000;

let dir: string;
beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "va-cont-"));
});
afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("stageAt", () => {
  it("returns the stage running at a time", () => {
    expect(stageAt(marks, T0 - 1)).toBeNull();
    expect(stageAt(marks, T0 + 15_000)).toBe("install");
    expect(stageAt(marks, T0 + 99_000)).toBe("run");
  });
});

describe("readProxyEvents", () => {
  it("reads only this audit's lines after the offset, folds allowed traffic, turns exfil into findings", async () => {
    const path = join(dir, "events.jsonl");
    await writeFile(path, line({ ts: ts(T0 - 60_000), auditId: "me", stage: "install", kind: "blocked", host: "old.example" }));
    const offset = await proxyLogOffset(path);
    await appendFile(
      path,
      [
        line({ ts: ts(T0 + 1000), auditId: null, stage: null, kind: "blocked", method: "GET", host: "evil.example", port: 443, path: "/x", reason: "no active audit" }),
        line({ ts: ts(T0 + 11_000), auditId: "me", stage: "install", kind: "allowed", method: "GET", host: "registry.npmjs.org", port: 443, path: "/a" }),
        line({ ts: ts(T0 + 11_500), auditId: "me", stage: "install", kind: "allowed", method: "GET", host: "registry.npmjs.org", port: 443, path: "/b", repeat: 300 }),
        line({ ts: ts(T0 + 12_000), auditId: "other", stage: "install", kind: "blocked", host: "x.example" }),
        line({ ts: ts(T0 + 13_000), auditId: "me", stage: "install", kind: "exfil", method: "POST", host: "collect.example", port: 8443, path: "/c", reason: "canary in body", var: "DATABASE_URL" }),
        line({ ts: ts(T0 + 13_100), auditId: "me", stage: "install", kind: "exfil", method: "POST", host: "collect.example", port: 8443, path: "/d", reason: "canary in body", var: "DATABASE_URL" }),
        line({ ts: ts(T0 + 14_000), auditId: "me", stage: "install", kind: "client_rejected", peer: "10.0.0.9" }),
        line({ ts: ts(T0 + 999_000), auditId: null, stage: null, kind: "blocked", host: "after.example" }), // outside window
        "not json\n",
        '{"ts":1,"auditId":"me","kind":"weird"}\n',
        '{"ts":2,"auditId":"me"', // partial last line
      ].join(""),
    );

    const r = await readProxyEvents({ auditId: "me", offset, windowStartMs: T0, windowEndMs: T0 + 60_000, marks, path });
    for (const e of r.entries) expect(ContainmentEntry.safeParse(e).success).toBe(true);
    for (const f of r.findings) expect(Finding.safeParse(f).success).toBe(true);

    const hosts = r.entries.map((e) => (e.source === "proxy" ? e.host : null));
    expect(hosts).not.toContain("old.example"); // before the offset
    expect(hosts).not.toContain("x.example"); // another audit
    expect(hosts).not.toContain("after.example"); // untagged, outside window

    const untagged = r.entries.find((e) => e.source === "proxy" && e.host === "evil.example");
    expect(untagged?.stage).toBe("intake"); // derived from the marks

    const allowed = r.entries.filter((e) => e.source === "proxy" && e.verdict === "allowed");
    expect(allowed).toHaveLength(1);
    expect(allowed[0]).toMatchObject({ host: "registry.npmjs.org", repeat: 300, path: undefined });

    // Refused peers aren't sandbox activity and would leak an infra address: dropped.
    expect(JSON.stringify(r.entries)).not.toContain("10.0.0.9");

    expect(r.entries.filter((e) => e.source === "proxy" && e.verdict === "exfil")).toHaveLength(2);
    expect(r.findings).toHaveLength(1); // deduped per var+host
    // At install time an exfil is install-time malware: supply_chain (score cap + banner).
    expect(r.findings[0]).toMatchObject({ severity: "critical", confirmed: true, source: "proxy", category: "supply_chain" });
    expect(r.findings[0]!.description).toContain("DATABASE_URL");
    expect(r.findings[0]!.evidence[0]).toMatchObject({ kind: "http", url: "collect.example:8443/c" });
  });

  it("re-reads from the start if the log shrank, and copes with a missing file", async () => {
    const path = join(dir, "short.jsonl");
    await writeFile(path, line({ ts: ts(T0 + 1), auditId: "me", stage: "run", kind: "blocked", host: "h.example" }));
    const r = await readProxyEvents({ auditId: "me", offset: 10_000_000, windowStartMs: T0, windowEndMs: T0 + 1e6, marks, path });
    expect(r.entries).toHaveLength(1);
    const none = await readProxyEvents({ auditId: "me", offset: 0, windowStartMs: T0, windowEndMs: T0 + 1, marks, path: join(dir, "nope") });
    expect(none.entries).toEqual([]);
  });

  it("masks planted canaries in the stored path, host and exfil finding", async () => {
    const path = join(dir, "canary.jsonl");
    await writeFile(path, line({ ts: ts(T0 + 1), auditId: "me", stage: "install", kind: "exfil", method: "GET", host: "registry.npmjs.org", path: "/-/v1/search?text=AKIAVIBE3011B7CB8F5D10DCA8", reason: "canary secret in outbound request" }));
    const r = await readProxyEvents({ auditId: "me", offset: 0, windowStartMs: T0, windowEndMs: T0 + 1e6, marks, path });
    const json = JSON.stringify(r);
    expect(json).not.toContain("3011B7CB8F5D");
    expect(json).toContain("text=AKIAVIBE…");
    expect(r.findings).toHaveLength(1);
  });

  it("caps untrusted strings", async () => {
    const path = join(dir, "long.jsonl");
    await writeFile(path, line({ ts: ts(T0 + 1), auditId: "me", stage: "run", kind: "blocked", host: "h.example", path: "/" + "a".repeat(2000), reason: "r".repeat(1000) }));
    const r = await readProxyEvents({ auditId: "me", offset: 0, windowStartMs: T0, windowEndMs: T0 + 1e6, marks, path });
    const e = r.entries[0]!;
    expect(e.source === "proxy" && e.path!.length).toBeLessThanOrEqual(301);
    expect(e.source === "proxy" && e.reason!.length).toBeLessThanOrEqual(201);
  });
});

describe("parseFirewallDrops", () => {
  it("parses iptables LOG lines from kern.log", () => {
    const text = [
      "2026-11-04T12:00:25.747095+00:00 vibe-sbx kernel: VIBEAUDIT-DROP egress IN=br-daa54e811059 OUT=enp1s0 PHYSIN=veth247d543 MAC=de:89 SRC=172.30.0.3 DST=1.1.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=40000 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0",
      "2026-11-04T12:00:26.000000+00:00 vibe-sbx kernel: VIBEAUDIT-DROP host IN=br-daa54e811059 OUT= SRC=172.30.0.3 DST=172.30.0.1 LEN=84 PROTO=ICMP TYPE=8 CODE=0",
      "2026-11-04T10:00:00.000000+00:00 vibe-sbx kernel: VIBEAUDIT-DROP egress IN=br-daa54e811059 DST=9.9.9.9 PROTO=UDP DPT=53", // long before the audit
      "garbage",
    ].join("\n");
    const out = parseFirewallDrops(text, marks, T0);
    expect(out).toHaveLength(2);
    expect(out[0]).toMatchObject({ source: "firewall", direction: "egress", proto: "tcp", dst: "1.1.1.1", dport: 443, stage: "run" });
    expect(out[1]).toMatchObject({ direction: "host", proto: "icmp", dst: "172.30.0.1" });
    expect((out[1] as { dport?: number }).dport).toBeUndefined();
    for (const e of out) expect(ContainmentEntry.safeParse(e).success).toBe(true);
  });
});

describe("mergeContainment", () => {
  it("keeps blocked/exfil over allowed when capping, and returns chronological order", () => {
    const allowed = Array.from({ length: 500 }, (_, i): ContainmentEntry => ({
      source: "proxy", at: new Date(T0 + i).toISOString(), stage: "install", verdict: "allowed", host: `h${i}.example`,
    }));
    const exfil: ContainmentEntry = { source: "proxy", at: new Date(T0 + 1e6).toISOString(), stage: "run", verdict: "exfil", host: "x" };
    const out = mergeContainment(allowed, [exfil]);
    expect(out).toHaveLength(400);
    expect(out.at(-1)).toEqual(exfil);
    for (let i = 1; i < out.length; i++) expect(out[i - 1]!.at <= out[i]!.at).toBe(true);
  });
});

describe("readProxyEvents bounds", () => {
  it("still finds exfil after a flood, keeps memory bounded, and dedupes findings per variable", async () => {
    const path = join(dir, "flood.jsonl");
    const flood: string[] = [];
    for (let i = 0; i < 2000; i++) {
      flood.push(line({ ts: ts(T0 + 11_000), auditId: "me", stage: "install", kind: "blocked", method: "GET", host: `h${i}.example`, reason: "host not allowed in stage install" }));
    }
    for (let i = 0; i < 50; i++) {
      flood.push(line({ ts: ts(T0 + 21_000), auditId: "me", stage: "run", kind: "exfil", method: "POST", host: `x${i}.example`, reason: "canary", var: "SECRET" }));
    }
    await writeFile(path, flood.join(""));
    const r = await readProxyEvents({ auditId: "me", offset: 0, windowStartMs: T0, windowEndMs: T0 + 1e6, marks, path, lineBudget: 500 });
    expect(r.findings).toHaveLength(1); // one per variable, not per (sandbox-chosen) host
    expect(r.findings[0]!.description).toContain("50 hosts");
    const blocked = r.entries.filter((e) => e.source === "proxy" && e.verdict === "blocked");
    // 300 kept individually + one "N more" summary; past the 500-line budget only exfil parsed
    expect(blocked.length).toBe(301);
    expect(blocked.at(-1)).toMatchObject({ repeat: 200, stage: "install" });
    expect(r.entries.filter((e) => e.source === "proxy" && e.verdict === "exfil").length).toBe(50);
    // At run time it's the app leaking a secret, not install-time malware.
    expect(r.findings.every((f) => f.category === "secret_exposure")).toBe(true);
  });

  it("counts sampled repeats as deltas, so a later stage doesn't inherit an earlier one's total", async () => {
    const path = join(dir, "repeat.jsonl");
    const l: string[] = [];
    const base = { auditId: "me", kind: "allowed", method: "GET", host: "registry.npmjs.org", port: 443 };
    for (let i = 0; i < 20; i++) l.push(line({ ...base, ts: ts(T0 + 11_000), stage: "install", path: `/p${i}` }));
    l.push(line({ ...base, ts: ts(T0 + 12_000), stage: "install", repeat: 100 }));
    l.push(line({ ...base, ts: ts(T0 + 21_000), stage: "run", repeat: 200 })); // proxy key has no stage
    l.push(line({ ...base, auditId: null, stage: null, ts: ts(T0 + 1000), repeat: 4700 })); // shared counter
    await writeFile(path, l.join(""));
    const r = await readProxyEvents({ auditId: "me", offset: 0, windowStartMs: T0, windowEndMs: T0 + 1e6, marks, path });
    const by = Object.fromEntries(r.entries.map((e) => [e.stage, e.source === "proxy" ? (e.repeat ?? 1) : 0]));
    expect(by).toEqual({ intake: 1, install: 100, run: 100 });
  });
});

describe("parseFirewallDrops ICMP errors", () => {
  it("doesn't read the embedded packet's fields", () => {
    const text =
      "2026-11-04T12:00:25.000000+00:00 vibe-sbx kernel: VIBEAUDIT-DROP egress IN=br-daa54e811059 OUT=enp1s0 SRC=172.30.0.3 DST=8.8.8.8 LEN=72 PROTO=ICMP TYPE=3 CODE=3 [SRC=8.8.8.8 DST=172.30.0.3 LEN=44 PROTO=UDP SPT=53 DPT=40000 LEN=24 ]";
    const [e] = parseFirewallDrops(text, marks, T0);
    expect(e).toMatchObject({ dst: "8.8.8.8", proto: "icmp" });
    expect((e as { dport?: number }).dport).toBeUndefined();
  });
});


describe("egressFindings", () => {
  const at = new Date(T0 + 12_000).toISOString();
  const fw = (o: Partial<Extract<ContainmentEntry, { source: "firewall" }>>): ContainmentEntry =>
    ({ source: "firewall", at, stage: "install", direction: "egress", proto: "tcp", dst: "192.0.2.1", dport: 443, ...o }) as ContainmentEntry;
  const px = (o: Partial<Extract<ContainmentEntry, { source: "proxy" }>>): ContainmentEntry =>
    ({ source: "proxy", at, stage: "install", verdict: "blocked", method: "GET", host: "evil.example", path: "/x", reason: "host not allowed in stage install", ...o }) as ContainmentEntry;

  it("flags a direct install-time connection as a critical, confirmed supply-chain finding", () => {
    const out = egressFindings([fw({})]);
    expect(out).toHaveLength(1);
    const f = Finding.parse(out[0]);
    expect(f).toMatchObject({ id: "f-egress-direct", severity: "critical", category: "supply_chain", confirmed: true });
    expect(f.evidence[0]).toMatchObject({ kind: "network", control: "firewall", target: "tcp 192.0.2.1:443", stage: "install" });
    expect(f.description).toContain("192.0.2.1:443");
  });

  it("rates DNS-only drops medium", () => {
    expect(egressFindings([fw({ proto: "udp", dst: "10.0.0.2", dport: 53 })])[0]).toMatchObject({ severity: "medium" });
  });

  it("ignores run/dynamic, allowed traffic, untagged entries and exfil rows", () => {
    expect(
      egressFindings([
        fw({ stage: "run" }),
        fw({ stage: "dynamic" }),
        fw({ stage: null }),
        px({ stage: "run", host: "api.openai.com" }),
        px({ verdict: "allowed", host: "registry.npmjs.org" }),
        px({ verdict: "exfil" }),
        px({ reason: "no active audit" }),
        { source: "limit", at, stage: "install", limit: "stage_timeout", detail: "x" },
      ]),
    ).toEqual([]);
  });

  it("doesn't flag the app calling its own provider API at build, but does at install or when evasive", () => {
    const own = px({ stage: "build", host: "api.openai.com:443", method: "CONNECT", path: undefined, reason: "host not allowed in stage build" });
    expect(egressFindings([own])).toEqual([]);
    expect(egressFindings([px({ stage: "install", host: "api.openai.com" })])).toHaveLength(1);
    expect(egressFindings([px({ stage: "build", host: "api.openai.com", reason: "IP-literal hosts are not allowed" })])).toHaveLength(1);
  });

  it("rates a plain blocked GET medium and an evasive or data-carrying block high", () => {
    expect(egressFindings([px({})])[0]).toMatchObject({ id: "f-egress-blocked", severity: "medium" });
    expect(egressFindings([px({ method: "POST", reason: "POST not allowed in stage install" })])[0]!.severity).toBe("high");
    expect(egressFindings([px({ method: undefined, host: undefined, reason: "raw TCP not allowed" })])[0]!.severity).toBe("high");
    expect(egressFindings([px({ stage: "build", reason: "IP-literal hosts are not allowed", host: "1.2.3.4" })])[0]!.severity).toBe("high");
  });

  it("caps evidence, lists hosts boundedly, puts evasive evidence first and counts repeats", () => {
    const many = Array.from({ length: 12 }, (_, i) => px({ host: `h${i}.example` }));
    const out = egressFindings([...many, px({ method: "POST", reason: "POST not allowed in stage install", repeat: 3 })]);
    const f = Finding.parse(out[0]);
    expect(f.evidence).toHaveLength(5);
    expect(f.evidence[0]).toMatchObject({ kind: "network", target: "POST evil.example/x" });
    expect(f.description).toContain("15 request(s)");
    expect(f.description).toMatch(/and \d+ more/);
  });

  it("emits one finding per control when both fired", () => {
    expect(egressFindings([fw({}), px({})]).map((f) => f.id)).toEqual(["f-egress-direct", "f-egress-blocked"]);
  });
});

describe("readProxyEvents + egressFindings under floods", () => {
  it("counts sampled blocked repeats as deltas, not running totals", async () => {
    const path = join(dir, "blk-repeat.jsonl");
    const base = { auditId: "me", stage: "install", kind: "blocked", method: "CONNECT", host: "evil.example", reason: "host not allowed in stage install" };
    const l: string[] = [];
    for (let i = 0; i < 20; i++) l.push(line({ ...base, ts: ts(T0 + 11_000) }));
    for (const n of [100, 200, 300]) l.push(line({ ...base, ts: ts(T0 + 12_000), repeat: n }));
    await writeFile(path, l.join(""));
    const r = await readProxyEvents({ auditId: "me", offset: 0, windowStartMs: T0, windowEndMs: T0 + 1e6, marks, path });
    const f = egressFindings(r.entries)[0]!;
    expect(f.description).toContain("300 request(s)");
  });

  it("keeps an evasive request that follows a flood of plain ones, and the overflow still counts", async () => {
    const path = join(dir, "blk-flood.jsonl");
    const l: string[] = [];
    for (let i = 0; i < 400; i++) {
      l.push(line({ ts: ts(T0 + 11_000), auditId: "me", stage: "install", kind: "blocked", method: "CONNECT", host: `h${i}.example`, reason: "host not allowed in stage install" }));
    }
    l.push(line({ ts: ts(T0 + 12_000), auditId: "me", stage: "install", kind: "blocked", reason: "raw TCP not allowed" }));
    await writeFile(path, l.join(""));
    const r = await readProxyEvents({ auditId: "me", offset: 0, windowStartMs: T0, windowEndMs: T0 + 1e6, marks, path });
    const f = egressFindings(r.entries)[0]!;
    expect(f.severity).toBe("high");
    expect(f.title).toContain("refused");
    expect(f.description).toContain("401 request(s)");
    expect(f.evidence[0]).toMatchObject({ kind: "network", detail: "raw TCP not allowed" });
  });

  it("a flood of plain blocks alone is high", () => {
    const at = new Date(T0 + 12_000).toISOString();
    const out = egressFindings([
      { source: "proxy", at, stage: "install", verdict: "blocked", method: "GET", host: "a.example", reason: "host not allowed in stage install" },
      { source: "proxy", at, stage: "install", verdict: "blocked", reason: "350 more blocked event(s) not listed", repeat: 350 },
    ]);
    expect(out[0]).toMatchObject({ severity: "high", id: "f-egress-blocked" });
  });

  it("an overflow row alone still yields a finding with evidence", () => {
    const at = new Date(T0 + 12_000).toISOString();
    const f = Finding.parse(egressFindings([{ source: "proxy", at, stage: "build", verdict: "blocked", reason: "40 more blocked event(s) not listed", repeat: 40 }])[0]);
    expect(f.severity).toBe("medium");
    expect(f.description).toContain("During build");
  });

  it("known tool telemetry is info, and an evasive request to the same host is not excused", () => {
    const at = new Date(T0 + 12_000).toISOString();
    const base = { source: "proxy" as const, at, stage: "build" as const, verdict: "blocked" as const, host: "telemetry.nextjs.org", reason: "host not allowed in stage build" };
    expect(egressFindings([{ ...base, method: "CONNECT" }])[0]).toMatchObject({ severity: "info" });
    expect(egressFindings([{ ...base, method: "CONNECT" }, { ...base, method: "CONNECT", host: "evil.example" }])[0]!.severity).toBe("medium");
    expect(egressFindings([{ ...base, method: "POST", reason: "POST not allowed in stage build" }])[0]!.severity).toBe("high");
  });

  it("many DNS-only drops are high", () => {
    const at = new Date(T0 + 12_000).toISOString();
    const dns = Array.from({ length: 25 }, () => ({ source: "firewall" as const, at, stage: "install" as const, direction: "egress" as const, proto: "udp", dst: "10.0.0.2", dport: 53 }));
    expect(egressFindings(dns)[0]).toMatchObject({ severity: "high" });
  });
});

describe("egressFindings known hosts", () => {
  const at = new Date(T0 + 12_000).toISOString();
  const b = (host: string, stage: "install" | "build") =>
    ({ source: "proxy", at, stage, verdict: "blocked", method: "CONNECT", host, reason: `host not allowed in stage ${stage}` }) as ContainmentEntry;
  it("does not excuse attacker-hostable CDNs", () => {
    expect(egressFindings([b("storage.googleapis.com", "install")])[0]!.severity).toBe("medium");
  });
  it("treats registry pokes during build as known tool traffic", () => {
    expect(egressFindings([b("registry.npmjs.org", "build")])[0]!.severity).toBe("info");
  });
});
