import { mkdtemp, rm, writeFile, appendFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ContainmentEntry, Finding } from "@vibeaudit/shared";
import { mergeContainment, parseFirewallDrops, proxyLogOffset, readProxyEvents, stageAt, type StageMark } from "./containment";

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
    expect(r.findings[0]).toMatchObject({ severity: "critical", confirmed: true, source: "proxy" });
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
      flood.push(line({ ts: ts(T0 + 11_000), auditId: "me", stage: "install", kind: "blocked", method: "GET", host: `h${i}.example`, reason: "host not allowed" }));
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
    expect(blocked.at(-1)).toMatchObject({ repeat: 200, stage: null });
    expect(r.entries.filter((e) => e.source === "proxy" && e.verdict === "exfil").length).toBe(50);
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

