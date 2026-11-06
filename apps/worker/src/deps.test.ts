import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { Finding } from "@vibeaudit/shared";
import { LIST_SCRIPT, type OsvClient, dependencyFindings, groupVersions, parsePackageList, toAdvisory } from "./deps";

async function runList(files: Record<string, string>) {
  const dir = await mkdtemp(join(tmpdir(), "va-deps-"));
  try {
    for (const [p, c] of Object.entries(files)) {
      await mkdir(dirname(join(dir, p)), { recursive: true });
      await writeFile(join(dir, p), c);
    }
    return parsePackageList(execFileSync(process.execPath, ["-e", LIST_SCRIPT], { cwd: dir, maxBuffer: 256 * 1024 }).toString());
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

const pj = (o: object) => JSON.stringify(o);

describe("package list", () => {
  it("prefers npm's hidden lockfile, with dev and direct flags", async () => {
    const r = await runList({
      "package.json": pj({ dependencies: { lodash: "^4" }, devDependencies: { vitest: "^1" } }),
      "node_modules/.package-lock.json": pj({
        packages: {
          "": { name: "app" },
          "node_modules/lodash": { version: "4.17.20" },
          "node_modules/vitest": { version: "1.0.0", dev: true },
          "node_modules/a/node_modules/@scope/b": { version: "2.0.0" },
          "node_modules/linked": { link: true },
        },
      }),
      "package-lock.json": pj({ packages: { "node_modules/ignored": { version: "9.9.9" } } }),
    });
    expect(r.src).toBe("installed");
    expect(r.packages).toEqual([
      { name: "lodash", version: "4.17.20", dev: false, direct: true },
      { name: "vitest", version: "1.0.0", dev: true, direct: true },
      { name: "@scope/b", version: "2.0.0", dev: false, direct: false },
    ]);
  });

  it("falls back to the repo lockfile, then to walking node_modules (pnpm store and scopes)", async () => {
    expect((await runList({ "package-lock.json": pj({ packages: { "node_modules/x": { version: "1.2.3" } } }) })).src).toBe("lockfile");
    const r = await runList({
      "package.json": pj({ dependencies: { express: "^4" } }),
      "node_modules/express/package.json": pj({ name: "express", version: "4.17.1" }),
      "node_modules/@types/node/package.json": pj({ name: "@types/node", version: "20.1.0" }),
      "node_modules/.pnpm/qs@6.5.2/node_modules/qs/package.json": pj({ name: "qs", version: "6.5.2" }),
    });
    expect(r.src).toBe("walk");
    expect(r.packages.map((p) => `${p.name}@${p.version}${p.direct ? "*" : ""}`).sort()).toEqual(["@types/node@20.1.0", "express@4.17.1*", "qs@6.5.2"]);
  });

  it("drops malformed names and versions from sandbox output", () => {
    const pkgs = ["ok\t1.0.0\t", "../evil\t1.0.0\t", "x\tlatest\t", "y\t1.0.0; rm -rf\t", "@s/ok\t2.0.0-beta.1\tr"].join("\n");
    const r = parsePackageList(JSON.stringify({ src: "walk", truncated: false, pkgs }));
    expect(r.packages.map((p) => p.name)).toEqual(["ok", "@s/ok"]);
    expect(parsePackageList("not json").packages).toEqual([]);
  });
});

describe("advisories", () => {
  const osvRecord = (id: string, severity: string, fixed?: string, name = "lodash") => ({
    id,
    summary: `  Prototype   pollution in ${name} `,
    aliases: ["CVE-2021-23337", "<script>"],
    database_specific: { severity },
    affected: [{ package: { name, ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, ...(fixed ? [{ fixed }] : [])] }] }],
  });

  it("toAdvisory maps severity, fixed version and drops junk", () => {
    expect(toAdvisory(osvRecord("GHSA-35jh-r3h4-6jhm", "HIGH", "4.17.21"), "lodash", "4.17.20")).toEqual({
      id: "GHSA-35jh-r3h4-6jhm",
      aliases: ["CVE-2021-23337"],
      summary: "Prototype pollution in lodash",
      severity: "high",
      malicious: false,
      fixed: "4.17.21",
    });
    expect(toAdvisory({ nope: 1 }, "x", "1.0.0")).toBeNull();
    expect(toAdvisory(osvRecord("GHSA-aaa", "WEIRD"), "lodash", "1.0.0")?.severity).toBe("medium");
  });

  const fakeOsv = (map: Record<string, string[]>, records: Record<string, unknown>): OsvClient & { vulnCalls: number } => {
    const o = {
      vulnCalls: 0,
      async query(pkgs: readonly { name: string; version: string }[]) {
        return pkgs.map((p) => map[`${p.name}@${p.version}`] ?? []);
      },
      async vuln(id: string) {
        o.vulnCalls++;
        return records[id] ?? null;
      },
    };
    return o;
  };

  it("one finding per vulnerable production package; dev skipped; transitive one level lower", async () => {
    const osv = fakeOsv(
      { "lodash@4.17.20": ["GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"], "qs@6.5.2": ["GHSA-qqqq-qqqq-qqqq"], "vitest@1.0.0": ["GHSA-vvvv-vvvv-vvvv"] },
      {
        "GHSA-aaaa-bbbb-cccc": osvRecord("GHSA-aaaa-bbbb-cccc", "CRITICAL", "4.17.21"),
        "GHSA-dddd-eeee-ffff": osvRecord("GHSA-dddd-eeee-ffff", "MODERATE", "4.17.19"),
        "GHSA-qqqq-qqqq-qqqq": osvRecord("GHSA-qqqq-qqqq-qqqq", "HIGH", "6.5.3", "qs"),
      },
    );
    const r = await dependencyFindings(
      [
        { name: "lodash", version: "4.17.20", dev: false, direct: true },
        { name: "qs", version: "6.5.2", dev: false, direct: false },
        { name: "vitest", version: "1.0.0", dev: true, direct: true },
        { name: "clean", version: "1.0.0", dev: false, direct: true },
      ],
      osv,
      "installed",
    );
    expect(r).toMatchObject({ vulnerable: 2, checked: 4, production: 3 });
    const fs = r.findings.map((f) => Finding.parse(f));
    expect(fs.map((f) => [f.title, f.severity])).toEqual([
      ["lodash@4.17.20 has 2 known vulnerabilities", "critical"],
      ["qs@6.5.2 has a known vulnerability", "medium"],
    ]);
    expect(fs[0]).toMatchObject({ category: "vulnerable_dependency", source: "dep_audit", confirmed: false });
    expect(fs[0]!.fix).toContain("4.17.21"); // the highest fix covers both advisories
    expect(fs[0]!.description).toContain("CVE-2021-23337");
    expect(fs[1]!.fix).toContain("override");
  });

  it("survives missing advisory details, and caps findings and lookups", async () => {
    const pkgs = Array.from({ length: 40 }, (_, i) => ({ name: `p${i}`, version: "1.0.0", dev: false, direct: true }));
    const map = Object.fromEntries(pkgs.map((p, i) => [`${p.name}@1.0.0`, [`GHSA-${i}-a`, `GHSA-${i}-b`, `GHSA-${i}-c`]]));
    const osv = fakeOsv(map, {});
    const r = await dependencyFindings(pkgs, osv, "walk");
    expect(r.findings).toHaveLength(15);
    expect(r.findings[0]!.severity).toBe("medium"); // unknown details -> medium
    expect(osv.vulnCalls).toBeLessThanOrEqual(80);
  });

  it("dev-only packages: ordinary advisories ignored, malicious ones reported", async () => {
    const osv = fakeOsv({ "a@1.0.0": ["GHSA-aaaa-aaaa-aaaa"], "evil@1.0.0": ["MAL-2024-1"] }, {});
    const r = await dependencyFindings(
      [
        { name: "a", version: "1.0.0", dev: true, direct: true },
        { name: "evil", version: "1.0.0", dev: true, direct: false },
      ],
      osv,
      "installed",
    );
    expect(r.findings.map((f) => [f.id, f.severity, f.confirmed])).toEqual([["f-malpkg-1", "critical", true]]);
    expect(await dependencyFindings([], osv, "installed")).toMatchObject({ findings: [] });
  });
});

describe("scoring", () => {
  it("caps the dependency penalty as a group but not other findings", async () => {
    const { scoreFrom } = await import("./pipeline");
    const dep = (i: number): Finding => ({ id: `f-dep-${i}`, severity: "high", category: "vulnerable_dependency", title: "t", description: "d", confirmed: false, evidence: [{ kind: "code", file: "x", snippet: "a@1.0.0" }], source: "dep_audit" });
    expect(scoreFrom(Array.from({ length: 15 }, (_, i) => dep(i)))).toBe(70);
    expect(scoreFrom([dep(1)])).toBe(90);
    const crit: Finding = { ...dep(0), id: "c", severity: "critical", confirmed: true, source: "secret_scan", category: "secret_exposure" };
    expect(scoreFrom([crit, ...Array.from({ length: 15 }, (_, i) => dep(i))])).toBe(30);
  });
});

describe("review fixes", () => {
  const rec = (id: string, ranges: { introduced: string; fixed?: string }[], extra: object = {}) => ({
    id,
    summary: "s",
    affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: ranges.flatMap((r) => [{ introduced: r.introduced }, ...(r.fixed ? [{ fixed: r.fixed }] : [])]) }] }],
    ...extra,
  });

  it("picks the smallest fix above the installed version, inside its own range", () => {
    const r = rec("GHSA-xxx", [{ introduced: "0", fixed: "3.10.2" }, { introduced: "4.0.0", fixed: "4.17.21" }]);
    expect(toAdvisory(r, "lodash", "4.17.10")!.fixed).toBe("4.17.21");
    expect(toAdvisory(r, "lodash", "3.5.0")!.fixed).toBe("3.10.2");
    expect(toAdvisory(r, "other", "4.17.10")!.fixed).toBeUndefined();
  });

  it("cmpVersion orders prereleases before releases", async () => {
    const { cmpVersion } = await import("./deps");
    expect(["1.0.0", "1.0.0-beta.2", "0.9.9", "1.0.0-alpha"].sort(cmpVersion)).toEqual(["0.9.9", "1.0.0-alpha", "1.0.0-beta.2", "1.0.0"]);
  });

  it("a MAL- record is a critical, confirmed supply-chain finding, even transitive, and outside the dep cap", async () => {
    const osv: OsvClient = {
      async query(pkgs) { return pkgs.map((p) => (p.name === "evil-pkg" ? ["MAL-2024-1234"] : p.name.startsWith("v") ? ["GHSA-high-high-high"] : [])); },
      async vuln(id) { return id.startsWith("MAL") ? { id, summary: "Malicious code in evil-pkg" } : { id, summary: "x", database_specific: { severity: "HIGH" } }; },
    };
    const pkgs = [{ name: "evil-pkg", version: "1.0.0", dev: false, direct: false }, ...Array.from({ length: 10 }, (_, i) => ({ name: `v${i}`, version: "1.0.0", dev: false, direct: true }))];
    const r = await dependencyFindings(pkgs, osv, "installed");
    const mal = Finding.parse(r.findings[0]);
    expect(mal).toMatchObject({ id: "f-malpkg-1", severity: "critical", confirmed: true, category: "supply_chain" });
    const { scoreFrom } = await import("./pipeline");
    expect(scoreFrom(r.findings)).toBe(100 - 40 - 30); // the malicious package is not capped
  });

  it("drops withdrawn advisories but keeps malformed ones by id", async () => {
    const osv: OsvClient = {
      async query() { return [["GHSA-wwww-wwww-wwww", "GHSA-mmmm-mmmm-mmmm"]]; },
      async vuln(id) { return id.includes("w") ? { id, withdrawn: "2024-01-01T00:00:00Z" } : { garbage: true }; },
    };
    const r = await dependencyFindings([{ name: "lodash", version: "1.0.0", dev: false, direct: true }], osv, "installed");
    expect(r.findings[0]!.title).toBe("lodash@1.0.0 has a known vulnerability");
    expect(r.findings[0]!.description).toContain("GHSA-mmmm-mmmm-mmmm");
  });

  it("shares one deadline across all OSV calls and stops asking after a failure", async () => {
    let calls = 0;
    const osv: OsvClient = {
      async query(pkgs) { return pkgs.map((_, i) => Array.from({ length: 5 }, (_, j) => `GHSA-${i}-${j}x`)); },
      async vuln(_id, signal) {
        calls++;
        await new Promise((res, rej) => { const t = setTimeout(res, 10_000); signal?.addEventListener("abort", () => { clearTimeout(t); rej(new Error("aborted")); }); });
        return null;
      },
    };
    const pkgs = Array.from({ length: 20 }, (_, i) => ({ name: `p${i}`, version: "1.0.0", dev: false, direct: true }));
    const t = Date.now();
    const r = await dependencyFindings(pkgs, osv, "installed", { budgetMs: 300 });
    expect(Date.now() - t).toBeLessThan(3000);
    expect(r.detailsSkipped).toBe(true);
    expect(calls).toBeLessThanOrEqual(8); // one wave of the worker pool, then it stopped
    expect(r.findings).toHaveLength(15); // still reported, by id
  });

  it("direct means top-level and declared; nested copies are transitive", async () => {
    const r = await runList({
      "package.json": pj({ dependencies: { debug: "^4" } }),
      "node_modules/.package-lock.json": pj({ packages: { "node_modules/debug": { version: "4.3.4" }, "node_modules/x/node_modules/debug": { version: "2.6.8" }, "node_modules/alias": { name: "real-pkg", version: "1.0.0" }, "node_modules/o": { version: "1.0.0", devOptional: true } } }),
    });
    expect(r.packages).toEqual([
      { name: "debug", version: "4.3.4", dev: false, direct: true },
      { name: "debug", version: "2.6.8", dev: false, direct: false },
      { name: "real-pkg", version: "1.0.0", dev: false, direct: false }, // "alias" isn't declared here
      { name: "o", version: "1.0.0", dev: true, direct: false },
    ]);
  });

  it("reads lockfile v1, ignores junk names in the script, and survives scope symlink loops", async () => {
    const v1 = await runList({ "package.json": pj({ dependencies: { a: "1" } }), "package-lock.json": pj({ lockfileVersion: 1, dependencies: { a: { version: "1.0.0", dependencies: { b: { version: "2.0.0", dev: true } } } } }) });
    expect(v1.src).toBe("lockfile");
    expect(v1.packages).toEqual([{ name: "a", version: "1.0.0", dev: false, direct: true }, { name: "b", version: "2.0.0", dev: true, direct: false }]);
    const junk = Object.fromEntries(Array.from({ length: 5000 }, (_, i) => [`node_modules/${"".repeat(200)}${i}`, { version: "1.0.0" }]));
    junk["node_modules/ok"] = { version: "1.0.0" };
    const j = await runList({ "package-lock.json": pj({ packages: junk }) });
    expect(j.packages.map((p) => p.name)).toEqual(["ok"]);
    const { symlink, mkdtemp: mk, rm: rmr, mkdir: md, writeFile: wf } = await import("node:fs/promises");
    const dir = await mk(join(tmpdir(), "va-loop-"));
    try {
      await md(join(dir, "node_modules/x"), { recursive: true });
      await wf(join(dir, "node_modules/x/package.json"), pj({ name: "x", version: "1.0.0" }));
      await symlink(join(dir, "node_modules"), join(dir, "node_modules/@a"), "junction").catch(() => {});
      await symlink(join(dir, "node_modules"), join(dir, "node_modules/@b"), "junction").catch(() => {});
      const t = Date.now();
      const out = parsePackageList(execFileSync(process.execPath, ["-e", LIST_SCRIPT], { cwd: dir, maxBuffer: 256 * 1024, timeout: 20_000 }).toString());
      expect(Date.now() - t).toBeLessThan(10_000);
      expect(out.packages.map((p) => p.name)).toEqual(["x"]);
    } finally {
      await rmr(dir, { recursive: true, force: true });
    }
  }, 30_000);
});

describe("round-3 fixes", () => {
  it("pnpm layout keeps direct deps direct even when .pnpm is listed first", async () => {
    const { symlink, mkdtemp: mk, rm: rmr, mkdir: md, writeFile: wf } = await import("node:fs/promises");
    const dir = await mk(join(tmpdir(), "va-pnpm-"));
    try {
      const store = join(dir, "node_modules/.pnpm/express@4.17.1/node_modules/express");
      await md(store, { recursive: true });
      await wf(join(store, "package.json"), pj({ name: "express", version: "4.17.1" }));
      await wf(join(dir, "package.json"), pj({ dependencies: { express: "^4", "@s/x": "1" } }));
      const sstore = join(dir, "node_modules/.pnpm/@s+x@1.0.0/node_modules/@s/x");
      await md(sstore, { recursive: true });
      await wf(join(sstore, "package.json"), pj({ name: "@s/x", version: "1.0.0" }));
      await md(join(dir, "node_modules/@s"), { recursive: true });
      await symlink(store, join(dir, "node_modules/express"), "junction");
      await symlink(sstore, join(dir, "node_modules/@s/x"), "junction");
      const out = parsePackageList(execFileSync(process.execPath, ["-e", LIST_SCRIPT], { cwd: dir }).toString());
      expect(out.packages.filter((p) => p.direct).map((p) => p.name).sort()).toEqual(["@s/x", "express"]);
    } finally {
      await rmr(dir, { recursive: true, force: true });
    }
  });

  it("npm aliases are direct by their declared key", async () => {
    const r = await runList({
      "package.json": pj({ dependencies: { alias: "npm:real-pkg@1" } }),
      "node_modules/.package-lock.json": pj({ packages: { "node_modules/alias": { name: "real-pkg", version: "1.0.0" } } }),
    });
    expect(r.packages).toEqual([{ name: "real-pkg", version: "1.0.0", dev: false, direct: true }]);
  });

  it("cmpVersion: numeric prerelease identifiers and build metadata", async () => {
    const { cmpVersion } = await import("./deps");
    expect(cmpVersion("2.0.0-beta.9", "2.0.0-beta.10")).toBeLessThan(0);
    expect(cmpVersion("1.0.0+b-1", "1.0.0")).toBe(0);
    expect(cmpVersion("1.0.0-1", "1.0.0-alpha")).toBeLessThan(0);
    expect(cmpVersion("1.0.0-alpha", "1.0.0-alpha.1")).toBeLessThan(0);
  });

  it("mergePackageLists keeps a package the install later hid", async () => {
    const { mergePackageLists } = await import("./deps");
    const before = { src: "lockfile", truncated: false, packages: [{ name: "evil", version: "1.0.0", dev: false, direct: false }, { name: "a", version: "1.0.0", dev: true, direct: true }] };
    const after = { src: "installed", truncated: false, packages: [{ name: "a", version: "1.0.0", dev: false, direct: true }] };
    const m = mergePackageLists(before, after);
    expect(m.src).toBe("installed");
    expect(m.packages).toEqual([{ name: "evil", version: "1.0.0", dev: false, direct: false }, { name: "a", version: "1.0.0", dev: false, direct: true }]);
    expect(mergePackageLists(null, after)).toBe(after);
  });
});

describe("round-4 fixes", () => {
  it("keeps results from earlier batches when a later one fails", async () => {
    let n = 0;
    const osv: OsvClient = {
      async query(pkgs) {
        if (n++ > 0) throw new Error("OSV HTTP 503");
        return pkgs.map((p) => (p.name === "evil" ? ["MAL-2024-9"] : []));
      },
      async vuln() { return null; },
    };
    const pkgs = [{ name: "evil", version: "1.0.0", dev: false, direct: false }, ...Array.from({ length: 1500 }, (_, i) => ({ name: `p${i}`, version: "1.0.0", dev: false, direct: false }))];
    const r = await dependencyFindings(pkgs, osv, "installed");
    expect(r.queryPartial).toBe(true);
    expect(r.findings[0]!.id).toBe("f-malpkg-1");
    expect(r.checked).toBe(1000);
  });

  it("merge puts the pre-install lockfile's packages first", async () => {
    const { mergePackageLists } = await import("./deps");
    const m = mergePackageLists(
      { src: "lockfile", truncated: false, packages: [{ name: "hidden", version: "1.0.0", dev: false, direct: false }] },
      { src: "installed", truncated: false, packages: [{ name: "a", version: "1.0.0", dev: false, direct: true }] },
    );
    expect(m.packages[0]!.name).toBe("hidden");
  });
});

describe("round-5 fixes", () => {
  it("walks a large pnpm-style tree without truncating", async () => {
    const { mkdtemp: mk, rm: rmr, mkdir: md, writeFile: wf, symlink } = await import("node:fs/promises");
    const dir = await mk(join(tmpdir(), "va-bigpnpm-"));
    try {
      const N = 2500;
      for (let i = 0; i < N; i++) {
        const base = join(dir, `node_modules/.pnpm/p${i}@1.0.0/node_modules`);
        await md(join(base, `p${i}`), { recursive: true });
        await wf(join(base, `p${i}/package.json`), pj({ name: `p${i}`, version: "1.0.0" }));
        for (let j = 1; j <= 6; j++) await md(join(base, `dep${(i + j) % N}`)).catch(() => {}); // dependency links (dirs here)
      }
      await symlink(join(dir, "node_modules/.pnpm/p0@1.0.0/node_modules/p0"), join(dir, "node_modules/p0"), "junction");
      const out = parsePackageList(execFileSync(process.execPath, ["-e", LIST_SCRIPT], { cwd: dir, maxBuffer: 256 * 1024 }).toString());
      expect(out.truncated).toBe(false);
      expect(out.packages.length).toBe(N);
    } finally {
      await rmr(dir, { recursive: true, force: true });
    }
  }, 120_000);

  it("whitelists the sandbox-reported source", () => {
    expect(parsePackageList(JSON.stringify({ src: "<b>x", truncated: false, pkgs: "" })).src).toBe("unknown");
  });
});

describe("groupVersions", () => {
  const adv = (id: string, severity: "high" | "medium" = "medium") => ({ id, aliases: [], summary: id, severity, malicious: false });
  const row = (version: string, ids: string[], o: { direct?: boolean; malicious?: boolean; severity?: "high" | "medium" | "critical" } = {}) => ({
    p: { name: "undici", version, direct: o.direct ?? false },
    advs: ids.map((i) => adv(i)),
    malicious: o.malicious ?? false,
    severity: o.severity ?? ("medium" as const),
  });

  it("folds one package's versions into one row with the union of advisories and the worst severity", () => {
    const out = groupVersions([row("7.25.0", ["GHSA-a", "GHSA-b"]), row("7.24.4", ["GHSA-b", "GHSA-c"], { direct: true, severity: "high" })]);
    expect(out).toHaveLength(1);
    expect(out[0]!.versions).toEqual(["7.24.4", "7.25.0"]);
    expect(out[0]!.advs.map((a) => a.id)).toEqual(["GHSA-a", "GHSA-b", "GHSA-c"]);
    expect(out[0]!.severity).toBe("high");
    expect(out[0]!.p.direct).toBe(true);
  });

  it("never folds a malicious version into anything", () => {
    const out = groupVersions([row("1.0.0", ["GHSA-a"]), row("1.0.1", ["MAL-1"], { malicious: true, severity: "critical" }), row("1.0.2", ["GHSA-b"])]);
    expect(out.map((r) => r.versions)).toEqual([["1.0.0", "1.0.2"], ["1.0.1"]]);
  });
});

describe("groupVersions fix targets", () => {
  it("keeps each version's own fix, and marks a package that is also installed transitively", () => {
    const mk = (version: string, fixTo: string | undefined, direct: boolean) => ({
      p: { name: "lodash", version, direct },
      advs: [{ id: "GHSA-x", aliases: [], summary: "x", severity: "high" as const, malicious: false }],
      malicious: false,
      severity: "high" as const,
      fixTo,
    });
    const [g] = groupVersions([mk("5.0.0", "5.0.3", true), mk("4.17.15", "4.17.21", false)]);
    expect(g!.fixes).toEqual([{ version: "4.17.15", fixTo: "4.17.21" }, { version: "5.0.0", fixTo: "5.0.3" }]);
    expect(g!.p.direct).toBe(true);
    expect(g!.transitive).toBe(true);
  });
});
