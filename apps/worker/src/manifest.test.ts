import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { MANIFEST_SCRIPT, declaredEnvNames, watchedCanaries } from "./pipeline";

// The manifest script is ours (it runs in the sandbox against repo files); here it runs against
// a fixture directory we write, so no repo code is involved.
const dir = mkdtempSync(join(tmpdir(), "va-manifest-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

function run(): { envNames: string[]; envFiles: string[]; pkg: string | null } {
  return JSON.parse(execFileSync(process.execPath, ["-e", MANIFEST_SCRIPT], { cwd: dir, encoding: "utf8" }));
}

describe("manifest script: declared env names", () => {
  it("takes names (never values) from env files and code, skipping node_modules", () => {
    writeFileSync(join(dir, "package.json"), '{"name":"x"}');
    writeFileSync(join(dir, ".env.example"), "# comment\nSTRIPE_SECRET_KEY=\nexport SUPABASE_URL=https://x\n lower_case=1\n");
    writeFileSync(join(dir, ".env"), "OPENAI_API_KEY=sk-real-value-that-must-not-leave\n");
    mkdirSync(join(dir, "src", "lib"), { recursive: true });
    writeFileSync(join(dir, "src", "lib", "db.ts"), 'const a = process.env.JWT_SECRET; const b = process.env["RESEND_KEY"]; const c = import.meta.env.VITE_PUBLIC_X;');
    mkdirSync(join(dir, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(dir, "node_modules", "dep", "index.js"), "process.env.FROM_DEPENDENCY");
    const out = run();
    expect(out.envNames).toEqual(expect.arrayContaining(["STRIPE_SECRET_KEY", "SUPABASE_URL", "OPENAI_API_KEY", "JWT_SECRET", "RESEND_KEY", "VITE_PUBLIC_X"]));
    expect(out.envNames).not.toContain("FROM_DEPENDENCY");
    expect(out.envNames).not.toContain("lower_case");
    expect(JSON.stringify(out)).not.toContain("sk-real-value");
    expect(out.envFiles).toEqual(expect.arrayContaining([".env", ".env.example"]));
  });

  it("skips quoted multi-line values and doesn't truncate mixed-case names", () => {
    writeFileSync(join(dir, ".env.local"), 'PRIVATE_KEY="-----BEGIN KEY-----\nQW8Z=\nABCD=\n-----END KEY-----"\nAFTER_PEM=1\n');
    writeFileSync(join(dir, "src", "mixed.js"), "process.env.API_Key; process.env.Foo; process.env?.OPTIONAL_X;");
    const out = run();
    expect(out.envNames).toEqual(expect.arrayContaining(["PRIVATE_KEY", "AFTER_PEM", "OPTIONAL_X"]));
    for (const bad of ["QW8Z", "ABCD", "API_K", "F"]) expect(out.envNames).not.toContain(bad);
  });

  it("sends at most 60 names", () => {
    writeFileSync(join(dir, "src", "many.js"), Array.from({ length: 150 }, (_, i) => `process.env.MANY_${i};`).join("\n"));
    expect(run().envNames.length).toBeLessThanOrEqual(60);
  });

  it("doesn't follow a symlinked env file or directory", () => {
    const outside = mkdtempSync(join(tmpdir(), "va-outside-"));
    writeFileSync(join(outside, "x.js"), "process.env.OUTSIDE_NAME");
    writeFileSync(join(outside, "envfile"), "LINKED_NAME=1\n");
    try {
      symlinkSync(outside, join(dir, "linked"), "dir");
      symlinkSync(join(outside, "envfile"), join(dir, ".env.linked"));
    } catch {
      rmSync(outside, { recursive: true, force: true });
      return; // no symlink permission on this machine (Windows without dev mode)
    }
    const out = run();
    expect(out.envNames).not.toContain("OUTSIDE_NAME");
    expect(out.envNames).not.toContain("LINKED_NAME");
    rmSync(outside, { recursive: true, force: true });
  });
});

describe("declaredEnvNames", () => {
  it("keeps well-formed unique names only, capped, never the generic canary", () => {
    expect(declaredEnvNames(null)).toEqual([]);
    expect(declaredEnvNames("A")).toEqual([]);
    expect(declaredEnvNames(["A_B", "A_B", 3, "bad name", "VIBEAUDIT_CANARY", "X".repeat(65), "OK"])).toEqual(["A_B", "OK"]);
    expect(declaredEnvNames(Array.from({ length: 500 }, (_, i) => `V${i}`))).toHaveLength(60);
  });
});

describe("watchedCanaries", () => {
  const c = { JWT_SECRET: "AKIAVIBE1111", VIBEAUDIT_CANARY: "AKIAVIBE2222" };
  it("watches every canary at install, only the generic one at build and run", () => {
    expect(watchedCanaries(c, "install").sort()).toEqual(["AKIAVIBE1111", "AKIAVIBE2222"]);
    expect(watchedCanaries(c, "build")).toEqual(["AKIAVIBE2222"]);
    expect(watchedCanaries(c, "run")).toEqual(["AKIAVIBE2222"]);
  });
});
