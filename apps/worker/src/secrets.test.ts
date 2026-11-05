import { describe, expect, it } from "vitest";
import { Finding } from "@vibeaudit/shared";
import { EXAMPLE_FILE, bundleLeakFindings, fromContent, maskFinding, maskSecrets, scanFiles, secretFindings } from "./secrets";

const F = (files: { path: string; content: string }[]) => files.map((f) => fromContent(f.path, f.content));

// Test fixtures are assembled at runtime so this file never contains a full key-shaped string.
const k = (...parts: string[]) => parts.join("");
const STRIPE_LIVE = k("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc");
const OPENAI = k("sk-", "proj-", "abcDEF123456ghiJKL789012mno");
const AWS = k("AKIA", "IOSFODNN7EXAMPLQ");
const GH = k("ghp_", "a".repeat(10), "B1c2D3e4F5g6H7i8J9k0L1m2N3");

const jwt = (payload: object) => `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.c2lnbmF0dXJlLXNpZ25hdHVyZQ`;

describe("maskSecrets", () => {
  it("masks known formats and keeps a recognisable prefix", () => {
    const out = maskSecrets(`const s = "${STRIPE_LIVE}"; aws=${AWS} gh ${GH} ai ${OPENAI}`);
    for (const v of [STRIPE_LIVE, AWS, GH, OPENAI]) expect(out).not.toContain(v);
    expect(out).toContain("sk_live_");
    expect(out).toContain("[redacted");
  });

  it("masks credential assignments and .env lines but not placeholders", () => {
    expect(maskSecrets(`const ADMIN_TOKEN = "Zx9qP2mL7vR4tY8w"`)).not.toContain("Zx9qP2mL7vR4tY8w");
    expect(maskSecrets("SESSION_SECRET=Zx9qP2mL7vR4tY8w")).not.toContain("Zx9qP2mL7vR4tY8w");
    expect(maskSecrets("API_KEY=your-api-key-here")).toBe("API_KEY=your-api-key-here");
    expect(maskSecrets("PORT=3000")).toBe("PORT=3000");
  });

  it("removes PEM bodies but keeps the line count", () => {
    const body = "MIIEowIBAAKCAQEA" + "q1w2e3r4t5y6u7i8o9p0".repeat(3);
    const pem = `a\n-----BEGIN RSA PRIVATE KEY-----\n${body}\n${body}\n-----END RSA PRIVATE KEY-----\nb`;
    const out = maskSecrets(pem);
    expect(out).not.toContain("MIIEowIBAAKCAQEA");
    expect(out.split("\n")).toHaveLength(pem.split("\n").length);
  });

  it("is idempotent and leaves the sandbox's own markers alone", () => {
    const once = maskSecrets(`x = "${STRIPE_LIVE}"`);
    expect(maskSecrets(once)).toBe(once);
    const placeholder = "sk-PLACEHOLDER-OPENAI_API_KEY-a1b2c3d4e5f6";
    expect(maskSecrets(placeholder)).toBe(placeholder);
    expect(maskSecrets("AKIAVIBE0123456789ABCDEF0123")).toBe("AKIAVIBE0123456789ABCDEF0123");
  });

  it("maskFinding covers every evidence text field", () => {
    const f: Finding = {
      id: "x", severity: "high", category: "secret_exposure", title: `t ${AWS}`, description: `d ${AWS}`, confirmed: true, source: "probe", fix: `f ${AWS}`,
      evidence: [
        { kind: "code", file: "a.js", snippet: AWS },
        { kind: "http", method: "GET", url: `http://x/?k=${AWS}`, status: 200, headers: { "x-k": AWS }, bodyExcerpt: AWS },
        { kind: "bundle", asset: "b.js", match: AWS },
        { kind: "network", control: "proxy", at: "2026-01-01T00:00:00Z", stage: "install", target: AWS, detail: AWS },
        { kind: "screenshot", path: "s.png", verdict: AWS },
      ],
    };
    expect(JSON.stringify(maskFinding(f))).not.toContain(AWS);
    expect(Finding.safeParse(maskFinding(f)).success).toBe(true);
  });
});

describe("scanFiles + secretFindings", () => {
  it("rates a key in browser-served code a step worse than in server code", () => {
    const hits = scanFiles(
      F([
        { path: "public/app.js", content: `const k = "${STRIPE_LIVE}";` },
        { path: "server.js", content: `const gh = "${GH}";` },
      ]),
      { framework: "express" },
    );
    const fs = secretFindings(hits).map((f) => Finding.parse(f));
    const browser = fs.find((f) => f.title.includes("browser"))!;
    expect(browser).toMatchObject({ severity: "critical", confirmed: true, source: "secret_scan" });
    expect(fs.find((f) => f.title.includes("GitHub"))!.severity).toBe("critical");
    // The report never carries the raw value.
    expect(JSON.stringify(fs)).not.toContain(STRIPE_LIVE);
    expect(JSON.stringify(fs)).not.toContain(GH);
  });

  it("flags committed .env secrets, skips .env.example and test fixtures", () => {
    const hits = scanFiles(
      F([
        { path: ".env", content: `OPENAI_API_KEY=${OPENAI}\nSESSION_SECRET=Zx9qP2mL7vR4tY8wQ1\nPORT=3000\nADMIN_PASSWORD=admin123` },
        { path: ".env.example", content: `OPENAI_API_KEY=${OPENAI}` },
        { path: "test/fixtures.js", content: `const k = "${STRIPE_LIVE}"` },
      ]),
      { framework: "nextjs" },
    );
    expect(hits.map((h) => [h.rule.id, h.file])).toEqual([
      ["openai", ".env"],
      ["env_value", ".env"],
    ]);
    expect(hits.every((h) => h.where === "env")).toBe(true);
    const fs = secretFindings(hits);
    expect(fs[0]!.title).toBe("Secret committed in .env");
  });

  it("treats NEXT_PUBLIC_ / VITE_ references and 'use client' files as browser code", () => {
    const hits = scanFiles(
      F([
        { path: "app/page.tsx", content: `"use client";\nconst k = "${AWS}";` },
        { path: "src/main.ts", content: `const t = "${GH}";` },
        { path: ".env.local", content: `NEXT_PUBLIC_STRIPE_KEY=${STRIPE_LIVE}` },
      ]),
      { framework: "vite" },
    );
    expect(hits.map((h) => h.where)).toEqual(["browser", "browser", "browser"]);
  });

  it("only reports service-role Supabase JWTs, not anon keys", () => {
    const hits = scanFiles(
      F([{ path: "lib/db.ts", content: `const a = "${jwt({ role: "anon" })}";\nconst s = "${jwt({ role: "service_role" })}";` }]),
      { framework: "nextjs" },
    );
    expect(hits.map((h) => [h.rule.id, h.line])).toEqual([["supabase_service", 2]]);
  });

  it("reports public Google keys low and does not double-report the line as generic", () => {
    const hits = scanFiles(F([{ path: "src/firebase.ts", content: `const firebaseApiKey = "AIza${"x1".repeat(17)}y";` }]), { framework: "nextjs" });
    expect(hits).toHaveLength(1);
    expect(secretFindings(hits)[0]!.severity).toBe("low");
  });

  it("ignores placeholders, weak dictionary values and localhost URLs", () => {
    const hits = scanFiles(
      F([{ path: "server.js", content: `const API_KEY = "your-api-key-here";\nconst password = "password1234";\nconst token = process.env.TOKEN;\nconst db = "postgres://postgres:postgres@localhost:5432/app";` }]),
      { framework: "express" },
    );
    expect(hits).toEqual([]);
  });

  it("caps findings and locations, and dedupes the same value", () => {
    const files = Array.from({ length: 30 }, (_, i) => ({ path: `src/f${i}.js`, content: `const k = "${STRIPE_LIVE}";` }));
    const hits = scanFiles(F(files), { framework: "express" });
    expect(hits).toHaveLength(1); // same value everywhere: reported once
    const many = Array.from({ length: 30 }, (_, i) => ({ path: `lib/f${i}.js`, content: `const k = "${k("sk_live_", "4eC39HqLyjWDarjtT1zd", String(1000 + i))}";` }));
    const f = secretFindings(scanFiles(F(many), { framework: "express" }))[0]!;
    expect(f.evidence).toHaveLength(5);
  });
});

describe("bundle scan", () => {
  it("proves a server env var was inlined into the client bundle via its marker", () => {
    const planted = { DATABASE_URL: "AKIAVIBE0123456789ABCDEF01", NEXT_PUBLIC_SITE_URL: "AKIAVIBEAAAA0000BBBB1111CC", NEXT_PUBLIC_STRIPE_SECRET: "AKIAVIBEFFFF0000EEEE1111DD" };
    const asset = ".next/static/chunks/app.js";
    const found = { AKIAVIBE0123456789ABCDEF01: [asset], AKIAVIBEAAAA0000BBBB1111CC: [asset], AKIAVIBEFFFF0000EEEE1111DD: [asset] };
    const fs = bundleLeakFindings(found, planted).map((f) => Finding.parse(f));
    expect(fs.map((f) => [f.title, f.severity])).toEqual([
      ["DATABASE_URL is built into the client bundle", "critical"],
      ["NEXT_PUBLIC_STRIPE_SECRET is built into the client bundle", "critical"],
    ]);
    expect(fs[0]!.evidence[0]).toMatchObject({ kind: "bundle", asset: ".next/static/chunks/app.js" });
    expect(JSON.stringify(fs)).not.toContain("AKIAVIBE0123456789ABCDEF01");
  });

  it("flags a key placeholder in the bundle and never reports the placeholder as an OpenAI key", () => {
    const ph = "sk-PLACEHOLDER-OPENAI_API_KEY-a1b2c3d4e5f6";
    const files = [{ path: "dist/assets/index.js", content: `fetch(u,{headers:{Authorization:"Bearer ${ph}"}})` }];
    expect(bundleLeakFindings({ [ph]: ["dist/assets/index.js"] }, { OPENAI_API_KEY: ph })[0]!.severity).toBe("critical");
    expect(scanFiles(F(files), { framework: "nextjs", bundle: true })).toEqual([]);
  });

  it("does not flag public-by-design vars (Sentry DSN, Firebase/Maps keys) but does flag public secrets", () => {
    const names = ["NEXT_PUBLIC_SENTRY_DSN", "NEXT_PUBLIC_FIREBASE_API_KEY", "NEXT_PUBLIC_GOOGLE_MAPS_API_KEY", "NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "VITE_STRIPE_PUBLISHABLE_KEY"];
    const planted = Object.fromEntries(names.map((n, i) => [n, `AKIAVIBE${String(i).repeat(18)}`]));
    const found = Object.fromEntries(Object.values(planted).map((v) => [v, ["a.js"]]));
    expect(bundleLeakFindings(found, planted)).toEqual([]);
    const sec = { NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY: "AKIAVIBE999999999999999999" };
    expect(bundleLeakFindings({ AKIAVIBE999999999999999999: ["a.js"] }, sec)[0]!.severity).toBe("critical");
  });

  it("bundle secret findings use bundle evidence", () => {
    const hits = scanFiles(F([{ path: "dist/assets/index.js", content: `x="${STRIPE_LIVE}"` }]), { framework: "", bundle: true });
    const f = Finding.parse(secretFindings(hits, { bundle: true })[0]);
    expect(f.title).toContain("built client bundle");
    expect(f.evidence[0]!.kind).toBe("bundle");
  });
});

describe("review fixes", () => {
  it("matches credential names that start with the keyword, and skips non-secret names", () => {
    const v = "Zx9qP2mL7vR4tY8wQ1";
    const src = [
      `password: "${v}",`,
      `const apiKey = "${v}";`,
      `token = "${v}"`,
      `"secret": "${v}"`,
      `const passwordHash = "$2b$10$${v}";`,
      `const TOKEN_URL = "${v}";`,
      `const tokenizerName = "${v}";`,
    ].join("\n");
    const hits = scanFiles(F([{ path: "server.js", content: src }]), { framework: "express" });
    expect(hits.map((h) => h.line)).toEqual([1]); // same value: one hit, on the first line
    expect(maskSecrets(`const apiKey = "${v}";`)).not.toContain(v);
    expect(maskSecrets(`const TOKEN_URL = "${v}";`)).toContain(v);
  });

  it("does not treat a bare PEM header in code as a key, nor wipe the rest of the file", () => {
    const code = `if (pem.startsWith("-----BEGIN PRIVATE KEY-----")) {\n  key = pem.replace("-----BEGIN PRIVATE KEY-----", "");\n}\nconst rest = 1;`;
    expect(scanFiles(F([{ path: "lib/fb.ts", content: code }]), { framework: "nextjs" })).toEqual([]);
    expect(maskSecrets(code)).toBe(code);
    const real = `const k = "-----BEGIN PRIVATE KEY-----\\n${"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC".repeat(3)}\\n-----END PRIVATE KEY-----";`;
    expect(scanFiles(F([{ path: "lib/fb.ts", content: real }]), { framework: "nextjs" })[0]!.rule.id).toBe("private_key");
    expect(maskSecrets(real)).not.toContain("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC");
  });

  it("does not flag public-by-design .env values", () => {
    const env = "NEXT_PUBLIC_SENTRY_DSN=Zx9qP2mL7vR4tY8wQ1abc\nAUTH_GOOGLE_ID=12345abcdefZx9qP2mL7\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=Zx9qP2mL7vR4tY8wQ1xyz";
    const hits = scanFiles(F([{ path: ".env", content: env }]), { framework: "nextjs" });
    expect(hits.map((h) => [h.line, h.where])).toEqual([[3, "browser"]]);
  });
});

describe("in-sandbox walker", () => {
  it("is valid JS, returns candidate lines only, finds markers, skips deps/lockfiles, and stays in budget", async () => {
    const { mkdtemp, mkdir, writeFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { execFileSync } = await import("node:child_process");
    const dir = await mkdtemp(join(tmpdir(), "va-walk-"));
    try {
      await mkdir(join(dir, "node_modules/x"), { recursive: true });
      await mkdir(join(dir, "src"), { recursive: true });
      await writeFile(join(dir, ".env"), "PORT=3000\nSESSION_SECRET=abc\n");
      await writeFile(join(dir, "package-lock.json"), `{"token":"${"z".repeat(50)}"}`);
      await writeFile(join(dir, "node_modules/x/i.js"), `const secret = "${STRIPE_LIVE}"`);
      await writeFile(join(dir, "src/a.ts"), `"use client";\nconst x = 1;\nconst k = "${STRIPE_LIVE}";\n`);
      await writeFile(join(dir, "src/db.ts"), `const x = 1;\nconst u = "mysql://root:Q7w8E9r0T1y2@10.0.0.5/db";\n`);
      await writeFile(join(dir, "src/big.js"), `${"a=1;".repeat(5000)}var t="${STRIPE_LIVE}";${"b=2;".repeat(5000)}AKIAVIBEMARKER0000000000\n`);
      for (let i = 0; i < 300; i++) await writeFile(join(dir, `src/f${i}.js`), `const token = "${"q".repeat(1500)}";\n`);
      const out = execFileSync(process.execPath, ["-e", (await import("./secrets")).scanScript(["."], false, ["AKIAVIBEMARKER0000000000"])], { cwd: dir, maxBuffer: 256 * 1024 }).toString();
      expect(out.length).toBeLessThan(256 * 1024);
      const { parseCollected } = await import("./secrets");
      const got = parseCollected(out, ["AKIAVIBEMARKER0000000000"]);
      expect(got.partial).toBe(true); // 300 x 1.5 KB candidate lines exceed the budget
      const paths = got.files.map((f) => f.path.replace(/\\/g, "/"));
      expect(paths[0]).toBe(".env"); // root files first
      expect(paths).not.toContain("package-lock.json");
      expect(paths.some((p) => p.startsWith("node_modules"))).toBe(false);
      const a = got.files.find((f) => f.path.replace(/\\/g, "/") === "src/a.ts")!;
      expect(a.client).toBe(true);
      expect(a.lines.map(([n]) => n)).toEqual([3]);
      expect(got.files.find((f) => f.path.replace(/\\/g, "/") === "src/db.ts")!.lines.map(([n]) => n)).toEqual([2]);
      const big = got.files.find((f) => f.path.replace(/\\/g, "/") === "src/big.js")!;
      expect(big.lines[0]![1].length).toBeLessThanOrEqual(600);
      expect(big.lines[0]![1]).toContain(STRIPE_LIVE);
      expect(got.found["AKIAVIBEMARKER0000000000"]).toEqual([expect.stringContaining("big.js")]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("parseCollected drops bad items instead of the whole scan, and ignores unplanted markers", async () => {
    const { parseCollected } = await import("./secrets");
    const good = { p: "a.js", c: 0, l: [[1, "x"]] };
    const got = parseCollected(JSON.stringify({ files: [good, { p: 5 }, { p: "b.js", c: 0, l: [[0, "bad line no"]] }], found: { M: ["a.js"], EVIL: ["b"] }, t: 0 }), ["M"]);
    expect(got.files.map((f) => f.path)).toEqual(["a.js"]);
    expect(got.found).toEqual({ M: ["a.js"] });
    expect(parseCollected('{"files":[', []).partial).toBe(true);
  });
});

describe("connection URLs", () => {
  it("flags a real password in a connection URL, in .env and in code, and masks it", () => {
    const url = "postgres://app:Zx9qP2mL7vR4@db.example.com:5432/app";
    const hits = scanFiles(
      F([
        { path: ".env", content: `DATABASE_URL=${url}` },
        { path: "lib/db.ts", content: `const u = "mysql://root:Q7w8E9r0T1y2@10.0.0.5/db";` },
      ]),
      { framework: "nextjs" },
    );
    expect(hits.map((h) => [h.rule.id, h.where])).toEqual([
      ["url_creds", "env"],
      ["url_creds", "server"],
    ]);
    expect(maskSecrets(`DATABASE_URL=${url}`)).not.toContain("Zx9qP2mL7vR4");
  });
});

describe("EXAMPLE_FILE", () => {
  it("matches example env files but not real ones", () => {
    for (const p of [".env.example", ".env.sample", ".env.template", "examples/a.js", "src/a.test.ts"]) expect(EXAMPLE_FILE.test(p), p).toBe(true);
    for (const p of [".env", ".env.local", ".env.production", "src/app.ts"]) expect(EXAMPLE_FILE.test(p), p).toBe(false);
  });
});

describe("round-2 review regressions", () => {
  const runWalker = async (setup: (dir: string, w: (p: string, c: string) => Promise<void>) => Promise<void>, roots: string[], bundle: boolean, markers: string[] = []) => {
    const { mkdtemp, mkdir, writeFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join, dirname } = await import("node:path");
    const { execFileSync } = await import("node:child_process");
    const { scanScript, parseCollected } = await import("./secrets");
    const dir = await mkdtemp(join(tmpdir(), "va-walk2-"));
    try {
      await setup(dir, async (p, c) => {
        await mkdir(dirname(join(dir, p)), { recursive: true });
        await writeFile(join(dir, p), c);
      });
      // Same cap the real sandbox exec has: overflowing it throws (ENOBUFS), failing the test.
      const out = execFileSync(process.execPath, ["-e", scanScript(roots, bundle, markers)], { cwd: dir, maxBuffer: 256 * 1024 }).toString();
      return parseCollected(out, markers);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  };

  it("stays under the stdout cap with escape-heavy lines, deep paths, and empty .env lines", async () => {
    const got = await runWalker(async (_d, w) => {
      for (let i = 0; i < 60; i++) await w(`src/e${i}.js`, `const token = "${"\x01".repeat(1900)}";\n`);
      for (let i = 0; i < 1500; i++) await w(`${"deep/".repeat(10)}d${i}/x.ts`, `const apiKey = "Zx9qP2mL7vR4tY8wQ1";\n`);
      for (let i = 0; i < 200; i++) await w(`envs/e${i}/.env`, "\n".repeat(200));
    }, ["."], false);
    expect(got.partial).toBe(true);
    expect(got.files.length).toBeGreaterThan(0);
  }, 60_000);

  it("bundle: finds a key at the end of a noisy minified chunk, and markers after the budget runs out", async () => {
    const got = await runWalker(async (_d, w) => {
      for (let i = 0; i < 30; i++) await w(`.next/static/chunks/c${i}.js`, Array.from({ length: 300 }, () => `x.auth.token=eyJnope;${"a".repeat(900)}`).join(""));
      await w(".next/static/chunks/zz.js", `${"auth;".repeat(2000)}var k="${STRIPE_LIVE}";var m="AKIAVIBEFEEDFACE00112233";`);
    }, [".next/static"], true, ["AKIAVIBEFEEDFACE00112233"]);
    expect(got.found["AKIAVIBEFEEDFACE00112233"]).toEqual([expect.stringContaining("zz.js")]);
    const hits = scanFiles(got.files, { framework: "nextjs", bundle: true });
    expect(hits.some((h) => h.rule.id === "stripe_live")).toBe(true);
  }, 60_000);

  it("window chaining doesn't cut a key that starts inside the previous window", async () => {
    // The "token" window [t-200, t+400] ends mid-key; the key's own hit must open a new window.
    const line = `${"q".repeat(3000)} token${"z".repeat(380)} "${STRIPE_LIVE}" ${"q".repeat(3000)}`;
    const got = await runWalker(async (_d, w) => w("src/min.js", `x=1;${line}`), ["."], false);
    expect(scanFiles(got.files, { framework: "express" }).some((h) => h.rule.id === "stripe_live")).toBe(true);
  }, 30_000);

  it("masking is linear on adversarial input", () => {
    for (const input of ["token".repeat(50_000), ("-eyJ" + "a".repeat(10)).repeat(18_000), "sk-".repeat(80_000), ("://" + ":".repeat(1000)).repeat(200), "-----BEGIN PRIVATE KEY-----".repeat(9000)]) {
      const t = Date.now();
      maskSecrets(input);
      expect(Date.now() - t, input.slice(0, 20)).toBeLessThan(1500);
    }
  });

  it("keeps canary proof visible in probe evidence", () => {
    const body = `{"SESSION_SECRET":"AKIAVIBE0123456789ABCDEF01"}\nSESSION_SECRET=AKIAVIBE0123456789ABCDEF01`;
    expect(maskSecrets(body)).toBe(body);
  });

  it("does not flag storage keys, event names, versions or csrf tokens", () => {
    const src = [
      `const AUTH_TOKEN_KEY = "app_auth_token_v2";`,
      `const TOKEN_STORAGE = "myapp.auth.token.v3";`,
      `const tokenizer_version = "v2.1.0-beta3abc";`,
      `const csrfToken = "a1b2c3d4e5f6a7b8";`,
      `const SESSION_KEY = "Zx9qP2mL7vR4tY8wQ1";`,
    ].join("\n");
    expect(scanFiles(F([{ path: "src/a.ts", content: src }]), { framework: "nextjs" })).toEqual([]);
    // but a real one still is
    expect(scanFiles(F([{ path: "src/a.ts", content: `const STRIPE_SECRET_KEY = "Zx9qP2mL7vR4tY8wQ1";` }]), { framework: "nextjs" })).toHaveLength(1);
  });

  it("masks only the password of a connection URL, and finds npm tokens", () => {
    expect(maskSecrets("postgres://app:Zx9qP2mL7vR4@db.example.com:5432/app")).toMatch(/^postgres:\/\/app:.*\[redacted 12 chars\]@db\.example\.com:5432\/app$/);
    const npmrc = `//registry.npmjs.org/:_authToken=${k("npm_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")}`;
    expect(scanFiles(F([{ path: ".npmrc", content: npmrc }]), { framework: "express" })[0]!.rule.id).toBe("npm_token");
  });
});

describe("round-3 review regressions", () => {
  it("sends and finds `export KEY=` lines in .env", async () => {
    const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { execFileSync } = await import("node:child_process");
    const { scanScript, parseCollected } = await import("./secrets");
    const dir = await mkdtemp(join(tmpdir(), "va-walk3-"));
    try {
      await writeFile(join(dir, ".env"), `export STRIPE_SECRET_KEY=${STRIPE_LIVE}\n`);
      const got = parseCollected(execFileSync(process.execPath, ["-e", scanScript(["."], false, [])], { cwd: dir }).toString(), []);
      expect(scanFiles(got.files, { framework: "express" })[0]!.rule.id).toBe("stripe_live");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not mistake UUID-style or prefixed random keys for identifiers", () => {
    const src = [
      `apiKey = "d3b07384-d9a0-4c9b-8f3e-1a2b3c4d5e6f";`,
      `MAILGUN_API_KEY = "key-3ax6xnjp29jd6fds4gc373sgvjxteol0";`,
      `const AUTH_KEY = "k3J9sd8fLq2mZx7Pv1Qw";`,
      `const JWT_SIGNING_KEY = "Q9w8E7r6T5y4U3i2O1p0";`,
      `const ENCRYPTION_KEY = "Z1x2C3v4B5n6M7a8S9d0";`,
    ];
    const hits = scanFiles(F([{ path: "server.js", content: src.join("\n") }]), { framework: "express" });
    expect(hits.map((h) => h.line)).toEqual([1, 2, 3, 4, 5]);
    for (const l of src) expect(maskSecrets(l)).toContain("[redacted");
  });

  it("finds npm tokens in code and uppercase connection-URL schemes in bundles", () => {
    expect(scanFiles(F([{ path: "src/a.js", content: `const t = "${k("npm_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")}";` }]), { framework: "express" })[0]!.rule.id).toBe("npm_token");
    expect(scanFiles(F([{ path: "dist/a.js", content: `u="Postgres://app:Zx9qP2mL7vR4@db.example.com/x"` }]), { framework: "vite", bundle: true })[0]!.rule.id).toBe("url_creds");
  });
});

describe("round-4 lows", () => {
  it("does not report env-var-name values or algorithm names", () => {
    const src = [`const encryptionKeyEnv = "ENCRYPTION_KEY_V2";`, `const hmacSha256 = "HmacSHA256Base64";`, `const hmacAlgorithm = "sha256WithRSAEncryption";`].join("\n");
    expect(scanFiles(F([{ path: "server.js", content: src }]), { framework: "express" })).toEqual([]);
  });
});
