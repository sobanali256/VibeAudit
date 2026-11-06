import { describe, expect, it } from "vitest";
import { planFromManifest } from "./planner";

const m = (packageJson: Record<string, unknown>, lockfiles: string[] = [], envFiles: string[] = []) => ({
  packageJson,
  lockfiles,
  envFiles,
});

describe("planFromManifest", () => {
  it("detects an Express app with npm", () => {
    const p = planFromManifest(m({ main: "server.js", dependencies: { express: "4" }, scripts: { start: "node server.js" } }, ["package-lock.json"]));
    expect(p.framework).toBe("express");
    expect(p.packageManager).toBe("npm");
    expect(p.installCommand).toContain("npm ci");
    expect(p.buildCommand).toBeNull();
    expect(p.startCommand).toBe("npm run start");
  });

  it("detects Next.js + pnpm from the lockfile", () => {
    const p = planFromManifest(m({ dependencies: { next: "16" }, scripts: { build: "next build", start: "next start" } }, ["pnpm-lock.yaml"]));
    expect(p.framework).toBe("nextjs");
    expect(p.packageManager).toBe("pnpm");
    expect(p.installCommand).toBe("pnpm install --frozen-lockfile");
    expect(p.buildCommand).toBe("pnpm build");
    expect(p.startCommand).toBe("pnpm start");
  });

  it("detects Vite and yarn", () => {
    const p = planFromManifest(m({ devDependencies: { vite: "5" }, scripts: { build: "vite build", preview: "vite preview" } }, ["yarn.lock"]));
    expect(p.framework).toBe("vite");
    expect(p.packageManager).toBe("yarn");
    expect(p.installCommand).toContain("yarn install");
    // No start script: preview, bound to all interfaces on the planned port.
    expect(p.startCommand).toBe("yarn run preview --host 0.0.0.0 --port 3000 --strictPort");
    expect(p.port).toBe(3000);
  });

  it("starts a Vite app via preview (npm needs --), or vite itself with no preview script", () => {
    const npm = planFromManifest(m({ devDependencies: { vite: "7" }, scripts: { build: "vite build", preview: "vite preview" } }, ["package-lock.json"]));
    expect(npm.startCommand).toBe("npm run preview -- --host 0.0.0.0 --port 3000 --strictPort");
    const bare = planFromManifest(m({ devDependencies: { vite: "7" }, scripts: { build: "vite build" } }));
    expect(bare.startCommand).toBe("npx --no-install vite preview --host 0.0.0.0 --port 3000 --strictPort");
    // Without a preview script, each package manager's own exec form (Yarn PnP has no .bin).
    expect(planFromManifest(m({ devDependencies: { vite: "7" } }, ["pnpm-lock.yaml"])).startCommand).toBe("pnpm exec vite preview --host 0.0.0.0 --port 3000 --strictPort");
    expect(planFromManifest(m({ devDependencies: { vite: "7" } }, ["yarn.lock"])).startCommand).toBe("yarn vite preview --host 0.0.0.0 --port 3000 --strictPort");
    // A full-stack app with its own server runs the server, not preview.
    expect(planFromManifest(m({ main: "server.js", dependencies: { express: "4" }, devDependencies: { vite: "7" }, scripts: { build: "vite build" } })).startCommand).toBe("node server.js");
    // An explicit start script still wins.
    expect(planFromManifest(m({ devDependencies: { vite: "7" }, scripts: { start: "node server.js" } })).startCommand).toBe("npm run start");
  });

  it("falls back to node main for a plain server, and unknown with no runner", () => {
    expect(planFromManifest(m({ main: "app.js", dependencies: {} })).startCommand).toBe("node app.js");
    const unknown = planFromManifest(m({ dependencies: {} }));
    expect(unknown.framework).toBe("unknown");
    expect(unknown.startCommand).toBeNull();
  });

  it("maps known provider deps to placeholder env, unknown to canary", () => {
    const p = planFromManifest(m({ dependencies: { express: "4", openai: "6", stripe: "18" } }), { declaredEnvNames: ["CUSTOM_SECRET", "CUSTOM_THING"] });
    const byName = Object.fromEntries(p.env.map((e) => [e.name, e.provide]));
    expect(byName.OPENAI_API_KEY).toBe("placeholder");
    expect(byName.STRIPE_SECRET_KEY).toBe("placeholder");
    expect(byName.CUSTOM_SECRET).toBe("canary");
    expect(byName.CUSTOM_THING).toBe("empty");
  });

  it("fakes addresses and public keys, leaves modes unset, caps and filters declared names", () => {
    const p = planFromManifest(m({ dependencies: { express: "4" } }), {
      declaredEnvNames: [
        "DATABASE_URL", "REDIS_HOST", "API_BASE", "SUPABASE_ANON_KEY", "JWT_SECRET", "LOG_LEVEL", "bad-name", "lower",
        "OPENAI_MODEL", "JWT_EXPIRES_IN", "MAX_TOKENS", "CI", "ENABLE_SIGNUP", "RESEND_KEY", "SUPABASE_SERVICE_ROLE_KEY",
        "NEXT_PUBLIC_SUPABASE_ANON_KEY", "NEXT_PUBLIC_APP_NAME", "SESSION_SECRET", "DB_PASSWORD", "MONGODB_URI", "SMTP_PASS",
      ],
    });
    const byName = Object.fromEntries(p.env.map((e) => [e.name, e.provide]));
    expect(byName).toEqual({
      DATABASE_URL: "fake", REDIS_HOST: "empty", API_BASE: "empty", SUPABASE_ANON_KEY: "canary", JWT_SECRET: "canary", LOG_LEVEL: "empty",
      OPENAI_MODEL: "empty", JWT_EXPIRES_IN: "empty", MAX_TOKENS: "empty", CI: "empty", ENABLE_SIGNUP: "empty", RESEND_KEY: "canary",
      SUPABASE_SERVICE_ROLE_KEY: "canary", NEXT_PUBLIC_SUPABASE_ANON_KEY: "fake", NEXT_PUBLIC_APP_NAME: "empty", SESSION_SECRET: "canary",
      DB_PASSWORD: "canary", MONGODB_URI: "fake", SMTP_PASS: "canary",
    });
    const many = planFromManifest(m({ dependencies: { openai: "6" } }), { declaredEnvNames: Array.from({ length: 100 }, (_, i) => `SECRET_${i}`) });
    // 60 declared + the provider key the SDK implies (always kept).
    expect(many.env).toHaveLength(61);
    expect(many.env.some((e) => e.name === "OPENAI_API_KEY")).toBe(true);
  });

  it("uses a bootstrap install without a lockfile, and ignores lookalike filenames", () => {
    expect(planFromManifest(m({ dependencies: { express: "4" } }, [])).installCommand).toContain("npm install");
    // "mylock.txt" is not a real lockfile, so it must not trigger the CI (frozen) path.
    expect(planFromManifest(m({ dependencies: { express: "4" } }, ["mylock.txt"])).installCommand).toContain("npm install");
  });

  it("refuses an unsafe package.json main (no shell injection into the sandbox start cmd)", () => {
    expect(planFromManifest(m({ main: "server.js; rm -rf /", dependencies: {} })).startCommand).toBeNull();
    expect(planFromManifest(m({ main: "../../etc/passwd", dependencies: {} })).startCommand).toBeNull();
    expect(planFromManifest(m({ main: "src/index.js", dependencies: {} })).startCommand).toBe("node src/index.js");
  });
});
