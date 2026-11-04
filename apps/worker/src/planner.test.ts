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
  });

  it("falls back to node main for a plain server, and unknown with no runner", () => {
    expect(planFromManifest(m({ main: "app.js", dependencies: {} })).startCommand).toBe("node app.js");
    const unknown = planFromManifest(m({ dependencies: {} }));
    expect(unknown.framework).toBe("unknown");
    expect(unknown.startCommand).toBeNull();
  });

  it("maps known provider deps to placeholder env, unknown to canary", () => {
    const p = planFromManifest(m({ dependencies: { express: "4", openai: "6", stripe: "18" } }), { declaredEnvNames: ["CUSTOM_THING"] });
    const byName = Object.fromEntries(p.env.map((e) => [e.name, e.provide]));
    expect(byName.OPENAI_API_KEY).toBe("placeholder");
    expect(byName.STRIPE_SECRET_KEY).toBe("placeholder");
    expect(byName.CUSTOM_THING).toBe("canary");
  });

  it("uses a bootstrap install without a lockfile", () => {
    expect(planFromManifest(m({ dependencies: { express: "4" } }, [])).installCommand).toContain("npm install");
  });
});
