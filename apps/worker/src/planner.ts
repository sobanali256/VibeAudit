import { ENV_VAR_RE, KEY_PROVIDERS } from "@vibeaudit/shared";

/**
 * Heuristic planner. Decides how to install/build/run a repo from its package.json and which
 * lockfiles are present. This is a pure function of content the SANDBOX returned (VM 1 never
 * opens the repo), so it only parses data — it never evals or shell-execs any of it.
 *
 * An LLM planner can refine this later, but the hosts a test key is scoped to are ALWAYS from
 * KEY_PROVIDERS, never from the model or the repo.
 */

export interface Manifest {
  /** Parsed root package.json (already JSON.parsed from sandbox output). */
  packageJson: Record<string, unknown>;
  /** Lockfile basenames present at the repo root. */
  lockfiles: string[];
  /** Names of .env / .env.* files present at the repo root (committed-secret signal). */
  envFiles?: string[];
}

export type Framework = "nextjs" | "vite" | "express" | "unknown";
export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";

export interface Plan {
  framework: Framework;
  packageManager: PackageManager;
  installCommand: string;
  buildCommand: string | null;
  startCommand: string | null;
  port: number | null;
  /** Env var names the app reads, with how the sandbox should provide each. */
  env: { name: string; provide: "canary" | "placeholder" | "empty" }[];
}

const asRecord = (v: unknown): Record<string, string> =>
  v && typeof v === "object" ? (v as Record<string, string>) : {};

// package.json "main" is interpolated into a shell command run in the sandbox. Even though
// that shell is inside gVisor (contained), only accept a plain repo-relative path so a crafted
// "main" can't inject extra commands or escape the repo dir.
function isSafeRelPath(p: string): boolean {
  return /^[A-Za-z0-9._/-]{1,200}$/.test(p) && !p.startsWith("/") && !p.split("/").includes("..");
}

// Exact lockfile names (an unanchored /lock/ would treat e.g. mylock.txt as a lockfile).
const LOCKFILES = new Set(["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"]);

function detectPackageManager(lockfiles: string[], pkg: Record<string, unknown>): PackageManager {
  const pm = typeof pkg.packageManager === "string" ? pkg.packageManager : "";
  if (lockfiles.includes("pnpm-lock.yaml") || pm.startsWith("pnpm")) return "pnpm";
  if (lockfiles.includes("yarn.lock") || pm.startsWith("yarn")) return "yarn";
  if (lockfiles.includes("bun.lockb") || lockfiles.includes("bun.lock") || pm.startsWith("bun")) return "bun";
  return "npm";
}

function detectFramework(deps: Record<string, string>, scripts: Record<string, string>): Framework {
  if (deps.next) return "nextjs";
  const scriptText = Object.values(scripts).join(" ");
  if (/\bnext\b/.test(scriptText)) return "nextjs";
  if (deps.vite || /\bvite\b/.test(scriptText)) return "vite";
  if (deps.express || deps.fastify || deps.koa || deps["@hapi/hapi"]) return "express";
  return "unknown";
}

const INSTALL: Record<PackageManager, string> = {
  npm: "npm install --no-audit --no-fund",
  pnpm: "pnpm install --no-frozen-lockfile",
  yarn: "yarn install --non-interactive",
  bun: "bun install",
};
const CI_INSTALL: Partial<Record<PackageManager, string>> = {
  npm: "npm ci --no-audit --no-fund",
  pnpm: "pnpm install --frozen-lockfile",
};

/** Guess which env vars the app expects from the bundle's dependencies + any committed .env. */
function detectEnv(
  deps: Record<string, string>,
  envFiles: string[] | undefined,
  declaredEnvNames: string[],
): Plan["env"] {
  const names = new Set<string>(declaredEnvNames.filter((n) => ENV_VAR_RE.test(n)));
  // Dependencies that imply a provider key.
  if (deps.openai) names.add("OPENAI_API_KEY");
  if (deps["@anthropic-ai/sdk"]) names.add("ANTHROPIC_API_KEY");
  if (deps.stripe) names.add("STRIPE_SECRET_KEY");
  if (deps["@google/generative-ai"] || deps["@google/genai"]) names.add("GEMINI_API_KEY");
  return [...names].map((name) => ({
    name,
    // Offer a real test key only for providers we know the host for; otherwise a canary stub.
    provide: Object.hasOwn(KEY_PROVIDERS, name) ? "placeholder" : "canary",
  }));
}

export function planFromManifest(m: Manifest, opts: { declaredEnvNames?: string[] } = {}): Plan {
  const pkg = m.packageJson ?? {};
  const scripts = asRecord(pkg.scripts);
  const deps = { ...asRecord(pkg.dependencies), ...asRecord(pkg.devDependencies) };
  const pm = detectPackageManager(m.lockfiles, pkg);
  const framework = detectFramework(deps, scripts);

  const hasLock = m.lockfiles.some((f) => LOCKFILES.has(f));
  const install = (hasLock && CI_INSTALL[pm]) || INSTALL[pm];

  const run = pm === "npm" ? "npm run" : pm; // `npm run build` vs `pnpm build`
  const buildCommand = scripts.build ? `${run} build` : framework === "nextjs" ? `${run} build` : null;

  let startCommand: string | null = null;
  if (scripts.start) startCommand = `${run} start`;
  else if (framework === "nextjs") startCommand = `${run} start`;
  else if (typeof pkg.main === "string" && isSafeRelPath(pkg.main)) startCommand = `node ${pkg.main}`;
  else startCommand = framework === "express" ? "node server.js" : null;

  const port = framework === "nextjs" || framework === "vite" ? 3000 : 3000;

  return {
    framework,
    packageManager: pm,
    installCommand: install,
    buildCommand,
    startCommand,
    port,
    env: detectEnv(deps, m.envFiles, opts.declaredEnvNames ?? []),
  };
}
