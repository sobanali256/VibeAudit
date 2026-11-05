import { readFileSync } from "node:fs";
import { z } from "zod";
import type { Finding } from "@vibeaudit/shared";
import type { Sandbox } from "./sandbox";

// Install-script scan: read what `npm install` would run (the repo's own lifecycle hooks and
// every installed dependency's), and flag hostile behaviour from the code itself. It runs
// whether or not the audit allowed scripts, so "ignore scripts" can't make a malicious repo
// look clean: the hook never ran here, but it runs for anyone who installs the project.
//
// Collection happens in the sandbox (repo files are never opened on VM 1); everything it
// returns is untrusted text, parsed and capped here and only ever matched with bounded regexes.

/** Hooks a plain `npm install` / `pnpm install` of the project itself runs. */
export const ROOT_HOOKS = ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare", "dependencies", "pnpm:devPreinstall"];
/** Config files that make the package manager run code; reported under these keys. */
const ROOT_SURFACES = [".npmrc", ".pnpmfile.cjs", ".yarnrc.yml", "binding.gyp"];
/** Hooks npm runs when installing a dependency (prepare only runs for git deps). */
const DEP_HOOKS = ["preinstall", "install", "postinstall"];

/**
 * Budgets. `totalBytes` is measured as JSON-escaped output bytes (a control char escapes to six
 * bytes), checked before anything is added, and `hardBytes` stops the walk outright, so the
 * output always fits COLLECT_MAX_OUTPUT. Anything cut for any reason marks the package
 * `truncated`, so the caller can fail closed instead of trusting a scan that didn't see it all.
 */
const LIMITS = { perFile: 64_000, perCmd: 2_000, filesPerPkg: 12, maxPkgs: 60, totalBytes: 700_000, hardBytes: 850_000, maxReads: 20_000, maxDirs: 20_000, scriptDepth: 3, requireDepth: 3, deadlineMs: 40_000 };
export const COLLECT_MAX_OUTPUT = 1024 * 1024;

/** Commands that are tools, not repo code, and load no repo config: a step running one needs no file. */
const BENIGN_COMMANDS = [
  "husky", "node-gyp", "node-gyp-build", "node-pre-gyp", "prebuild-install", "tsc", "patch-package", "ngcc",
  "electron-rebuild", "lefthook", "simple-git-hooks", "is-ci", "opencollective-postinstall", "opencollective",
  "echo", "exit", "true", "false", ":", "rm", "mkdir", "cp", "mv", "test", "[", "chmod", "touch", "printf", "ln",
  "rimraf", "shx", "only-allow", "git", "corepack", "pod-install", "jetify",
];

/**
 * Tools that load (and so execute) repo config files: the step is resolved by reading those.
 * Prisma reads prisma/schema.prisma (collected separately; non-client generators are flagged).
 */
const TOOL_CONFIGS: Record<string, string[]> = {
  next: ["next.config"], vite: ["vite.config"], nuxt: ["nuxt.config"], nuxi: ["nuxt.config"], astro: ["astro.config"],
  "svelte-kit": ["svelte.config"], panda: ["panda.config"], contentlayer: ["contentlayer.config"], tsup: ["tsup.config"],
  playwright: ["playwright.config"], cypress: ["cypress.config"], "fumadocs-mdx": ["source.config"],
  "graphql-codegen": ["codegen"], "electron-builder": ["electron-builder.config", "electron-builder"], prisma: [],
  wrangler: [], expo: ["app.config"], "react-native": ["react-native.config"], "relay-compiler": ["relay.config"],
  ng: [], ngx: [], esbuild: [], "ts-patch": [], webpack: ["webpack.config"], rollup: ["rollup.config"],
};

/**
 * Runs as `node -e` in the app container. The code lives in install-collect.cjs (plain JS, so
 * its regexes aren't double-escaped in a template string); its settings are prepended.
 */
export const INSTALL_COLLECT_SCRIPT =
  `const CFG=${JSON.stringify({ limits: LIMITS, benign: BENIGN_COMMANDS, toolConfigs: TOOL_CONFIGS, rootHooks: ROOT_HOOKS, depHooks: DEP_HOOKS })};\n` +
  readFileSync(new URL("./install-collect.cjs", import.meta.url), "utf8");

const Collected = z.object({
  pkgs: z.array(
    z.object({
      name: z.string().max(214),
      version: z.string().max(64),
      root: z.boolean(),
      /** Repo code: the root, or a local `file:` package living inside the repo. */
      local: z.boolean(),
      hooks: z.record(z.string(), z.string().max(LIMITS.perCmd)),
      files: z.array(z.object({ path: z.string().max(500), content: z.string().max(LIMITS.perFile) })).max(LIMITS.filesPerPkg),
      /** Something was cut (long hook, big file, file cap, depth, budget): the scan saw only part. */
      truncated: z.boolean(),
      /** Hook steps naming code the collector couldn't read (a bare bin, a missing file). */
      unresolved: z.array(z.string().max(200)).max(5),
    }),
  ).max(LIMITS.maxPkgs),
  partial: z.boolean(),
});
export type InstallPackage = z.infer<typeof Collected>["pkgs"][number];

export function parseCollected(stdout: string): { pkgs: InstallPackage[]; partial: boolean } | null {
  try {
    const r = Collected.safeParse(JSON.parse(stdout));
    if (!r.success) return null;
    // Only hooks we asked for: a planted key must not slip in as "code".
    for (const p of r.data.pkgs) {
      const allowed = p.root ? [...ROOT_HOOKS, ...ROOT_SURFACES] : DEP_HOOKS;
      p.hooks = Object.fromEntries(Object.entries(p.hooks).filter(([k]) => allowed.includes(k)));
    }
    return { pkgs: r.data.pkgs.filter((p) => Object.keys(p.hooks).length), partial: r.data.partial };
  } catch {
    return null;
  }
}

/** Collect the root's or the dependencies' install hooks from the sandbox. Never throws. */
export async function collectInstallScripts(sandbox: Sandbox, image: string, id: string, mode: "root" | "deps"): Promise<{ pkgs: InstallPackage[]; partial: boolean; why?: string }> {
  try {
    const r = await sandbox.run({
      role: "app",
      image,
      cmd: ["node", "-e", INSTALL_COLLECT_SCRIPT],
      env: { VA_MODE: mode },
      timeoutMs: 60_000,
      maxOutput: COLLECT_MAX_OUTPUT,
      name: `va-${id}-hooks-${mode}`,
    });
    const got = parseCollected(r.stdout);
    if (got) return got;
    return { pkgs: [], partial: true, why: `exit ${r.code}${r.timedOut ? ", timed out" : ""}` };
  } catch (e) {
    return { pkgs: [], partial: true, why: String((e as Error)?.message ?? e).slice(0, 200) };
  }
}

// ---------------------------------------------------------------- analysis (VM 1)

export type Signal = "env_harvest" | "credential_read" | "network" | "download_exec" | "obfuscation";

/** Bounded patterns only: the input is attacker-controlled text. */
const SIGNALS: Record<Signal, RegExp> = {
  env_harvest:
    /Object\.(?:keys|entries|values|getOwnPropertyNames)\(\s{0,10}process\.env\s{0,10}\)(?!\s{0,10}\.filter\(\s{0,10}\(?\s{0,10}\w{1,30}\s{0,10}\)?\s{0,10}=>\s{0,10}\/\^)|JSON\.stringify\(\s{0,10}process\.env\s{0,10}[,)]|\bfor\s{0,10}\(\s{0,10}(?:const|let|var)?\s{0,10}\w{1,40}\s{1,10}in\s{1,10}process\.env\s{0,10}\)|\bprintenv\b|(?:^|[\s;&|(`$])env\s{0,10}\|(?!\|)|\bset\s{0,10}\|\s{0,10}(?:curl|nc|base64)/,
  credential_read:
    /\.ssh\/|\bid_(?:rsa|ed25519|ecdsa)\b|\.npmrc\b|\.aws\/credentials|\.git-credentials|\.docker\/config\.json|\/etc\/(?:passwd|shadow)\b|\.bash_history|\.kube\/config|wallet\.dat|Local Storage\/leveldb|Login Data\b/,
  network:
    /require\(\s{0,10}["'](?:node:)?(?:net|dgram|tls|https?)["']\s{0,10}\)|from\s{1,10}["'](?:node:)?(?:net|dgram|tls|https?)["']|\bnet\.(?:connect|createConnection)\(|\bhttps?\.(?:request|get)\(|\bfetch\(|\bnew\s{1,10}WebSocket\(|\bdns\.(?:promises\.)?(?:lookup|resolve\w{0,10})\(|\bXMLHttpRequest\b|\b(?:curl|wget|ncat|netcat)\b|\bnc\s{1,10}-/,
  download_exec:
    /\b(?:curl|wget)\b[^\n|;]{0,300}\|\s{0,10}(?:ba|z|da)?sh\b|\b(?:curl|wget)\b[^\n;]{0,300}&&\s{0,10}(?:chmod\s{1,10}\+x|(?:ba)?sh\s)|powershell(?:\.exe)?\s{1,10}[^\n]{0,200}(?:IEX|Invoke-Expression|DownloadString)|\bInvoke-WebRequest\b/i,
  obfuscation:
    /\beval\s{0,10}\(\s{0,10}(?:atob|Buffer|unescape|decodeURIComponent|String\.fromCharCode|(?:require\(\s{0,10}["'](?:node:)?fs["']\s{0,10}\)\.|fs\.)?readFileSync)|new\s{1,10}Function\s{0,10}\(\s{0,10}(?:atob|Buffer)|Buffer\.from\([^)]{0,400}["'](?:base64|hex)["']\)\.toString\([^)]{0,40}\)\s{0,10}\)|["'`][A-Za-z0-9+/=]{400}|(?:\\x[0-9a-f]{2}){40}/i,
};

const SIGNAL_NAMES = Object.keys(SIGNALS) as Signal[];

export interface SignalHit {
  signal: Signal;
  file: string;
  line: number;
  snippet: string;
}

/** Every signal in a package's hook commands and the files they run (first hit per signal per file). */
/** Most text scanned per package (and see SCAN_BUDGET for the whole audit). */
const SCAN_PER_PACKAGE = 256_000;
export const SCAN_BUDGET = 1_500_000;

export function scanPackage(p: InstallPackage, budget = { left: SCAN_BUDGET }): SignalHit[] {
  return scan(p, budget).hits;
}

const WINDOW = 4000;
const STEP = 3500; // overlap, so a pattern straddling a window edge is still seen whole

/** Every signal in a package's hooks and files (first hit per signal per file); `cut` = budget ran out. */
function scan(p: InstallPackage, budget: { left: number }): { hits: SignalHit[]; cut: boolean } {
  const hits: SignalHit[] = [];
  let pkgLeft = SCAN_PER_PACKAGE;
  let cut = false;
  const sources = [
    ...Object.entries(p.hooks).map(([k, v]) => ({ file: `package.json (scripts.${k})`, content: v })),
    ...p.files.map((f) => ({ file: f.path, content: f.content })),
  ];
  for (const src of sources) {
    const take = Math.min(src.content.length, pkgLeft, budget.left);
    if (take < src.content.length) cut = true;
    if (take <= 0) break;
    pkgLeft -= take;
    budget.left -= take;
    const lines = src.content.slice(0, take).split("\n");
    const found = new Set<Signal>();
    for (let i = 0; i < lines.length && found.size < SIGNAL_NAMES.length; i++) {
      const line = lines[i]!;
      for (let at = 0; at < line.length || at === 0; at += STEP) {
        const w = line.slice(at, at + WINDOW);
        for (const sig of SIGNAL_NAMES) {
          if (found.has(sig) || !SIGNALS[sig].test(w)) continue;
          found.add(sig);
          hits.push({ signal: sig, file: src.file, line: i + 1, snippet: w.trim().slice(0, 240) });
        }
        if (at + WINDOW >= line.length) break;
      }
    }
  }
  return { hits, cut };
}

export interface InstallVerdict {
  severity: Finding["severity"];
  title: string;
  why: string;
}

/**
 * What a package's signals add up to. Secrets + a way out, or obfuscated code + a way out,
 * is what install-time malware looks like, so it is critical even unrun. A dependency that
 * only downloads (sharp, esbuild, puppeteer fetch binaries) is normal and isn't flagged; the
 * repo's own hook doing network I/O at install time is unusual enough to mention.
 */
export function judge(hits: readonly SignalHit[], root: boolean): InstallVerdict | null {
  const has = (s: Signal) => hits.some((h) => h.signal === s);
  const out = has("network") || has("download_exec");
  if ((has("env_harvest") || has("credential_read")) && out) {
    return { severity: "critical", title: "reads secrets and opens network connections", why: `It ${has("credential_read") ? "reads credential files" : "reads the whole environment (where API keys and tokens live)"} and makes network connections, the pattern of install-time credential theft.` };
  }
  if (has("obfuscation") && (out || has("env_harvest"))) {
    return { severity: "critical", title: "runs obfuscated code with network access", why: "It decodes and runs hidden code and can reach the network, a common way to smuggle a payload past review." };
  }
  if (has("download_exec")) {
    return { severity: "high", title: "downloads and runs code", why: "It fetches something from the internet and executes it, so what runs on install is whatever that server sends that day." };
  }
  if (!root) return null;
  if (has("env_harvest") || has("credential_read")) {
    return { severity: "medium", title: "reads secrets", why: "It reads the environment or credential files at install time, which an install step rarely needs." };
  }
  if (has("network")) {
    return { severity: "medium", title: "makes network connections", why: "It opens network connections during install, which most apps never need to do." };
  }
  if (has("obfuscation")) {
    return { severity: "medium", title: "contains obfuscated code", why: "It decodes and runs hidden code during install." };
  }
  return null;
}

/**
 * Findings for packages whose install hooks look hostile. `scriptsRan` says whether this audit
 * let them run (if it did, the containment log shows what happened when they tried).
 */
export function installScriptFindings(pkgs: readonly InstallPackage[], scriptsRan: boolean, start = 1): Finding[] {
  const out: Finding[] = [];
  const budget = { left: SCAN_BUDGET };
  for (const p of pkgs) {
    const { hits, cut } = scan(p, budget);
    // Repo code (the root, or a local file: package) gets the strict rules; registry packages
    // the lenient ones (a binary download is normal there; OSV covers known-bad versions).
    const v = judge(hits, p.root || p.local);
    // Fail closed for repo code: if the scan didn't see it all and found nothing critical,
    // say so instead of reporting it clean.
    if ((p.root || p.local) && v?.severity !== "critical" && (p.truncated || cut || p.unresolved.length)) {
      out.push(uncheckedFinding(p, `f-install-${start + out.length}`, cut));
    }
    if (!v) continue;
    const who = p.root ? "The repo's own install script" : `Dependency ${p.name}${p.version ? `@${p.version}` : ""}`;
    const hookList = Object.keys(p.hooks).join(", ");
    const ran = scriptsRan
      ? "This audit let it run inside the sandbox; the containment log shows what it tried."
      : "This audit ran with install scripts disabled, so it never executed here, but it runs for anyone who installs the project.";
    // Strongest evidence first: what makes it dangerous, then the hook itself.
    const order: Signal[] = ["credential_read", "env_harvest", "obfuscation", "download_exec", "network"];
    const ev = [...hits].sort((a, b) => order.indexOf(a.signal) - order.indexOf(b.signal)).slice(0, 4);
    out.push({
      id: `f-install-${start + out.length}`,
      severity: v.severity,
      category: "supply_chain",
      title: `${p.root ? "Install script" : `Dependency ${p.name}`} ${v.title}`,
      description: `${who} (${hookList}) ${v.title}. ${v.why} ${ran}`,
      confirmed: false,
      evidence: (ev.length ? ev : [{ signal: "network" as Signal, file: "package.json", line: 1, snippet: Object.values(p.hooks)[0] ?? "" }]).map((h) => ({ kind: "code" as const, file: p.root ? h.file : `node_modules/${p.name}/${h.file}`, line: h.line, snippet: h.snippet })),
      fix: p.root
        ? "Remove the install hook or reduce it to a plain build step. Nothing at install time should read the environment or talk to the network."
        : `Remove ${p.name} (or pin a known-good version) and rotate any credentials on machines that installed it.`,
      source: "install_scan",
    });
  }
  return out;
}

/** Install hooks a dependency would have run but didn't (ignore-scripts): context, not a finding. */
export function unrunHookSummary(pkgs: readonly InstallPackage[]): string {
  const names = pkgs.filter((p) => !p.root).map((p) => p.name);
  return names.length ? `${names.length} dependenc${names.length === 1 ? "y has" : "ies have"} install scripts: ${names.slice(0, 10).join(", ")}${names.length > 10 ? ", ..." : ""}` : "no dependency install scripts";
}

function uncheckedFinding(p: InstallPackage, id: string, cut: boolean): Finding {
  const why = [
    p.unresolved.length ? `it runs ${p.unresolved.map((u) => JSON.stringify(u)).join(", ")}, which the scan couldn't read` : "",
    p.truncated || cut ? "part of it was too large or too deep to read" : "",
  ].filter(Boolean).join(", and ");
  const who = p.root ? "The repo runs code on install" : `Local package ${p.name} runs code on install`;
  return {
    id,
    severity: "medium",
    category: "supply_chain",
    title: p.root ? "Install script could not be fully checked" : `Local package ${p.name}: install script not fully checked`,
    description: `${who} (${Object.keys(p.hooks).join(", ")}), but ${why}, so it may do things this audit didn't see. Read it before installing.`,
    confirmed: false,
    evidence: Object.entries(p.hooks).slice(0, 4).map(([k, v]) => ({ kind: "code" as const, file: `package.json (scripts.${k})`, snippet: v.slice(0, 240) })),
    fix: "Keep install hooks small and readable (a plain build step), or remove them.",
    source: "install_scan",
  };
}

/** The repo declares install hooks but nothing could be collected at all. Fail closed. */
export function unscannedRootFinding(hooks: Record<string, string>, id: string): Finding {
  return uncheckedFinding({ name: "(root)", version: "", root: true, local: true, hooks, files: [], truncated: true, unresolved: [] }, id, true);
}

/** The dependency scan stopped early (too many packages or too much code): say so. */
export function depsUncheckedFinding(id: string): Finding {
  return {
    id,
    severity: "low",
    category: "supply_chain",
    title: "Not every dependency install script could be checked",
    description: "The dependency tree has more install scripts (or more install-script code) than the scan reads in one audit, so some were not checked. Known-malicious versions are still caught by the advisory check.",
    confirmed: false,
    evidence: [{ kind: "code", file: "node_modules", snippet: "(install-script scan stopped at its budget)" }],
    fix: "Review which dependencies run install scripts (npm query ':attr(scripts, [postinstall])') and drop the ones you don't need.",
    source: "install_scan",
  };
}
