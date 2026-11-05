import { randomBytes } from "node:crypto";
import {
  type ApprovalRequest,
  type AuditStage,
  type ContainmentEntry,
  type Finding,
  KEY_PROVIDERS,
  type ProxyState,
  type Report,
  WORKSPACE_MOUNT,
  keyPlaceholder,
  MAX_ARCHIVE_ENTRIES,
  STAGE_TIMEOUTS_MS,
} from "@vibeaudit/shared";
import {
  type AuditRow,
  addEvent,
  finishAudit,
  getAudit,
  getSecrets,
  heartbeat,
  requestApproval,
  type Sql,
} from "@vibeaudit/db";
import { type Plan, planFromManifest } from "./planner";
import { collectSources, llmReview } from "./review";
import { type OsvClient, type PackageList, dependencyFindings, listPackages, mergePackageLists } from "./deps";
import { EXAMPLE_FILE, type SecretHit, bundleLeakFindings, bundleRoots, collectBundleFiles, collectRepoFiles, maskFinding, maskSecrets, scanFiles, secretFindings } from "./secrets";
import type { LlmClient } from "./llm";
import { openTarball, resolveRepo } from "./intake";
import { Sandbox, SandboxError } from "./sandbox";
import { clearProxyState, writeProxyState } from "./proxy-state";
import { type StageMark, egressFindings, mergeContainment, parseFirewallDrops, proxyLogOffset, readProxyEvents } from "./containment";

export interface PipelineDeps {
  sql: Sql;
  sandbox: Sandbox;
  proxyUrl: string;
  token?: string;
  appImage?: string;
  /** LLM client for the static review stage. Absent = skip the LLM review. */
  llm?: LlmClient;
  /** Advisory database for the dependency audit. Absent = skip it. */
  osv?: OsvClient;
  /** Poll interval while waiting for the human approval decision. */
  approvalPollMs?: number;
}

const APP_IMAGE = "node:22-bookworm-slim";
const APPROVAL_TTL_MS = 30 * 60_000;

const ev = (sql: Sql, id: string, kind: string, payload: Record<string, unknown> = {}) =>
  addEvent(sql, id, kind, payload);

class Cancelled extends Error {}

/**
 * Run one audit end to end. The caller (the loop) has already claimed it (status=running).
 * teardown + proxy-state clear happen in `finally`, so nothing outlives the audit even on
 * error. Repo code only ever runs inside the Sandbox (VM 2, gVisor); everything the sandbox
 * returns is untrusted and only ever parsed, never evaluated, here on VM 1.
 */
export async function runAudit(audit: AuditRow, deps: PipelineDeps): Promise<void> {
  const { sql, sandbox } = deps;
  const id = audit.id;
  const image = deps.appImage ?? APP_IMAGE;
  const findings: Finding[] = [];
  const startedAt = new Date().toISOString();
  let staticOnly = false;
  let staticReason: string | undefined;
  // Containment bookkeeping: where the proxy log stood when we began, when each stage started,
  // and any resource caps we hit.
  const windowStartMs = Date.now();
  const proxyOffset = await proxyLogOffset();
  const marks: StageMark[] = [];
  const limitHits: ContainmentEntry[] = [];
  let containment: ContainmentEntry[] | undefined;
  const enter = async (name: AuditStage) => {
    marks.push({ stage: name, at: Date.now() });
    await stage(sql, id, name);
  };
  const limitHit = (st: AuditStage, detail: string) =>
    limitHits.push({ source: "limit", at: new Date().toISOString(), stage: st, limit: "stage_timeout", detail });

  const beat = setInterval(() => void heartbeat(sql, id).catch(() => {}), 20_000);

  try {
    if (audit.source.kind !== "github") throw new Error("only github sources are supported so far");

    // --- intake: resolve ref, stream the tarball into the sandbox (VM 1 never opens it) ---
    await enter("intake");
    const resolved = await resolveRepo({ owner: audit.source.owner, repo: audit.source.repo, ref: audit.source.ref, subpath: audit.source.subpath }, { token: deps.token });
    await ev(sql, id, "log", { stage: "intake", msg: `resolved ${audit.source.owner}/${audit.source.repo}@${resolved.ref}` });
    await sandbox.setup();
    const { stream, done } = await openTarball(resolved, { token: deps.token });
    const unpack = await sandbox.run({
      role: "app",
      image,
      // busybox-free: use tar from the node image (GNU tar). Count entries after, fail on bomb.
      cmd: ["bash", "-lc", `tar -xzf - --strip-components=1 -C ${WORKSPACE_MOUNT}/app && find ${WORKSPACE_MOUNT}/app | head -n ${MAX_ARCHIVE_ENTRIES + 1} | wc -l`],
      input: stream,
      timeoutMs: 120_000,
      name: `va-${id}-unpack`,
    });
    const bytes = await done.catch((e) => {
      throw new Error(`tarball download failed: ${e.message}`);
    });
    if (unpack.code !== 0) throw new Error(`unpack failed: ${unpack.stderr.trim().slice(0, 300)}`);
    if (Number(unpack.stdout.trim()) > MAX_ARCHIVE_ENTRIES) throw new Error("archive has too many entries");
    await ev(sql, id, "log", { stage: "intake", msg: `unpacked ${bytes} bytes` });

    // --- plan: read the manifest from the sandbox, decide how to run it ---
    await enter("plan");
    const manifest = await readManifest(sandbox, image, id);
    const plan = planFromManifest(manifest);
    await ev(sql, id, "log", { stage: "plan", msg: `framework=${plan.framework} pm=${plan.packageManager}` });
    if (plan.framework === "unknown" || !plan.startCommand) {
      staticOnly = true;
      staticReason = "could not determine how to run this project";
    }

    // --- approve: park for the human, then act on the decision ---
    await enter("approve");
    const canaries = planCanaries(plan, id);
    const req = buildApprovalRequest(id, plan, manifest);
    await requestApproval(sql, id, req);
    await ev(sql, id, "awaiting_approval", { requestId: req.requestId });
    const decided = await waitForDecision(sql, id, deps.approvalPollMs ?? 2000, Date.parse(req.expiresAt));
    if (decided.status === "cancelled") throw new Cancelled();
    const decision = decided.approval_decision!;
    if (decision.decision === "static_only") {
      staticOnly = true;
      staticReason = "user chose a static-only audit";
    }
    const ignoreScripts = decision.decision === "approve" ? decision.ignoreScripts : true;
    const testKeys = decision.decision === "approve" ? await getSecrets(sql, id) : {};

    // --- static: review the repo source (before install, so no node_modules noise). Always
    // runs, even for a static-only audit. Best effort: a review failure never fails the audit. ---
    await enter("static");
    // Package list from the committed lockfile, taken before any repo code runs: install
    // scripts could later rewrite the lockfiles to hide a malicious package.
    const depsBefore = deps.osv ? await listPackages(sandbox, image, id, "deps-pre").catch(() => null) : null;
    if (deps.osv) {
      await ev(sql, id, "log", { stage: "static", msg: maskSecrets(`pre-install package list: ${depsBefore ? `${depsBefore.packages.length} from ${depsBefore.src}${depsBefore.why ? ` (${depsBefore.why})` : ""}` : "failed"}`) }).catch(() => {});
    }
    let repoHits: SecretHit[] = [];
    let envScanned = false;
    try {
      const got = await collectRepoFiles(sandbox, image, id);
      repoHits = scanFiles(got.files, { framework: plan.framework });
      // Only a complete walk vouches for the env file (a partial one may have stopped first).
      envScanned = !got.partial;
      const secretFs = secretFindings(repoHits);
      findings.push(...secretFs);
      await ev(sql, id, "log", { stage: "static", msg: `secret scan: ${secretFs.length} finding(s) from ${got.files.length} candidate file(s)${got.partial ? " (partial: output budget reached)" : ""}` });
    } catch (e) {
      await ev(sql, id, "log", { stage: "static", msg: `secret scan skipped: ${String((e as Error)?.message ?? e).slice(0, 200)}` }).catch(() => {});
    }
    // A committed env file (not an .example) with no recognisable secret in it is still worth a
    // note; one with secrets is covered by the secret findings themselves.
    const realEnv = manifest.envFiles.filter((f) => !EXAMPLE_FILE.test(f));
    // By file, not by `where`: a NEXT_PUBLIC_ line in .env is classed "browser" but still covers it.
    if (realEnv.length && !repoHits.some((h) => /^\.env/.test(h.file.split(/[/\\]/).pop() ?? ""))) {
      findings.push(mkFinding("f-env", "medium", "secret_exposure", "Committed environment file",
        `The repo commits ${realEnv.join(", ")}. Env files usually hold secrets and belong in .gitignore; ` +
          (envScanned ? "no recognisable key was found in it, but check it by hand." : "the secret scan could not check it, so check it by hand."),
        true, [{ kind: "code", file: realEnv[0]!, snippet: "(environment file present in the repository root)" }], "secret_scan"));
    }
    if (deps.llm) {
      try {
        const sources = await collectSources(sandbox, image, id);
        const llmFindings = await llmReview(sources, deps.llm);
        findings.push(...llmFindings);
        await ev(sql, id, "log", { stage: "static", msg: `LLM review: ${llmFindings.length} finding(s) from ${sources.length} file(s)` });
      } catch (e) {
        await ev(sql, id, "log", { stage: "static", msg: `static review skipped: ${String((e as Error)?.message ?? e).slice(0, 200)}` }).catch(() => {});
      }
    } else {
      await ev(sql, id, "log", { stage: "static", msg: "static review: no LLM configured" }).catch(() => {});
    }

    if (!staticOnly) {
      // --- install (read-only egress: registries, GET/HEAD only) ---
      await enter("install");
      await writeProxyState({ auditId: id, stage: "install", keys: {}, canaries: Object.values(canaries) });
      const install = await sandbox.run({
        role: "app",
        image,
        cmd: ["bash", "-lc", `cd ${WORKSPACE_MOUNT}/app && ${plan.installCommand}${ignoreScripts ? " --ignore-scripts" : ""}`],
        env: sandboxEnv(plan, canaries, id, testKeys, false),
        timeoutMs: STAGE_TIMEOUTS_MS.install,
        name: `va-${id}-install`,
      });
      await ev(sql, id, "log", { stage: "install", msg: tailLog(install) });
      if (install.timedOut) {
        limitHit("install", `install exceeded ${STAGE_TIMEOUTS_MS.install / 1000}s and was killed`);
        throw new Error("install timed out");
      }
      if (install.code !== 0) { staticOnly = true; staticReason = "dependency install failed"; }

      // --- build (if any) ---
      if (!staticOnly && plan.buildCommand) {
        await enter("build");
        await writeProxyState({ auditId: id, stage: "build", keys: {}, canaries: Object.values(canaries) });
        const build = await sandbox.run({
          role: "app",
          image,
          cmd: ["bash", "-lc", `cd ${WORKSPACE_MOUNT}/app && ${plan.buildCommand}`],
          env: sandboxEnv(plan, canaries, id, testKeys, true),
          timeoutMs: STAGE_TIMEOUTS_MS.buildPerTry,
          name: `va-${id}-build`,
        });
        await ev(sql, id, "log", { stage: "build", msg: tailLog(build) });
        if (build.timedOut) limitHit("build", `build exceeded ${STAGE_TIMEOUTS_MS.buildPerTry / 1000}s and was killed`);
        if (build.code !== 0) { staticOnly = true; staticReason = build.timedOut ? "build timed out" : "build failed"; }
        else await scanBundle(sandbox, image, id, plan.framework, sql, findings, repoHits, plantedEnv(plan, canaries, id, testKeys));
      }

      // --- run + dynamic probing ---
      if (!staticOnly && plan.startCommand) {
        await enter("run");
        await writeProxyState({ auditId: id, stage: "run", keys: proxyKeys(testKeys), canaries: Object.values(canaries) });
        const appName = await sandbox.start({
          role: "app",
          image,
          cmd: ["bash", "-lc", `cd ${WORKSPACE_MOUNT}/app && exec ${plan.startCommand}`],
          env: { ...sandboxEnv(plan, canaries, id, testKeys, true), PORT: String(plan.port ?? 3000) },
          name: `va-${id}-app`,
        });
        const runDeadline = Date.now() + STAGE_TIMEOUTS_MS.run;
        const ip = await waitForApp(sandbox, appName, plan.port ?? 3000, runDeadline);
        if (!ip) {
          if (Date.now() >= runDeadline) limitHit("run", `the app didn't start listening within ${STAGE_TIMEOUTS_MS.run / 1000}s`);
          staticOnly = true;
          staticReason = "the app did not start listening";
          await ev(sql, id, "log", { stage: "run", msg: tailLog({ stdout: await sandbox.logs(appName), stderr: "" }) });
        } else {
          await enter("dynamic");
          // Cap dynamic probing by the remaining run budget; whatever we have is still reported.
          // probe() must never reject the race: the loser keeps running after a timeout, so a
          // late rejection would have no awaiter and crash the worker as an unhandledRejection.
          await Promise.race([
            probe(sandbox, id, ip, plan.port ?? 3000, findings, sql).catch(() => {}),
            new Promise((r) => setTimeout(r, Math.max(1000, runDeadline - Date.now()))),
          ]);
        }
      }
    }

    // --- report ---
    await enter("report");
    // Dependency audit: what install put in node_modules (or the lockfile, if install never
    // ran), checked against OSV from VM 1. Best effort, like the other static passes.
    if (deps.osv) await auditDependencies(sandbox, image, id, sql, findings, deps.osv, depsBefore);
    const status = staticOnly ? "static_only" : "completed";
    containment = await assembleContainment(sandbox, id, proxyOffset, windowStartMs, marks, limitHits, findings);
    const report: Report = {
      auditId: id,
      source: audit.source,
      status,
      mode: staticOnly ? "static_only" : "runtime",
      staticOnlyReason: staticReason,
      score: scoreFrom(findings),
      // Masked here, once, so no secret value from the repo or the app reaches the stored report.
      findings: findings.map(maskFinding),
      containment,
      startedAt,
      finishedAt: new Date().toISOString(),
    };
    // Final event first: live viewers hang up once the status turns terminal.
    await ev(sql, id, "done", { status, score: report.score, findings: findings.length });
    await finishAudit(sql, id, { status, report });
  } catch (err) {
    if (err instanceof Cancelled) {
      await ev(sql, id, "cancelled", {});
      return;
    }
    // Error text can carry sandbox stderr (e.g. "unpack failed: ..."): mask before storing it.
    const message = maskSecrets((err instanceof Error ? err.message : String(err)).slice(0, 4000));
    // Keep what the sandbox did even when the audit fails: a hostile install that exfils and
    // then hangs is exactly the case whose containment log matters most.
    let partial: Report | undefined;
    try {
      // Assembled already if the failure came after the report was built (e.g. finishAudit):
      // reuse it, since assembling again would add its findings to `findings` a second time.
      containment ??= await assembleContainment(sandbox, id, proxyOffset, windowStartMs, marks, limitHits, findings);
      partial = {
        auditId: id,
        source: audit.source,
        status: "failed",
        mode: marks.some((m) => m.stage === "install") ? "runtime" : "static_only",
        staticOnlyReason: `the audit failed: ${message.slice(0, 300)}`,
        score: scoreFrom(findings),
        findings: findings.map(maskFinding),
        containment,
        startedAt,
        finishedAt: new Date().toISOString(),
      };
    } catch {
      // best effort; the failure itself is still recorded below
    }
    await ev(sql, id, "error", { message }).catch(() => {});
    await finishAudit(sql, id, { status: "failed", error: message, report: partial }).catch(() => {});
  } finally {
    clearInterval(beat);
    await clearProxyState().catch(() => {});
    await sandbox.teardown();
  }
}

async function stage(sql: Sql, id: string, name: AuditStage): Promise<void> {
  await heartbeat(sql, id, name);
  await ev(sql, id, "stage", { stage: name });
}

async function readManifest(sandbox: Sandbox, image: string, id: string) {
  const script =
    'const fs=require("fs");const r=p=>{try{return fs.readFileSync(p,"utf8")}catch{return null}};' +
    'const ls=fs.existsSync(".")?fs.readdirSync("."):[];' +
    'process.stdout.write(JSON.stringify({pkg:r("package.json"),lockfiles:ls.filter(f=>/(lock|shrinkwrap)/.test(f)),envFiles:ls.filter(f=>/^\\.env/.test(f))}))';
  const r = await sandbox.run({
    role: "app",
    image,
    cmd: ["node", "-e", script],
    timeoutMs: 20_000,
    name: `va-${id}-manifest`,
  });
  let parsed: { pkg: string | null; lockfiles: string[]; envFiles: string[] };
  try {
    parsed = JSON.parse(r.stdout.trim() || "{}");
  } catch {
    throw new Error("could not read package.json from the repo");
  }
  let packageJson: Record<string, unknown> = {};
  if (parsed.pkg) {
    try {
      packageJson = JSON.parse(parsed.pkg);
    } catch {
      throw new Error("package.json is not valid JSON");
    }
  }
  return { packageJson, lockfiles: parsed.lockfiles ?? [], envFiles: parsed.envFiles ?? [] };
}

function buildApprovalRequest(id: string, plan: Plan, manifest: { packageJson: Record<string, unknown> }): ApprovalRequest {
  const scripts = (manifest.packageJson.scripts as Record<string, string>) ?? {};
  const installScripts = ["preinstall", "install", "postinstall", "prepare"]
    .filter((s) => scripts[s])
    .map((s) => ({ pkg: "(root)", script: `${s}: ${scripts[s]}` }));
  return {
    auditId: id,
    requestId: randomBytes(9).toString("base64url"),
    plan: {
      framework: plan.framework,
      packageManager: plan.packageManager,
      installCommand: plan.installCommand,
      buildCommand: plan.buildCommand,
      startCommand: plan.startCommand,
      port: plan.port,
    },
    // Show what will really happen: reserved names get nothing planted (see isReservedEnv).
    env: plan.env.map((e) => (isReservedEnv(e.name) ? { ...e, provide: "empty" as const } : e)),
    installScripts,
    expiresAt: new Date(Date.now() + APPROVAL_TTL_MS).toISOString(),
  };
}

async function waitForDecision(sql: Sql, id: string, pollMs: number, deadlineMs: number): Promise<AuditRow> {
  for (;;) {
    const row = await getAudit(sql, id);
    if (!row) throw new Error("audit vanished while awaiting approval");
    if (row.status === "cancelled") return row;
    if (row.status !== "awaiting_approval" && row.approval_decision) return row;
    // The single worker blocks here, so the queue's own expiry sweep can't run meanwhile —
    // enforce the deadline ourselves, release the slot, and let the audit be cancelled.
    if (Date.now() > deadlineMs) {
      await finishAudit(sql, id, { status: "cancelled", error: "approval expired" }).catch(() => {});
      throw new Cancelled();
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/**
 * Names the sandbox sets itself (proxy, CA, runtime, telemetry opt-outs). A repo declaring one
 * in .env.example must not get a canary or placeholder there: the caller env is appended after
 * the container flags and Docker keeps the last --env, so it would knock the app off the proxy
 * (and turn its traffic into firewall drops, a false supply-chain finding) or break node.
 */
export function isReservedEnv(name: string): boolean {
  return (
    /^(?:https?|no|all)_proxy$/i.test(name) ||
    /^(?:YARN|NODE|NPM_CONFIG|PNPM)_/i.test(name) ||
    ["SSL_CERT_FILE", "PORT", "PATH", "HOME"].includes(name) ||
    Object.hasOwn(TELEMETRY_OPT_OUT, name)
  );
}

/** A canary stub per env var that isn't getting a real test key. */
function planCanaries(plan: Plan, id: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const e of plan.env) {
    if (e.provide === "canary" && !isReservedEnv(e.name)) out[e.name] = `AKIAVIBE${randomBytes(9).toString("hex").toUpperCase()}`;
  }
  // Always plant at least one canary so exfil detection is live even with no declared env.
  if (Object.keys(out).length === 0) out.VIBEAUDIT_CANARY = `AKIAVIBE${randomBytes(9).toString("hex").toUpperCase()}`;
  return out;
}

function proxyKeys(testKeys: Record<string, string>): ProxyState["keys"] {
  const keys: ProxyState["keys"] = {};
  for (const [name, value] of Object.entries(testKeys)) {
    const hosts = KEY_PROVIDERS[name];
    if (hosts) keys[name] = { value, hosts: [...hosts] };
  }
  return keys;
}

const TELEMETRY_OPT_OUT: Record<string, string> = {
  NEXT_TELEMETRY_DISABLED: "1",
  CHECKPOINT_DISABLE: "1", // Prisma
  DO_NOT_TRACK: "1",
  NUXT_TELEMETRY_DISABLED: "1",
  ASTRO_TELEMETRY_DISABLED: "1",
  GATSBY_TELEMETRY_DISABLED: "1",
  STORYBOOK_DISABLE_TELEMETRY: "1",
  TURBO_TELEMETRY_DISABLED: "1",
  NG_CLI_ANALYTICS: "false",
  // Update checks and Next's lockfile patcher hit the npm registry, which build doesn't allow.
  NO_UPDATE_NOTIFIER: "1",
  npm_config_update_notifier: "false",
  NEXT_IGNORE_INCORRECT_LOCKFILE: "1",
  // Browser/binary downloads go to CDNs anyone can host on (storage.googleapis.com...), so
  // they aren't excused as "known" hosts; skip them at the source instead.
  PUPPETEER_SKIP_DOWNLOAD: "1",
  PUPPETEER_SKIP_CHROMIUM_DOWNLOAD: "1",
  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1",
  CYPRESS_INSTALL_BINARY: "0",
  SENTRYCLI_SKIP_DOWNLOAD: "1",
};

function sandboxEnv(plan: Plan, canaries: Record<string, string>, id: string, testKeys: Record<string, string>, includeKeys: boolean): Record<string, string> {
  // Opt well-known tools out of telemetry: their phone-home calls would otherwise show up as
  // blocked install/build egress (a supply-chain finding) on every Next.js or Prisma repo.
  const env: Record<string, string> = { ...canaries, ...TELEMETRY_OPT_OUT };
  if (includeKeys) {
    for (const e of plan.env) {
      // Only hand the app a placeholder when a real test key backs it; otherwise the proxy
      // has no swap rule and the bare placeholder would just egress and fail auth.
      if (e.provide === "placeholder" && testKeys[e.name] && !isReservedEnv(e.name)) env[e.name] = keyPlaceholder(e.name, id);
    }
  }
  return env;
}

async function waitForApp(sandbox: Sandbox, appName: string, port: number, deadlineMs: number): Promise<string | null> {
  while (Date.now() < deadlineMs) {
    await new Promise((r) => setTimeout(r, 1500));
    const ip = await sandbox.ipOf(appName);
    if (!ip) {
      // No IP: distinguish "crashed/exited" (give up) from "not up yet" (keep waiting).
      if (!(await sandbox.isRunning(appName))) return null;
      continue;
    }
    // Probe the port from a throwaway container on the same network.
    const r = await sandbox.run({
      role: "browser",
      image: "curlimages/curl:8.17.0",
      cmd: ["-sS", "-o", "/dev/null", "-m", "3", `http://${ip}:${port}/`],
      timeoutMs: 8000,
      name: `va-${sandbox.auditId}-portcheck`,
    });
    if (r.code === 0) return ip;
    if (!(await sandbox.isRunning(appName))) return null;
  }
  return null;
}

interface ProbeResult {
  status: number;
  body: string;
  headers: string;
}

async function probe(sandbox: Sandbox, id: string, ip: string, port: number, findings: Finding[], sql: Sql): Promise<void> {
  const base = `http://${ip}:${port}`;
  // One curl per request. `-D -` dumps response headers ahead of the body on stdout; we append
  // a sentinel + the numeric status so we can split headers / body / status reliably. `method`,
  // `headers` and `data` let a probe send a forged header or a POST without extra plumbing.
  const SEP = "\\n__VA_STATUS__:";
  const call = async (path: string, opts: { method?: string; headers?: string[]; data?: string } = {}): Promise<ProbeResult> => {
    const cmd = ["-sS", "-m", "6", "-D", "-"];
    if (opts.method) cmd.push("-X", opts.method);
    for (const h of opts.headers ?? []) cmd.push("-H", h);
    if (opts.data !== undefined) cmd.push("--data", opts.data);
    cmd.push("-w", SEP + "%{http_code}", `${base}${path}`);
    const r = await sandbox.run({ role: "browser", image: "curlimages/curl:8.17.0", cmd, timeoutMs: 12_000, name: `va-${id}-probe` });
    const marker = r.stdout.lastIndexOf("\n__VA_STATUS__:");
    const status = marker >= 0 ? Number(r.stdout.slice(marker + "\n__VA_STATUS__:".length).trim()) || 0 : 0;
    const out = marker >= 0 ? r.stdout.slice(0, marker) : r.stdout;
    // Headers are everything up to the first blank line; the rest is the body.
    const split = out.search(/\r?\n\r?\n/);
    const headers = split >= 0 ? out.slice(0, split) : "";
    const body = split >= 0 ? out.slice(split).replace(/^\r?\n\r?\n/, "") : out;
    return { status, body, headers };
  };

  // A battery of unauthenticated/forged requests. Each finding is runtime-confirmed by the
  // response. One probe throwing must not drop the others, so each runs under `safe`.
  const results: Record<string, number> = {};
  const safe = async (label: string, fn: () => Promise<void>) => {
    try {
      await fn();
    } catch (e) {
      results[label] = -1;
      // Logging is best-effort: a DB blip here must not turn into an unhandled rejection.
      await ev(sql, id, "log", { stage: "dynamic", msg: `probe ${label} errored: ${String((e as Error)?.message ?? e).slice(0, 200)}` }).catch(() => {});
    }
  };

  await safe("users", async () => {
    const users = await call("/api/users");
    results.users = users.status;
    if (users.status === 200 && /passwordHash|password/i.test(users.body)) {
      findings.push(mkFinding("f-users", "critical", "missing_auth", "User records exposed without authentication",
        "GET /api/users returns the full user table, including password hashes, with no authentication.", true,
        [{ kind: "http", method: "GET", url: "/api/users", status: 200, bodyExcerpt: users.body.slice(0, 300) }], "probe"));
    }
  });

  await safe("debug", async () => {
    const debug = await call("/api/debug");
    results.debug = debug.status;
    if (debug.status === 200 && /env|process/i.test(debug.body)) {
      findings.push(mkFinding("f-debug", "high", "secret_exposure", "Debug endpoint dumps the environment",
        "GET /api/debug returns process environment variables and server internals to any caller.", true,
        [{ kind: "http", method: "GET", url: "/api/debug", status: 200, bodyExcerpt: debug.body.slice(0, 300) }], "probe"));
    }
  });

  // IDOR: a note belonging to another user is readable by id with no auth or ownership check.
  await safe("idor", async () => {
    const own = await call("/api/notes/1");
    const other = await call("/api/notes/2");
    results.idor = other.status;
    if (other.status === 200 && own.status === 200 && /"(text|ownerId)"/i.test(other.body)) {
      findings.push(mkFinding("f-idor", "high", "missing_auth", "Any record readable by id (IDOR)",
        "GET /api/notes/:id returns a record for any id with no authentication or ownership check, so one user can read another's data.", true,
        [{ kind: "http", method: "GET", url: "/api/notes/2", status: other.status, bodyExcerpt: other.body.slice(0, 300) }], "probe"));
    }
  });

  // Broken access control: an admin-only action gated solely by a client-supplied header.
  await safe("admin-header", async () => {
    const forged = await call("/api/admin/delete-user", { method: "POST", headers: ["Content-Type: application/json", "x-user-role: admin"], data: '{"id":3}' });
    results["admin-header"] = forged.status;
    if (forged.status >= 200 && forged.status < 300 && /"ok"|success/i.test(forged.body)) {
      findings.push(mkFinding("f-admin-header", "critical", "missing_auth", "Admin action authorized by a client-supplied header",
        "POST /api/admin/delete-user performs a privileged action when the request sets x-user-role: admin, a value any client controls, so anyone can act as an administrator.", true,
        [{ kind: "http", method: "POST", url: "/api/admin/delete-user", status: forged.status, bodyExcerpt: forged.body.slice(0, 200) }], "probe"));
    }
  });

  // Unauthenticated AI proxy: the endpoint accepts a request with no credentials. A 502 here is
  // still proof (the sandbox proxy blocks the upstream call) — what matters is it wasn't gated.
  await safe("chat", async () => {
    const chat = await call("/api/chat", { method: "POST", headers: ["Content-Type: application/json"], data: '{"message":"ping"}' });
    results.chat = chat.status;
    // A real HTTP response that wasn't an auth gate or a 404. `status >= 200` excludes 0, which
    // the parser produces for a timeout / no response (curl %{http_code}=000) — never a finding.
    if (chat.status >= 200 && chat.status !== 404 && chat.status !== 401 && chat.status !== 403) {
      findings.push(mkFinding("f-chat", "high", "missing_auth", "AI proxy endpoint has no authentication or rate limit",
        "POST /api/chat forwards to a paid upstream API without requiring any auth, so anyone can run up the bill against the server's key.", true,
        [{ kind: "http", method: "POST", url: "/api/chat", status: chat.status, bodyExcerpt: chat.body.slice(0, 200) }], "probe"));
    }
  });

  // Verbose errors: an unhandled error returns a stack trace to the caller.
  await safe("crash", async () => {
    const crash = await call("/api/crash");
    results.crash = crash.status;
    if (crash.status >= 500 && /\bat\b.*\.js:\d+|Error:/i.test(crash.body)) {
      findings.push(mkFinding("f-crash", "medium", "unsafe_defaults", "Server errors leak stack traces",
        "An unhandled error on /api/crash returns a full stack trace, exposing file paths and server internals.", true,
        [{ kind: "http", method: "GET", url: "/api/crash", status: crash.status, bodyExcerpt: crash.body.slice(0, 300) }], "probe"));
    }
  });

  // Wildcard CORS: Access-Control-Allow-Origin: * on an API response.
  await safe("cors", async () => {
    const root = await call("/api/users");
    const acao = /^access-control-allow-origin:\s*(.+)$/im.exec(root.headers);
    if (acao && acao[1]!.trim() === "*") {
      findings.push(mkFinding("f-cors", "medium", "unsafe_defaults", "Wildcard CORS policy",
        "Responses send Access-Control-Allow-Origin: *, letting any website read the API's responses in a victim's browser.", true,
        [{ kind: "http", method: "GET", url: "/api/users", status: root.status, headers: { "access-control-allow-origin": "*" } }], "probe"));
    }
  });

  await ev(sql, id, "log", { stage: "dynamic", msg: `probed ${Object.entries(results).map(([k, v]) => `${k} (${v})`).join(", ")}` }).catch(() => {});
}

function mkFinding(id: string, severity: Finding["severity"], category: Finding["category"], title: string, description: string, confirmed: boolean, evidence: Finding["evidence"], source: Finding["source"]): Finding {
  return { id, severity, category, title, description, confirmed, evidence, source };
}

const WEIGHT: Record<Finding["severity"], number> = { critical: 40, high: 20, medium: 10, low: 4, info: 0 };
const DEP_PENALTY_CAP = 30;
export function scoreFrom(findings: Finding[]): number {
  // Unconfirmed findings (static suspicion, e.g. LLM review) count at half weight, so a noisy
  // or hallucinating static pass can't tank an otherwise-clean repo the way proven findings do.
  const cost = (f: Finding) => WEIGHT[f.severity] * (f.confirmed ? 1 : 0.5);
  // Known-vulnerable dependency versions are capped as a group: most real apps carry a few
  // advisories deep in their tree, and that hygiene signal shouldn't drown out what the audit
  // proved about the app itself. Each one is still listed in full.
  // (Known-malicious packages are supply_chain findings, outside the cap.)
  const capped = (f: Finding) => f.source === "dep_audit" && f.category === "vulnerable_dependency";
  const deps = Math.min(DEP_PENALTY_CAP, findings.filter(capped).reduce((s, f) => s + cost(f), 0));
  const penalty = findings.filter((f) => !capped(f)).reduce((s, f) => s + cost(f), 0) + deps;
  return Math.max(0, Math.round(100 - penalty));
}

function tailLog(r: { stdout: string; stderr: string }): string {
  // Build output can print env values or keys: mask before it goes to the live event stream.
  // Mask a wider tail than we keep: a 2000-char window that starts mid-key would lose the prefix
  // the masker keys on. Only the tail, not the whole (sandbox-sized) log: masking costs CPU on VM 1.
  return maskSecrets((r.stdout + (r.stderr ? `\n${r.stderr}` : "")).slice(-4000)).slice(-2000);
}

export { SandboxError, probe as _probeForTest };

/**
 * Build the containment log (and add exfil findings). Best effort: a missing or unreadable
 * log must never fail an otherwise finished audit, so each source degrades to empty.
 */
async function assembleContainment(
  sandbox: Sandbox,
  id: string,
  proxyOffset: number,
  windowStartMs: number,
  marks: StageMark[],
  limitHits: ContainmentEntry[],
  findings: Finding[],
): Promise<ContainmentEntry[]> {
  const windowEndMs = Date.now();
  const [proxy, fwText] = await Promise.all([
    readProxyEvents({ auditId: id, offset: proxyOffset, windowStartMs, windowEndMs, marks }).catch(() => ({ entries: [], findings: [] })),
    sandbox.firewallLog().catch(() => ""),
  ]);
  const fw = parseFirewallDrops(fwText, marks, windowStartMs);
  // Egress stopped during install/build is a finding of its own, not only a containment row.
  const merged = mergeContainment(proxy.entries, fw, limitHits);
  // Push last, after everything that can throw: the failure path re-assembles if this one
  // threw, and must not find these findings already added.
  findings.push(...proxy.findings, ...egressFindings([...proxy.entries, ...fw]));
  return merged;
}

/** What the build env actually planted (canaries + key placeholders), minus fixed settings. */
function plantedEnv(plan: Plan, canaries: Record<string, string>, id: string, testKeys: Record<string, string>): Record<string, string> {
  const env = sandboxEnv(plan, canaries, id, testKeys, true);
  for (const k of Object.keys(TELEMETRY_OPT_OUT)) delete env[k];
  return env;
}

/**
 * After a successful build: scan what will be served to browsers for secrets and for the env
 * markers the build was given. Best effort: never fails the audit.
 */
async function scanBundle(sandbox: Sandbox, image: string, id: string, framework: string, sql: Sql, findings: Finding[], repoHits: readonly SecretHit[], planted: Record<string, string>): Promise<void> {
  try {
    if (!bundleRoots(framework).length) return; // server-only build output: not a client bundle
    const got = await collectBundleFiles(sandbox, image, id, framework, Object.values(planted));
    // A secret the repo scan already reported (anywhere) isn't reported twice.
    const known = new Set(repoHits.map((h) => h.fingerprint));
    const hits = scanFiles(got.files, { framework, bundle: true }).filter((h) => !known.has(h.fingerprint));
    const out = [...bundleLeakFindings(got.found, planted), ...secretFindings(hits, { bundle: true })];
    findings.push(...out);
    await ev(sql, id, "log", { stage: "build", msg: `bundle scan: ${out.length} finding(s) from ${got.files.length} candidate file(s)${got.partial ? " (partial: output budget reached)" : ""}` });
  } catch (e) {
    await ev(sql, id, "log", { stage: "build", msg: `bundle scan skipped: ${String((e as Error)?.message ?? e).slice(0, 200)}` }).catch(() => {});
  }
}

async function auditDependencies(sandbox: Sandbox, image: string, id: string, sql: Sql, findings: Finding[], osv: OsvClient, before: PackageList | null): Promise<void> {
  try {
    const list = mergePackageLists(before, await listPackages(sandbox, image, id));
    if (!list.packages.length) {
      await ev(sql, id, "log", { stage: "report", msg: maskSecrets(`dependency audit: no package list (${list.src}${list.why ? `; ${list.why}` : ""})`) });
      return;
    }
    const r = await dependencyFindings(list.packages, osv, list.src);
    findings.push(...r.findings);
    await ev(sql, id, "log", {
      stage: "report",
      msg: `dependency audit: ${r.vulnerable} flagged, ${r.checked} package(s) checked (${r.production} production; from ${list.src}${before?.packages.length ? " + pre-install lockfile" : ""}${list.truncated ? ", list truncated" : ""}${r.queryPartial ? ", OSV timed out part-way" : ""}${r.detailsSkipped ? ", some advisory details unavailable" : ""})`,
    });
  } catch (e) {
    await ev(sql, id, "log", { stage: "report", msg: `dependency audit skipped: ${String((e as Error)?.message ?? e).slice(0, 200)}` }).catch(() => {});
  }
}
