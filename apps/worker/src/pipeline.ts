import { randomBytes } from "node:crypto";
import {
  type ApprovalRequest,
  type AuditStage,
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
import { openTarball, resolveRepo } from "./intake";
import { Sandbox, SandboxError } from "./sandbox";
import { clearProxyState, writeProxyState } from "./proxy-state";

export interface PipelineDeps {
  sql: Sql;
  sandbox: Sandbox;
  proxyUrl: string;
  token?: string;
  appImage?: string;
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

  const beat = setInterval(() => void heartbeat(sql, id).catch(() => {}), 20_000);

  try {
    if (audit.source.kind !== "github") throw new Error("only github sources are supported so far");

    // --- intake: resolve ref, stream the tarball into the sandbox (VM 1 never opens it) ---
    await stage(sql, id, "intake");
    const resolved = await resolveRepo({ owner: audit.source.owner, repo: audit.source.repo, ref: audit.source.ref }, { token: deps.token });
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
    await stage(sql, id, "plan");
    const manifest = await readManifest(sandbox, image, id);
    const plan = planFromManifest(manifest);
    await ev(sql, id, "log", { stage: "plan", msg: `framework=${plan.framework} pm=${plan.packageManager}` });
    if (manifest.envFiles.length) {
      findings.push(mkFinding("f-env", "high", "secret_exposure", "Committed environment file",
        `The repo commits ${manifest.envFiles.join(", ")}, which usually holds secrets and should never be in version control.`,
        true, [{ kind: "code", file: manifest.envFiles[0]!, snippet: "(.env present in the repository root)" }], "probe"));
    }
    if (plan.framework === "unknown" || !plan.startCommand) {
      staticOnly = true;
      staticReason = "could not determine how to run this project";
    }

    // --- approve: park for the human, then act on the decision ---
    await stage(sql, id, "approve");
    const canaries = planCanaries(plan, id);
    const req = buildApprovalRequest(id, plan, manifest);
    await requestApproval(sql, id, req);
    await ev(sql, id, "awaiting_approval", { requestId: req.requestId });
    const decided = await waitForDecision(sql, id, deps.approvalPollMs ?? 2000);
    if (decided.status === "cancelled") throw new Cancelled();
    const decision = decided.approval_decision!;
    if (decision.decision === "static_only") {
      staticOnly = true;
      staticReason = "user chose a static-only audit";
    }
    const ignoreScripts = decision.decision === "approve" ? decision.ignoreScripts : true;
    const testKeys = decision.decision === "approve" ? await getSecrets(sql, id) : {};

    if (!staticOnly) {
      // --- install (read-only egress: registries, GET/HEAD only) ---
      await stage(sql, id, "install");
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
      if (install.timedOut) throw new Error("install timed out");
      if (install.code !== 0) { staticOnly = true; staticReason = "dependency install failed"; }

      // --- build (if any) ---
      if (!staticOnly && plan.buildCommand) {
        await stage(sql, id, "build");
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
        if (build.code !== 0) { staticOnly = true; staticReason = "build failed"; }
      }

      // --- run + dynamic probing ---
      if (!staticOnly && plan.startCommand) {
        await stage(sql, id, "run");
        await writeProxyState({ auditId: id, stage: "run", keys: proxyKeys(testKeys), canaries: Object.values(canaries) });
        const appName = await sandbox.start({
          role: "app",
          image,
          cmd: ["bash", "-lc", `cd ${WORKSPACE_MOUNT}/app && exec ${plan.startCommand}`],
          env: { ...sandboxEnv(plan, canaries, id, testKeys, true), PORT: String(plan.port ?? 3000) },
          name: `va-${id}-app`,
        });
        const ip = await waitForApp(sandbox, appName, plan.port ?? 3000);
        if (!ip) {
          staticOnly = true;
          staticReason = "the app did not start listening";
          await ev(sql, id, "log", { stage: "run", msg: tailLog({ stdout: await sandbox.logs(appName), stderr: "" }) });
        } else {
          await stage(sql, id, "dynamic");
          await probe(sandbox, id, ip, plan.port ?? 3000, findings, sql);
        }
      }
    }

    // --- report ---
    await stage(sql, id, "report");
    const status = staticOnly ? "static_only" : "completed";
    const report: Report = {
      auditId: id,
      source: audit.source,
      status,
      mode: staticOnly ? "static_only" : "runtime",
      staticOnlyReason: staticReason,
      score: scoreFrom(findings),
      findings,
      containment: [],
      startedAt,
      finishedAt: new Date().toISOString(),
    };
    await finishAudit(sql, id, { status, report });
    await ev(sql, id, "done", { status, score: report.score, findings: findings.length });
  } catch (err) {
    if (err instanceof Cancelled) {
      await ev(sql, id, "cancelled", {});
      return;
    }
    const message = err instanceof Error ? err.message : String(err);
    await ev(sql, id, "error", { message });
    await finishAudit(sql, id, { status: "failed", error: message }).catch(() => {});
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
    env: plan.env,
    installScripts,
    expiresAt: new Date(Date.now() + APPROVAL_TTL_MS).toISOString(),
  };
}

async function waitForDecision(sql: Sql, id: string, pollMs: number): Promise<AuditRow> {
  for (;;) {
    const row = await getAudit(sql, id);
    if (!row) throw new Error("audit vanished while awaiting approval");
    if (row.status === "cancelled") return row;
    if (row.status !== "awaiting_approval" && row.approval_decision) return row;
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/** A canary stub per env var that isn't getting a real test key. */
function planCanaries(plan: Plan, id: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const e of plan.env) {
    if (e.provide === "canary") out[e.name] = `AKIAVIBE${randomBytes(9).toString("hex").toUpperCase()}`;
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

function sandboxEnv(plan: Plan, canaries: Record<string, string>, id: string, testKeys: Record<string, string>, includeKeys: boolean): Record<string, string> {
  const env: Record<string, string> = { ...canaries };
  if (includeKeys) {
    for (const e of plan.env) {
      if (e.provide === "placeholder" && (testKeys[e.name] || Object.hasOwn(KEY_PROVIDERS, e.name))) {
        env[e.name] = keyPlaceholder(e.name, id);
      }
    }
  }
  return env;
}

async function waitForApp(sandbox: Sandbox, appName: string, port: number): Promise<string | null> {
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 1500));
    const ip = await sandbox.ipOf(appName);
    if (!ip) return null; // container exited
    // Probe the port from a throwaway container on the same network.
    const r = await sandbox.run({
      role: "browser",
      image: "curlimages/curl:8.17.0",
      cmd: ["-sS", "-o", "/dev/null", "-m", "3", `http://${ip}:${port}/`],
      timeoutMs: 8000,
      name: `va-${sandbox.auditId}-portcheck`,
    });
    if (r.code === 0) return ip;
  }
  return null;
}

async function probe(sandbox: Sandbox, id: string, ip: string, port: number, findings: Finding[], sql: Sql): Promise<void> {
  const base = `http://${ip}:${port}`;
  const get = async (path: string) => {
    const r = await sandbox.run({
      role: "browser",
      image: "curlimages/curl:8.17.0",
      cmd: ["-sS", "-m", "6", "-w", "\\n%{http_code}", `${base}${path}`],
      timeoutMs: 12_000,
      name: `va-${id}-probe`,
    });
    const nl = r.stdout.lastIndexOf("\n");
    return { status: Number(r.stdout.slice(nl + 1).trim()) || 0, body: r.stdout.slice(0, nl) };
  };

  // A small battery of unauthenticated reads. Each finding is runtime-confirmed by the response.
  const users = await get("/api/users");
  if (users.status === 200 && /passwordHash|password/i.test(users.body)) {
    findings.push(mkFinding("f-users", "critical", "missing_auth", "User records exposed without authentication",
      "GET /api/users returns the full user table, including password hashes, with no authentication.", true,
      [{ kind: "http", method: "GET", url: "/api/users", status: 200, bodyExcerpt: users.body.slice(0, 300) }], "probe"));
  }
  const debug = await get("/api/debug");
  if (debug.status === 200 && /env|process/i.test(debug.body)) {
    findings.push(mkFinding("f-debug", "high", "secret_exposure", "Debug endpoint dumps the environment",
      "GET /api/debug returns process environment variables and server internals to any caller.", true,
      [{ kind: "http", method: "GET", url: "/api/debug", status: 200, bodyExcerpt: debug.body.slice(0, 300) }], "probe"));
  }
  await ev(sql, id, "log", { stage: "dynamic", msg: `probed /api/users (${users.status}), /api/debug (${debug.status})` });
}

function mkFinding(id: string, severity: Finding["severity"], category: Finding["category"], title: string, description: string, confirmed: boolean, evidence: Finding["evidence"], source: Finding["source"]): Finding {
  return { id, severity, category, title, description, confirmed, evidence, source };
}

const WEIGHT: Record<Finding["severity"], number> = { critical: 40, high: 20, medium: 10, low: 4, info: 0 };
function scoreFrom(findings: Finding[]): number {
  const penalty = findings.reduce((s, f) => s + WEIGHT[f.severity], 0);
  return Math.max(0, 100 - penalty);
}

function tailLog(r: { stdout: string; stderr: string }): string {
  return (r.stdout + (r.stderr ? `\n${r.stderr}` : "")).slice(-2000);
}

export { SandboxError };
