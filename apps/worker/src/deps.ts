import { z } from "zod";
import type { Finding, Severity } from "@vibeaudit/shared";
import type { Sandbox } from "./sandbox";

/**
 * Dependency audit: which installed packages have known advisories, and whether any is a
 * known-malicious package.
 *
 * The package list comes out of the sandbox (UNTRUSTED: names and versions are parsed and
 * format-checked, never evaluated). The advisory lookup runs here on VM 1 against OSV.dev,
 * so the sandbox needs no extra egress and nothing but public package names and versions
 * leaves VM 1. OSV's answers are external data too: schema-checked and length-capped.
 */

// ---------------------------------------------------------------- package list (in the sandbox)

const MAX_PACKAGES = 4000;
const NAME_SRC = String.raw`^(?:@[a-z0-9][a-z0-9._~-]{0,213}\/)?[a-z0-9][a-z0-9._~-]{0,213}$`;
const VERSION_SRC = String.raw`^\d{1,9}\.\d{1,9}\.\d{1,9}(?:[-+][0-9A-Za-z.+-]{1,100})?$`;
const NAME_RE = new RegExp(NAME_SRC, "i");
const VERSION_RE = new RegExp(VERSION_SRC);

/**
 * Lists packages as "name\tversion\tflags" lines (flags: d = dev-only, r = direct dependency,
 * i.e. installed at the top level and named in package.json). Sources, best first: npm's
 * hidden lockfile (what was actually installed), the repo's package-lock.json (v2/v3
 * "packages", or v1 "dependencies"), then a walk of node_modules (pnpm's .pnpm store
 * included; no dev flags there). Reads files only. pnpm/yarn lockfiles aren't parsed, so for
 * those repos the pre-install snapshot is empty and only the post-install walk counts. Names and versions are format-checked here
 * too, so junk can't spend the count or byte budget.
 */
export const LIST_SCRIPT = `
const fs=require("fs"),path=require("path");
const MAX=${MAX_PACKAGES},NAME=new RegExp(${JSON.stringify(NAME_SRC)},"i"),VER=new RegExp(${JSON.stringify(VERSION_SRC)});
const out=new Map();let bytes=0,full=false,visits=0,entries=0;
const r=p=>{try{return JSON.parse(fs.readFileSync(p,"utf8"))}catch{return null}};
const pkg=r("package.json")||{};const declared=new Set([...Object.keys(pkg.dependencies||{}),...Object.keys(pkg.devDependencies||{}),...Object.keys(pkg.optionalDependencies||{})]);
// Bounded by count and serialized bytes: the sandbox's stdout cap is 256 KB.
// declName: the name package.json would declare it under (differs from n for npm aliases).
const add=(n,v,dev,top,declName)=>{if(typeof n!=="string"||typeof v!=="string"||!NAME.test(n)||!VER.test(v))return;const k=n+"@"+v;const direct=!!top&&declared.has(declName||n);
  const prev=out.get(k);if(prev){prev.dev=prev.dev&&!!dev;prev.direct=prev.direct||direct;return}
  if(out.size>=MAX||bytes>180000){full=true;return}bytes+=JSON.stringify(k).length+8;out.set(k,{n,v,dev:!!dev,direct})};
function fromLock(l){const ps=l&&l.packages;if(!ps||typeof ps!=="object")return false;let any=false;
  for(const [k,p] of Object.entries(ps)){if(!k||!p||typeof p!=="object"||p.link)continue;const i=k.lastIndexOf("node_modules/");if(i<0)continue;
    const keyName=k.slice(i+13);add(typeof p.name==="string"?p.name:keyName,p.version,p.dev===true||p.devOptional===true,k==="node_modules/"+keyName,keyName);any=true}
  return any}
function fromLockV1(l){const ds=l&&l.dependencies;if(!ds||typeof ds!=="object")return false;let any=false;
  const rec=(d,top,depth)=>{if(depth>30)return;for(const [n,p] of Object.entries(d)){if(!p||typeof p!=="object")continue;add(n,p.version,p.dev===true,top);any=true;if(p.dependencies&&typeof p.dependencies==="object")rec(p.dependencies,false,depth+1)}};
  rec(ds,true,0);return any}
let src="none";
if(fromLock(r("node_modules/.package-lock.json")))src="installed";
else{const lock=r("package-lock.json");if(fromLock(lock)||fromLockV1(lock))src="lockfile";
else{
  const seen=new Set();
  const once=p=>{let real;try{real=fs.realpathSync(p)}catch{return false}if(seen.has(real))return false;seen.add(real);return true};
  // Caps count real work: successful directory reads, and entries looked at.
  const visit=(dir,depth,top)=>{if(full||depth>8||visits>50000)return;let ents;try{ents=fs.readdirSync(dir,{withFileTypes:true})}catch{return}visits++;
    // pnpm's store last: its packages are the targets of the top-level symlinks, which must be
    // seen first (as top-level) or they'd be skipped as already-visited.
    ents.sort((a,b)=>(a.name===".pnpm"?1:0)-(b.name===".pnpm"?1:0));
    for(const e of ents){if(++entries>200000)break;if(!e.isDirectory()&&!e.isSymbolicLink())continue;const p=path.join(dir,e.name);
      if(e.name===".bin"||e.name===".cache")continue;
      if(e.name===".pnpm"){if(!once(p))continue;let st;try{st=fs.readdirSync(p,{withFileTypes:true})}catch{continue}for(const s of st){if(s.isDirectory())visit(path.join(p,s.name,"node_modules"),depth+1,false)}continue}
      if(e.name.startsWith("@")){if(once(p))visit(p,depth+1,top);continue}
      // Record the package before the visited check (a top-level link to an already-seen
      // store dir still makes it direct); recurse only once per real directory.
      const j=r(path.join(p,"package.json"));if(j&&j.name&&j.version){const sc=path.basename(dir);add(j.name,j.version,false,top,sc.startsWith("@")?sc+"/"+e.name:e.name);src="walk"}
      if(once(p))visit(path.join(p,"node_modules"),depth+1,false)}};
  visit("node_modules",0,true);
}}
const lines=[];for(const {n,v,dev,direct} of out.values())lines.push(n+"\\t"+v+"\\t"+(dev?"d":"")+(direct?"r":""));
process.stdout.write(JSON.stringify({src,truncated:full||visits>50000||entries>200000,pkgs:lines.join("\\n")}));
`;

export interface InstalledPackage {
  name: string;
  version: string;
  dev: boolean;
  direct: boolean;
}

export interface PackageList {
  src: string;
  truncated: boolean;
  packages: InstalledPackage[];
  /** Why the list is empty or unreadable (exit code, timeout, stderr tail), for the log. */
  why?: string;
}

export function parsePackageList(stdout: string): PackageList {
  let raw: unknown;
  try {
    raw = JSON.parse(stdout.trim() || "null");
  } catch {
    return { src: "unreadable", truncated: true, packages: [] };
  }
  const ok = z.object({ src: z.string().max(20), truncated: z.boolean(), pkgs: z.string().max(400_000) }).safeParse(raw);
  if (!ok.success) return { src: "unreadable", truncated: true, packages: [] };
  const packages: InstalledPackage[] = [];
  const seen = new Set<string>();
  for (const line of ok.data.pkgs.split("\n").slice(0, MAX_PACKAGES)) {
    const [name, version, flags = ""] = line.split("\t");
    if (!name || !version || !NAME_RE.test(name) || !VERSION_RE.test(version)) continue;
    const k = `${name}@${version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    packages.push({ name, version, dev: flags.includes("d"), direct: flags.includes("r") });
  }
  const src = ["installed", "lockfile", "walk", "none"].includes(ok.data.src) ? ok.data.src : "unknown";
  return { src, truncated: ok.data.truncated, packages };
}

/**
 * Union of two lists: the one taken before any repo code ran (the committed lockfile) and the
 * one after install. Install scripts can rewrite node_modules/.package-lock.json and the
 * lockfile to hide a package; they can't edit the snapshot we already took.
 */
export function mergePackageLists(before: PackageList | null, after: PackageList): PackageList {
  if (!before?.packages.length) return after;
  const by = new Map<string, InstalledPackage>();
  // The committed lockfile's packages first: they're queried first, so a slow OSV can't time
  // out exactly the ones an install script tried to hide.
  for (const p of [...before.packages, ...after.packages]) {
    const k = `${p.name}@${p.version}`;
    const prev = by.get(k);
    by.set(k, prev ? { ...prev, dev: prev.dev && p.dev, direct: prev.direct || p.direct } : { ...p });
  }
  return { src: after.packages.length ? after.src : before.src, truncated: before.truncated || after.truncated, packages: [...by.values()].slice(0, MAX_PACKAGES * 2), why: after.why };
}

export async function listPackages(sandbox: Sandbox, image: string, id: string, tag = "deps"): Promise<PackageList> {
  const r = await sandbox.run({ role: "app", image, cmd: ["node", "-e", LIST_SCRIPT], timeoutMs: 60_000, name: `va-${id}-${tag}` });
  const list = parsePackageList(r.stdout);
  if (!list.packages.length) list.why = `exit ${r.code}${r.timedOut ? ", timed out" : ""}${r.stderr.trim() ? `: ${r.stderr.trim().slice(-200)}` : ""}`;
  return list;
}

// ---------------------------------------------------------------- advisories (OSV, on VM 1)

export interface Advisory {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  /** OpenSSF malicious-packages record (MAL-*): the package itself is malware. */
  malicious: boolean;
  /** Lowest version that fixes it for the installed version, if OSV says. */
  fixed?: string;
}

export interface OsvClient {
  /** For each package (same order), the advisory ids affecting that version. */
  query(pkgs: readonly { name: string; version: string }[], signal?: AbortSignal): Promise<string[][]>;
  /** Advisory details, or null if unavailable. */
  vuln(id: string, signal?: AbortSignal): Promise<unknown>;
}

const OSV_BATCH = 1000;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,63}$/;
const isMal = (id: string) => /^MAL-/i.test(id);

/** OSV client; HTTP errors throw (callers stop asking on the first one). */
export function createOsv(baseUrl = "https://api.osv.dev", perCallMs = 15_000): OsvClient {
  const call = async (path: string, body: unknown, signal?: AbortSignal): Promise<unknown> => {
    const sig = signal ? AbortSignal.any([signal, AbortSignal.timeout(perCallMs)]) : AbortSignal.timeout(perCallMs);
    const res = await fetch(`${baseUrl}${path}`, {
      method: body ? "POST" : "GET",
      headers: body ? { "content-type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined,
      signal: sig,
    });
    if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
    // OSV is a trusted-ish public API; the size check is a sanity bound, not a defence.
    const text = await res.text();
    if (text.length > 8_000_000) throw new Error("OSV response too large");
    return JSON.parse(text) as unknown;
  };
  return {
    async query(pkgs, signal) {
      const out: string[][] = [];
      for (let i = 0; i < pkgs.length; i += OSV_BATCH) {
        const chunk = pkgs.slice(i, i + OSV_BATCH);
        // Results come back in query order. Per-query pagination (next_page_token) only kicks
        // in for packages with very many advisories; the first page is plenty for a report.
        const data = (await call(
          "/v1/querybatch",
          { queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: "npm" }, version: p.version })) },
          signal,
        )) as { results?: { vulns?: { id?: unknown }[] }[] };
        for (let j = 0; j < chunk.length; j++) {
          const vulns = data.results?.[j]?.vulns ?? [];
          out.push(vulns.map((v) => v.id).filter((x): x is string => typeof x === "string" && ID_RE.test(x)).slice(0, 50));
        }
      }
      return out;
    },
    async vuln(id, signal) {
      if (!ID_RE.test(id)) return null;
      return call(`/v1/vulns/${encodeURIComponent(id)}`, undefined, signal);
    },
  };
}

const OsvVuln = z
  .object({
    id: z.string(),
    summary: z.string().optional(),
    details: z.string().optional(),
    withdrawn: z.string().optional(),
    aliases: z.array(z.string()).optional(),
    database_specific: z.object({ severity: z.string().optional() }).passthrough().optional(),
    affected: z
      .array(
        z
          .object({
            package: z.object({ name: z.string().optional(), ecosystem: z.string().optional() }).passthrough().optional(),
            ranges: z.array(z.object({ type: z.string().optional(), events: z.array(z.record(z.string(), z.string())).optional() }).passthrough()).optional(),
          })
          .passthrough(),
      )
      .optional(),
  })
  .passthrough();

const SEV: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };
const cap = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);

/** Semver-ish compare: numeric major.minor.patch, then a prerelease sorts before its release. */
export function cmpVersion(a: string, b: string): number {
  // Build metadata (+...) never affects order; strip it before looking for a prerelease.
  const split = (v: string) => {
    const core = v.split("+")[0]!;
    const i = core.indexOf("-");
    return { nums: (i < 0 ? core : core.slice(0, i)).split(".").map((x) => Number(x) || 0), pre: i < 0 ? "" : core.slice(i + 1) };
  };
  const A = split(a);
  const B = split(b);
  for (let i = 0; i < 3; i++) if ((A.nums[i] ?? 0) !== (B.nums[i] ?? 0)) return (A.nums[i] ?? 0) - (B.nums[i] ?? 0);
  if (A.pre === B.pre) return 0;
  if (!A.pre) return 1;
  if (!B.pre) return -1;
  // Dot-separated identifiers: numeric ones compare as numbers and sort before text ones.
  const pa = A.pre.split(".");
  const pb = B.pre.split(".");
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i];
    const y = pb[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const nx = /^\d+$/.test(x);
    const ny = /^\d+$/.test(y);
    if (nx && ny) return Number(x) - Number(y);
    if (nx !== ny) return nx ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}

/**
 * Pick the advisory fields we report from an untrusted OSV record. The fix version is the
 * smallest `fixed` above the installed version within a range that the installed version is
 * actually in (introduced <= installed < fixed), for this npm package only.
 */
export function toAdvisory(raw: unknown, pkgName: string, installed: string): Advisory | null {
  const ok = OsvVuln.safeParse(raw);
  if (!ok.success || !ID_RE.test(ok.data.id) || ok.data.withdrawn) return null;
  const v = ok.data;
  const aliases = (v.aliases ?? []).filter((x) => ID_RE.test(x)).slice(0, 4);
  const malicious = isMal(v.id) || aliases.some(isMal);
  const sev = malicious ? "critical" : (SEV[(v.database_specific?.severity ?? "").toUpperCase()] ?? "medium");
  let fixed: string | undefined;
  for (const a of v.affected ?? []) {
    if (a.package?.name !== pkgName || (a.package.ecosystem ?? "npm").toLowerCase() !== "npm") continue;
    for (const r of a.ranges ?? []) {
      if (r.type && r.type !== "SEMVER" && r.type !== "ECOSYSTEM") continue;
      let introduced: string | null = null;
      for (const e of r.events ?? []) {
        if (e.introduced !== undefined) introduced = e.introduced === "0" ? "0.0.0" : e.introduced;
        if (e.fixed && VERSION_RE.test(e.fixed) && introduced && VERSION_RE.test(introduced)) {
          if (cmpVersion(introduced, installed) <= 0 && cmpVersion(installed, e.fixed) < 0 && (!fixed || cmpVersion(e.fixed, fixed) < 0)) fixed = e.fixed;
          introduced = null;
        }
      }
    }
  }
  return {
    id: v.id,
    aliases,
    summary: cap((v.summary || v.details || v.id).replace(/\s+/g, " ").trim(), 200),
    severity: sev,
    malicious,
    ...(fixed ? { fixed } : {}),
  };
}

// ---------------------------------------------------------------- findings

const RANK: Severity[] = ["info", "low", "medium", "high", "critical"];
const worst = (a: Severity, b: Severity) => (RANK.indexOf(a) >= RANK.indexOf(b) ? a : b);
const down = (s: Severity): Severity => RANK[Math.max(1, RANK.indexOf(s) - 1)]!; // never below low
const MAX_DEP_FINDINGS = 15;
const MAX_VULN_DETAILS = 80;
const MAX_DETAILS_PER_PACKAGE = 5;
const DETAIL_CONCURRENCY = 8;
/** Total time for every OSV call in one audit: a slow or hung OSV must not stall the queue. */
export const OSV_BUDGET_MS = 45_000;
const QUERY_CHUNK = 1000;

/**
 * Look the packages up and turn hits into findings.
 *  - A package with a MAL-* (malicious package) record: critical, confirmed, category
 *    supply_chain, whatever its depth: the package itself is malware.
 *  - Otherwise one finding per vulnerable package version at its worst advisory's severity.
 *    Dev-only packages aren't shipped and are left out; a transitive dependency rates one
 *    level lower (often unreachable). Known-vulnerable versions, not proven exploits:
 *    reported unconfirmed.
 * Every OSV call shares one deadline; after the first failed detail lookup the rest are
 * skipped and those advisories are reported by id at medium.
 */
export async function dependencyFindings(
  packages: readonly InstalledPackage[],
  osv: OsvClient,
  src: string,
  opts: { budgetMs?: number } = {},
): Promise<{ findings: Finding[]; vulnerable: number; checked: number; production: number; detailsSkipped: boolean; queryPartial: boolean }> {
  const prod = packages.filter((p) => !p.dev);
  if (!packages.length) return { findings: [], vulnerable: 0, checked: 0, production: 0, detailsSkipped: false, queryPartial: false };
  const signal = AbortSignal.timeout(opts.budgetMs ?? OSV_BUDGET_MS);
  // Every package is looked up: a dev dependency's install scripts run too (our install
  // includes dev deps for the build), so a malicious one matters. For dev-only packages only
  // the MAL-* hits are kept; their ordinary advisories aren't shipped to users.
  // Batch by batch, so a timeout keeps what earlier batches found (the first batch failing
  // still throws: nothing was checked, and the caller logs that).
  const ids: string[][] = [];
  let queryPartial = false;
  for (let i = 0; i < packages.length; i += QUERY_CHUNK) {
    try {
      const slice = packages.slice(i, i + QUERY_CHUNK);
      const r = await osv.query(slice, signal);
      for (let j = 0; j < slice.length; j++) ids.push(r[j] ?? []); // stay aligned with packages
    } catch (e) {
      if (i === 0) throw e;
      queryPartial = true;
      break;
    }
  }
  const hits = packages
    .map((p, i) => ({ p, ids: (ids[i] ?? []).filter((id) => !p.dev || isMal(id)) }))
    .filter((h) => h.ids.length);

  // Which advisory details to fetch: malicious ids first, then direct deps, a few per package.
  const order = [...hits].sort((a, b) => Number(b.ids.some(isMal)) - Number(a.ids.some(isMal)) || Number(b.p.direct) - Number(a.p.direct));
  const wanted: string[] = [];
  for (const h of order) {
    for (const id of [...h.ids.filter(isMal), ...h.ids.filter((x) => !isMal(x))].slice(0, MAX_DETAILS_PER_PACKAGE)) {
      if (wanted.length >= MAX_VULN_DETAILS) break;
      if (!wanted.includes(id)) wanted.push(id);
    }
  }
  const details = new Map<string, unknown>();
  let failed = false;
  let next = 0;
  const worker = async () => {
    while (!failed && next < wanted.length) {
      const id = wanted[next++]!;
      try {
        details.set(id, await osv.vuln(id, signal));
      } catch {
        failed = true; // down, rate-limited or out of time: stop asking
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, wanted.length) }, worker));

  const rows = hits.map(({ p, ids: vids }) => {
    const idOnly = (id: string): Advisory => ({ id, aliases: [], summary: id, severity: isMal(id) ? "critical" : "medium", malicious: isMal(id) });
    const advs = vids
      .map((id): Advisory | null => {
        const raw = details.get(id);
        if (raw && typeof raw === "object" && typeof (raw as { withdrawn?: unknown }).withdrawn === "string") return null; // withdrawn
        return (details.has(id) ? toAdvisory(raw, p.name, p.version) : null) ?? idOnly(id); // unfetched or malformed: by id
      })
      .filter((a): a is Advisory => a !== null);
    const malicious = advs.some((a) => a.malicious);
    const top = advs.reduce<Severity>((s, a) => worst(s, a.severity), "low");
    return { p, advs, malicious, severity: malicious || p.direct ? top : down(top) };
  }).filter((r) => r.advs.length);
  rows.sort((a, b) => Number(b.malicious) - Number(a.malicious) || RANK.indexOf(b.severity) - RANK.indexOf(a.severity) || Number(b.p.direct) - Number(a.p.direct));

  const file = src === "installed" ? "node_modules/.package-lock.json" : src === "lockfile" ? "package-lock.json" : "node_modules";
  const findings: Finding[] = rows.slice(0, MAX_DEP_FINDINGS).map(({ p, advs, malicious, severity }, i): Finding => {
    const list = advs.slice(0, 5).map((a) => `${a.id}${a.aliases.length ? ` (${a.aliases.join(", ")})` : ""}: ${a.summary}`);
    const more = advs.length > 5 ? ` · and ${advs.length - 5} more` : "";
    if (malicious) {
      return {
        id: `f-malpkg-${i + 1}`,
        severity: "critical",
        category: "supply_chain",
        title: `${p.name}@${p.version} is a known malicious package`,
        description:
          `${src === "lockfile" ? "The lockfile pins" : "The install pulled in"} ${p.name}@${p.version}${p.direct ? "" : " (as a dependency of another package)"}, which the OpenSSF malicious-packages database lists as malware. ` +
          `${list.join(" · ")}${more}. Anything that installed it should be treated as compromised.`,
        // A listed malicious version, installed (or pinned): a fact, not an inference.
        confirmed: true,
        evidence: [{ kind: "code", file, snippet: `${p.name}@${p.version}` }],
        fix: `Remove ${p.name}${p.direct ? "" : " and the package that depends on it"}, then rotate every secret on any machine or CI runner that installed it.`,
        source: "dep_audit",
      };
    }
    const fixes = advs.map((a) => a.fixed).filter((x): x is string => !!x);
    const fixTo = fixes.sort(cmpVersion).at(-1); // the highest fix covers every advisory listed
    return {
      id: `f-dep-${i + 1}`,
      severity,
      category: "vulnerable_dependency",
      title: `${p.name}@${p.version} has ${advs.length > 1 ? `${advs.length} known vulnerabilities` : "a known vulnerability"}`,
      description:
        `${p.direct ? "A direct dependency" : "A transitive dependency (pulled in by another package)"} of this app is a version with published advisories. ` +
        `${list.join(" · ")}${more}.`,
      confirmed: false,
      evidence: [{ kind: "code", file, snippet: `${p.name}@${p.version}` }],
      fix: fixTo
        ? `Upgrade ${p.name} to ${fixTo} or later${p.direct ? "" : " (update the package that depends on it, or add an override)"}.`
        : `No fixed version is listed for ${p.version}; check the advisory and consider replacing ${p.name}.`,
      source: "dep_audit",
    };
  });
  return { findings, vulnerable: rows.length, checked: ids.length, production: prod.length, detailsSkipped: failed, queryPartial };
}
