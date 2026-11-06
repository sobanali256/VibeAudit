import { createReadStream } from "node:fs";
import { rename, stat } from "node:fs/promises";
import { createInterface } from "node:readline";
import { AuditStage, type ContainmentEntry, type Finding, KEY_PROVIDERS, ProxyEvent } from "@vibeaudit/shared";

/**
 * Containment log: every time the sandbox reached for the network (and a control let it
 * through or stopped it) or hit a resource cap. Assembled from three sources at report time:
 *  - the egress proxy's events.jsonl on VM 1 (read from the byte offset where the audit began),
 *  - VM 2's iptables drop log (packets that never reached the proxy), filtered by the audit's
 *    bridge interface,
 *  - stage timeouts the worker observed.
 * Hosts, paths and reasons originate in the sandbox: they're untrusted, length-capped here and
 * only ever rendered as text.
 */

export const PROXY_EVENTS_PATH = process.env.VIBEAUDIT_PROXY_EVENTS ?? "/var/lib/vibeaudit/proxy/events.jsonl";

/** Report size caps. Blocked/exfil/firewall entries are kept in preference to allowed ones. */
const MAX_ENTRIES = 400;
/** Lines fully parsed per audit; past this only exfil lines are still looked at (cheap check). */
const LINE_BUDGET = 200_000;
/** Individually kept entries per verdict while reading; the rest are only counted. */
const KEEP_PER_VERDICT = 300;
/** Exfil findings per audit, and hosts named in each (the sandbox chooses the hosts). */
const MAX_EXFIL_FINDINGS = 10;
const MAX_HOSTS_PER_FINDING = 5;
/** Evasive blocked events kept past the per-verdict cap (see isEvasiveBlock). */
const MAX_EVASIVE_EXTRA = 50;
/** Rotate the proxy log at audit start past this size (the proxy reopens it on every write). */
const ROTATE_BYTES = 64 << 20;

export interface StageMark {
  stage: AuditStage;
  at: number; // ms epoch
}

/** Which stage was running at `ms` (null before the first mark). */
export function stageAt(marks: readonly StageMark[], ms: number): AuditStage | null {
  let cur: AuditStage | null = null;
  for (const m of marks) {
    if (m.at <= ms) cur = m.stage;
    else break;
  }
  return cur;
}

/**
 * Prepare the proxy log for a new audit and return the offset its lines will start at.
 * Rotates a large log first (so "allowed" logging, which the proxy stops at 256 MB, keeps
 * working): the proxy appends with a fresh open() per event, so a rename is safe.
 */
export async function proxyLogOffset(path = PROXY_EVENTS_PATH): Promise<number> {
  try {
    const { size } = await stat(path);
    if (size > ROTATE_BYTES) {
      await rename(path, `${path}.1`);
      return 0;
    }
    return size;
  } catch {
    return 0;
  }
}

/**
 * Planted canaries are fakes, but a report that prints one whole looks like a leaked key (and
 * could be replayed into a later audit's proxy log). Keep the recognisable prefix only.
 */
export const maskCanaries = (s: string | undefined) => (s === undefined ? undefined : s.replace(/AKIAVIBE[0-9A-F]{4,}/gi, "AKIAVIBE…"));

const cap = (s: string | undefined, n: number) => (s === undefined ? undefined : s.length > n ? `${s.slice(0, n)}…` : s);

interface ProxyRead {
  entries: ContainmentEntry[];
  findings: Finding[];
}

type ProxyEntry = Extract<ContainmentEntry, { source: "proxy" }>;

/**
 * Read this audit's proxy events. Lines tagged with another audit are skipped; untagged lines
 * (no proxy state was active, e.g. intake) count only inside this audit's time window, which
 * is sound because VM 2 runs one audit at a time. Allowed requests are folded into one entry
 * per (stage, method, host); other verdicts are kept individually up to a cap, then counted.
 * Exfil attempts also become findings (one per leaked variable): a canary or key placeholder
 * leaving the sandbox is proof, not suspicion. Everything here is bounded no matter how much
 * the sandbox logs: a flood can't hide an exfil line, grow the report, or exhaust memory.
 */
export async function readProxyEvents(opts: {
  auditId: string;
  offset: number;
  windowStartMs: number;
  windowEndMs: number;
  marks: readonly StageMark[];
  path?: string;
  /** Override for tests. */
  lineBudget?: number;
}): Promise<ProxyRead> {
  const budget = opts.lineBudget ?? LINE_BUDGET;
  const path = opts.path ?? PROXY_EVENTS_PATH;
  let start = opts.offset;
  try {
    if ((await stat(path)).size < start) start = 0; // truncated or replaced since we began
  } catch {
    return { entries: [], findings: [] };
  }

  const allowed = new Map<string, { e: ProxyEntry; n: number; keys: Set<string> }>();
  const kept: Record<"blocked" | "exfil", ProxyEntry[]> = { blocked: [], exfil: [] };
  // Overflow past the per-verdict cap, counted per stage so egressFindings still sees it.
  const dropped = new Map<string, { verdict: "blocked" | "exfil"; stage: AuditStage | null; n: number; at: string }>();
  let evasiveExtra = 0;
  // The proxy counts repeats per (kind, host, reason, method) across stages; its sampled
  // lines carry that running total. Track what we've accounted so each line adds its delta.
  const accounted = new Map<string, number>();
  const exfil = new Map<string, { f: Finding; hosts: Set<string>; extra: number }>();
  let lines = 0;

  const rl = createInterface({ input: createReadStream(path, { start, encoding: "utf8" }), crlfDelay: Infinity });
  try {
    for await (const line of rl) {
      if (!line || line.length > 8192) continue;
      // Over budget: keep scanning, but only parse lines that can be an exfil event.
      if (++lines > budget && !line.includes(EXFIL_MARK)) continue;
      let raw: unknown;
      try {
        raw = JSON.parse(line);
      } catch {
        continue; // a partial last line while the proxy is mid-write
      }
      const parsed = ProxyEvent.safeParse(raw);
      if (!parsed.success) continue;
      const ev = parsed.data;
      // Peers the proxy refused aren't sandbox activity (anything on the VPC can knock on
      // :8080), and the event names an infra address: not for the report.
      if (ev.kind === "client_rejected") continue;
      const ms = ev.ts * 1000;
      if (ev.auditId !== null && ev.auditId !== opts.auditId) continue;
      if (ev.auditId === null && (ms < opts.windowStartMs || ms > opts.windowEndMs)) continue;

      // The worker's own stage marks are authoritative (the proxy state stays "run" through
      // dynamic/report); the proxy's label is only a fallback, and only if it's a real stage.
      const tagged = AuditStage.safeParse(ev.stage);
      const stage = stageAt(opts.marks, ms) ?? (tagged.success ? tagged.data : null);
      const host = maskCanaries(cap(ev.host, 253));
      const at = new Date(ms).toISOString();
      const entry: ProxyEntry = {
        source: "proxy",
        at,
        stage,
        verdict: ev.kind,
        method: cap(ev.method, 16),
        host: host && ev.port && ev.port !== 443 && ev.port !== 80 ? `${host}:${ev.port}` : host,
        path: maskCanaries(cap(ev.path, 300)),
        reason: cap(ev.reason, 200),
        keyVar: cap(ev.var, 64),
      };

      if (ev.kind === "allowed") {
        // Untagged counters are shared by every audit since the proxy started: trust 1/line.
        let n = 1;
        if (ev.auditId !== null) {
          const pk = `${ev.host}|${ev.reason}|${ev.method}`;
          const before = accounted.get(pk) ?? 0;
          const total = ev.repeat ? Math.max(ev.repeat, before + 1) : before + 1;
          accounted.set(pk, total);
          n = total - before;
        }
        const k = `${stage}|${entry.method}|${entry.host}`;
        let cur = allowed.get(k);
        if (!cur) {
          if (allowed.size >= 2000) continue; // distinct hosts are sandbox-chosen: bound them
          cur = { e: { ...entry, path: undefined, keyVar: undefined }, n: 0, keys: new Set() };
          allowed.set(k, cur);
        }
        cur.n += n;
        for (const v of ev.swapped ?? []) if (cur.keys.size < 8) cur.keys.add(cap(v, 64)!);
        continue;
      }

      // A sampled line stands for every identical event since the last one we saw (the proxy's
      // repeat is a running total per key): count the delta, not the total.
      let n = 1;
      if (ev.auditId !== null) {
        const pk = `${ev.kind}|${ev.host}|${ev.reason}|${ev.method}`;
        const before = accounted.get(pk) ?? 0;
        const total = ev.repeat ? Math.max(ev.repeat, before + 1) : before + 1;
        accounted.set(pk, total);
        n = total - before;
      }
      const counted = n > 1 ? { ...entry, repeat: n } : entry;
      const bucket = kept[ev.kind];
      if (bucket.length < KEEP_PER_VERDICT) bucket.push(counted);
      // A flood of plain blocks must not push out the one request that shows intent.
      else if (ev.kind === "blocked" && evasiveExtra < MAX_EVASIVE_EXTRA && isEvasiveBlock(entry)) {
        evasiveExtra++;
        bucket.push(counted);
      } else {
        const dk = `${ev.kind}|${stage}`;
        const cur = dropped.get(dk) ?? { verdict: ev.kind, stage, n: 0, at };
        cur.n += n;
        if (at > cur.at) cur.at = at;
        dropped.set(dk, cur);
      }

      if (ev.kind === "exfil") {
        const what = entry.keyVar ?? "canary";
        const cur = exfil.get(what);
        if (cur) {
          if (entry.host && !cur.hosts.has(entry.host)) {
            if (cur.hosts.size < MAX_HOSTS_PER_FINDING) cur.hosts.add(entry.host);
            else cur.extra++;
          }
        } else if (exfil.size < MAX_EXFIL_FINDINGS) {
          exfil.set(what, { f: exfilFinding(exfil.size + 1, entry), hosts: new Set(entry.host ? [entry.host] : []), extra: 0 });
        }
      }
    }
  } finally {
    rl.close();
  }

  const entries: ContainmentEntry[] = [...kept.blocked, ...kept.exfil];
  for (const { verdict, stage, n, at } of dropped.values()) {
    entries.push({
      source: "proxy",
      at, // the last overflowed event in that stage
      stage,
      verdict,
      reason: `${n} more ${verdict} event(s) not listed`,
      repeat: n,
    });
  }
  for (const { e, n, keys } of allowed.values()) {
    entries.push({ ...e, ...(n > 1 ? { repeat: n } : {}), ...(keys.size ? { keyVar: [...keys].join(",") } : {}) });
  }
  const findings = [...exfil.values()].map(({ f, hosts, extra }) => {
    if (hosts.size <= 1 && !extra) return f;
    const list = [...hosts].join(", ") + (extra ? ` and ${extra} more` : "");
    return { ...f, description: `${f.description} It tried ${hosts.size + extra} hosts in all: ${list}.` };
  });
  return { entries, findings };
}

const EXFIL_MARK = '"kind":"exfil"';

function exfilFinding(n: number, e: ProxyEntry): Finding {
  const what = e.keyVar ? `the ${e.keyVar} value` : "a planted canary secret";
  return {
    id: `f-exfil-${n}`,
    severity: "critical",
    // At install/build time it's install-time malware (score cap + banner); later it's the app.
    category: e.stage === "install" || e.stage === "build" ? "supply_chain" : "secret_exposure",
    title: "Secret exfiltration attempt",
    description:
      `During the ${e.stage ?? "audit"} stage, code in the sandbox tried to send ${what} to ${e.host ?? "an external host"}. ` +
      "The egress proxy blocked it; on a real deployment that value would have left.",
    confirmed: true,
    evidence: [
      {
        kind: "http",
        method: e.method ?? "?",
        url: `${e.host ?? ""}${e.path ?? ""}` || "(unknown)",
        status: 403,
        bodyExcerpt: e.reason ? `blocked: ${e.reason}` : "blocked by the egress proxy",
      },
    ],
    fix: "Find the code (often an install script or a dependency) that reads the variable and sends it out, and remove it.",
    source: "proxy",
  };
}

// iptables LOG line, as written to kern.log:
// 2026-11-04T11:29:05.747095+00:00 vibe-sbx kernel: VIBEAUDIT-DROP egress IN=br-… OUT=… SRC=… DST=1.1.1.1 … PROTO=TCP SPT=… DPT=443 …
// [^\[]*? keeps matching inside the outer header: ICMP errors embed the offending packet as
// "[SRC=... DST=... PROTO=UDP ... DPT=53]", whose fields must not be mistaken for the drop's own.
const FW_RE = /^(\S+) \S+ kernel: (?:\[[^\]]*\] )?VIBEAUDIT-DROP (egress|host) [^\[]*?\bDST=([0-9a-fA-F.:]{2,45}) [^\[]*?\bPROTO=([A-Za-z0-9]{1,10})(?: [^\[]*?\bDPT=(\d{1,5}))?/;

/** Parse the drop lines for this audit's bridge (the caller greps by bridge first). */
export function parseFirewallDrops(text: string, marks: readonly StageMark[], windowStartMs: number): ContainmentEntry[] {
  const out: ContainmentEntry[] = [];
  for (const line of text.split("\n")) {
    const m = FW_RE.exec(line);
    if (!m) continue;
    const ms = Date.parse(m[1]!);
    if (!Number.isFinite(ms) || ms < windowStartMs - 5_000) continue; // a reused bridge name from long ago
    out.push({
      source: "firewall",
      at: new Date(ms).toISOString(),
      stage: stageAt(marks, ms),
      direction: m[2] as "egress" | "host",
      proto: m[4]!.toLowerCase(),
      dst: m[3]!,
      dport: m[5] ? Number(m[5]) : undefined,
    });
  }
  return out;
}

const RANK: Record<string, number> = { exfil: 0, limit: 1, blocked: 2, firewall: 3, allowed: 4 };
const rank = (e: ContainmentEntry) => RANK[e.source === "proxy" ? e.verdict : e.source] ?? 5;

/**
 * Merge, cap and order the log. If over the cap, the least interesting entries (allowed
 * traffic, then firewall noise) are dropped first; the result is chronological.
 */
export function mergeContainment(...parts: ContainmentEntry[][]): ContainmentEntry[] {
  let all = parts.flat();
  if (all.length > MAX_ENTRIES) {
    all = all
      .map((e, i) => ({ e, i }))
      .sort((a, b) => rank(a.e) - rank(b.e) || a.i - b.i)
      .slice(0, MAX_ENTRIES)
      .map(({ e }) => e);
  }
  return all.sort((a, b) => a.at.localeCompare(b.at));
}

/** Stages where the code running is the repo's install/build scripts and its dependencies'. */
const SUPPLY_CHAIN_STAGES = new Set<AuditStage>(["install", "build"]);
const MAX_EGRESS_EVIDENCE = 5;
/** Proxy reasons that mean "a host we don't expect", which legitimate binary downloaders also hit. */
const PLAIN_HOST_BLOCK = /^host not allowed in stage /;
/** The "N more blocked event(s) not listed" overflow row readProxyEvents adds. */
const OVERFLOW_ROW = /^\d+ more (?:blocked|exfil) event\(s\) not listed$/;
/** More blocked install/build requests than this is itself a sign of intent (scanning, beaconing). */
const BLOCK_FLOOD = 300;
/** DNS drops past this look like data smuggled out in queries rather than one confused client. */
const DNS_FLOOD = 20;
/**
 * Telemetry hosts well-known tools phone home to on their own (the sandbox env opts out, but
 * not every version honours it). Plain requests to these are reported at info level; anything
 * evasive is still not excused.
 */
const KNOWN_TOOL_HOSTS = new Set(["telemetry.nextjs.org", "telemetry.vercel.com", "checkpoint.prisma.io"]);
/** The package registries are allowed in install but not build, where tools still poke them (lockfile patching, update checks). */
const REGISTRY_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com"]);
/** Binary CDNs (storage.googleapis.com and the like) are deliberately absent: anyone can host a payload there. */
const isKnownToolBlock = (e: ProxyEntry) => {
  const h = stripPort(e.host ?? "");
  return KNOWN_TOOL_HOSTS.has(h) || (e.stage === "build" && REGISTRY_HOSTS.has(h));
};

/** Hosts of the providers the sandbox plants key slots for (api.openai.com...). */
const PROVIDER_HOSTS = new Set(Object.values(KEY_PROVIDERS).flat());
/**
 * The app calling its own AI/payments API while it builds (a statically generated page that asks
 * OpenAI for text): its key slot holds a canary, the build stage allows no API host, so the call
 * is blocked. That is the app doing its job, not install-time code reaching out: it stays in
 * the containment log but isn't a supply-chain finding. Only plain requests qualify.
 */
const isOwnApiAtBuild = (e: ProxyEntry) => e.stage === "build" && PROVIDER_HOSTS.has(stripPort(e.host ?? "")) && !isEvasiveBlock(e);

/** A block that isn't just "a GET to a host off the allowlist": raw socket, IP literal, odd port, a body, an upgrade... */
export function isEvasiveBlock(e: { reason?: string; method?: string }): boolean {
  if (!PLAIN_HOST_BLOCK.test(e.reason ?? "")) return true;
  return !(e.method === undefined || e.method === "GET" || e.method === "HEAD" || e.method === "CONNECT");
}

type FirewallEntry = Extract<ContainmentEntry, { source: "firewall" }>;

/**
 * Turn egress that the sandbox stopped during install/build into findings. The containment log
 * proves the attempt was contained; these say the repo (or a dependency of it) attempted it,
 * which is a supply-chain red flag in its own right. Allowed traffic never counts, and nothing
 * from run/dynamic does (an app calling an API we didn't key is not hostile).
 *  - Firewall drops: the connection skipped the HTTP(S)_PROXY the sandbox is told to use.
 *    Critical for anything but DNS: package managers and binary downloaders honour the proxy,
 *    so a direct socket is deliberate. DNS-only drops are a client that ignores the proxy and
 *    resolves names itself: medium.
 *  - Proxy blocks: high when the request was evasive or carried data (raw TCP/UDP, IP literal,
 *    odd port, non-GET, bodies); medium when it was only a GET to a host off the allowlist.
 * Exfil attempts already have their own critical findings and aren't repeated here.
 * Known limit: a dependency that only phones home once the app is running (run/dynamic) is not
 * caught here, since app traffic to unkeyed APIs looks the same; it still shows in the log.
 */
export function egressFindings(entries: readonly ContainmentEntry[]): Finding[] {
  const fw: FirewallEntry[] = [];
  const px: ProxyEntry[] = [];
  const pxStages: ProxyEntry[] = [];
  let overflow = 0;
  // Firewall times come from VM 2's clock and stage marks from VM 1's. Both are NTP-synced
  // (ms skew), and the run container's first packet comes >1s after the run mark (docker start
  // over SSH + node boot), so a run-stage connection isn't mistaken for a build one. No grace
  // window on purpose: it would hide a postinstall that connects out just before install ends.
  for (const e of entries) {
    if (!e.stage || !SUPPLY_CHAIN_STAGES.has(e.stage)) continue;
    if (e.source === "firewall") fw.push(e);
    else if (e.source === "proxy" && e.verdict === "blocked" && !/^no active audit/.test(e.reason ?? "") && !isOwnApiAtBuild(e)) {
      pxStages.push(e);
      if (!e.host && !e.method && OVERFLOW_ROW.test(e.reason ?? "")) overflow += e.repeat ?? 0;
      else px.push(e);
    }
  }
  const out: Finding[] = [];

  if (fw.length) {
    const isDns = (e: FirewallEntry) => e.dport === 53;
    const direct = fw.filter((e) => !isDns(e));
    const shown = (direct.length ? direct : fw).slice(0, MAX_EGRESS_EVIDENCE);
    const dests = distinct(fw.map(fwTarget));
    const dnsFlood = !direct.length && fw.length > DNS_FLOOD;
    out.push({
      id: "f-egress-direct",
      severity: direct.length ? "critical" : dnsFlood ? "high" : "medium",
      category: "supply_chain",
      title: direct.length ? "Install-time code opened a direct network connection" : "Install-time code resolved hosts outside the proxy",
      description:
        `During ${stagesOf(fw)}, code from the repo or one of its dependencies tried to reach ${listOf(dests)} without going through the ` +
        "egress proxy it was given. The sandbox firewall dropped it, so nothing left; on a developer laptop or a CI runner it would have. " +
        (direct.length
          ? "Package managers and legitimate download scripts honour the proxy, so a raw connection like this is deliberate: treat the repo as hostile until you know what made it."
          : dnsFlood
            ? `Only DNS lookups were seen, but ${fw.length} of them: a confused download script makes a few, data smuggled out in DNS queries makes many.`
            : "Only DNS lookups were seen, which is usually a download script that ignores proxy settings, but it can also be data smuggled out in DNS queries."),
      confirmed: true,
      evidence: shown.map((e) => ({ kind: "network" as const, control: "firewall" as const, at: e.at, stage: e.stage, target: fwTarget(e), detail: `direction ${e.direction}` })),
      fix: "Check package.json scripts (preinstall/install/postinstall/prepare, build) and each dependency's install scripts for network calls; remove the code or the dependency. Install with --ignore-scripts until you have.",
      source: "proxy",
    });
  }

  if (pxStages.length) {
    const evasive = px.filter(isEvasiveBlock);
    const total = px.reduce((n, e) => n + (e.repeat ?? 1), 0) + overflow;
    const flood = total > BLOCK_FLOOD;
    const known = !evasive.length && !flood && !overflow && px.every(isKnownToolBlock);
    const shown = [...evasive, ...px.filter((e) => !isEvasiveBlock(e))].slice(0, MAX_EGRESS_EVIDENCE);
    const hosts = distinct(px.map((e) => e.host ?? "(unknown host)"));
    out.push({
      id: "f-egress-blocked",
      severity: evasive.length || flood ? "high" : known ? "info" : "medium",
      category: "supply_chain",
      title: evasive.length
        ? "Install-time code made a request the proxy refused"
        : flood
          ? "Install-time code flooded the proxy with blocked requests"
          : known
            ? "A build tool tried to phone home"
            : "Install-time code contacted an unexpected host",
      description:
        `During ${stagesOf(pxStages)}, code from the repo or one of its dependencies sent ${total} request(s) the egress proxy blocked` +
        (hosts.length ? `, to ${listOf(hosts)}${overflow ? " and others not listed" : ""}. ` : ". ") +
        (evasive.length
          ? "Some were not plain downloads (a raw socket, an IP address, an odd port, or a request carrying data), which install scripts have no reason to send."
          : flood
            ? "Install scripts fetch a handful of things; this many blocked requests looks like scanning or beaconing."
            : known
              ? "These hosts belong to well-known tools (telemetry or prebuilt-binary downloads), so this is almost certainly benign, but it is still traffic your install sends out."
              : "They were plain downloads from hosts outside the package-registry allowlist. Some packages fetch prebuilt binaries this way, so check which one did before assuming the worst."),
      confirmed: true,
      evidence: (shown.length ? shown : pxStages.slice(0, 1)).map((e) => ({
        kind: "network" as const,
        control: "proxy" as const,
        at: e.at,
        stage: e.stage,
        target: `${e.method ?? ""} ${e.host ?? ""}${e.path ?? ""}`.trim() || "(unknown)",
        detail: [e.reason, e.repeat ? `×${e.repeat}` : null].filter(Boolean).join(" · ") || undefined,
      })),
      fix: "Find which install/build script or dependency makes these requests (npm explain, or the package's own scripts) and remove it or pin a version that doesn't.",
      source: "proxy",
    });
  }
  return out;
}

const fwTarget = (e: FirewallEntry) => `${e.proto} ${e.dst}${e.dport ? `:${e.dport}` : ""}`;
const distinct = (xs: string[]) => [...new Set(xs)];
const stripPort = (h: string) => h.replace(/:\d+$/, "").toLowerCase();
const listOf = (xs: string[]) => (xs.length <= MAX_HOSTS_PER_FINDING ? xs.join(", ") : `${xs.slice(0, MAX_HOSTS_PER_FINDING).join(", ")} and ${xs.length - MAX_HOSTS_PER_FINDING} more`);
const stagesOf = (es: readonly { stage: AuditStage | null }[]) => distinct(es.map((e) => e.stage!)).join(" and ");
