import { createReadStream } from "node:fs";
import { rename, stat } from "node:fs/promises";
import { createInterface } from "node:readline";
import { AuditStage, type ContainmentEntry, type Finding, ProxyEvent } from "@vibeaudit/shared";

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
  const dropped: Record<"blocked" | "exfil", number> = { blocked: 0, exfil: 0 };
  // The proxy counts repeats per (kind, host, reason, method) across stages; its sampled
  // lines carry that running total. Track what we've accounted so each line adds its delta.
  const accounted = new Map<string, number>();
  const exfil = new Map<string, { f: Finding; hosts: Set<string>; extra: number }>();
  let lines = 0;
  let lastAt = "";

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
      const host = cap(ev.host, 253);
      const at = new Date(ms).toISOString();
      if (at > lastAt) lastAt = at;
      const entry: ProxyEntry = {
        source: "proxy",
        at,
        stage,
        verdict: ev.kind,
        method: cap(ev.method, 16),
        host: host && ev.port && ev.port !== 443 && ev.port !== 80 ? `${host}:${ev.port}` : host,
        path: cap(ev.path, 300),
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

      const bucket = kept[ev.kind];
      if (bucket.length < KEEP_PER_VERDICT) bucket.push(ev.repeat && ev.auditId !== null ? { ...entry, repeat: ev.repeat } : entry);
      else dropped[ev.kind]++;

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
  for (const verdict of ["blocked", "exfil"] as const) {
    const n = dropped[verdict];
    if (n > 0) {
      entries.push({
        source: "proxy",
        at: lastAt || new Date(opts.windowEndMs).toISOString(),
        stage: null,
        verdict,
        reason: `${n} more ${verdict} event(s) not listed`,
        repeat: n,
      });
    }
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
    category: "secret_exposure",
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
