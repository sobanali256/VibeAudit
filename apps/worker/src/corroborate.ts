import type { Finding, Severity } from "@vibeaudit/shared";

/**
 * Merge an LLM code-review finding into the stronger finding that reports the SAME issue.
 *
 * The review reads code; probes, the proxy, the vision check and the scanners prove things.
 * When both land on one issue the report used to list (and score) it twice. A review finding is
 * folded into a stronger one only when every guard holds, so a distinct problem is never hidden:
 *  - a topic rule matches the review's own text, and the target finding exists;
 *  - same category family (an XSS "in the admin dashboard" is not the open admin page);
 *  - the review is no more severe than the target, so merging can never lower the score or lift
 *    the malicious-install cap;
 *  - an anchor ties them together: the route the probe actually hit (`/api/users`) appears in
 *    the review's text or code, or, for committed secrets, the same file.
 * The merged review finding is dropped and cited under `corroboratedBy` (title, file, line). Its
 * code is NOT added to the target's evidence: a review line is model output and must not sit
 * next to runtime proof looking proven. Review text is matched against fixed regexes only.
 */

type Anchor = "route" | "file" | "none";

interface Rule {
  /** Which stronger findings this topic can merge into (by id). */
  target: RegExp;
  /** Must match the review finding's title + description. */
  text: RegExp;
  /** Optional second condition on the same text. */
  also?: RegExp;
  /** Must NOT match the same text. */
  not?: RegExp;
  anchor: Anchor;
  /**
   * Skip the category guard. Only for supply-chain targets: the review is never allowed to say
   * supply_chain (so it can't trigger the malicious cap), so its category says nothing here.
   * Those rules demand explicit install-hook wording instead.
   */
  anyCategory?: true;
  /**
   * The review must be about install-time code: it says so (INSTALL wording), or the code it
   * cites is a hook file the install-script scanner itself flagged (scripts/setup.js run by
   * "postinstall"). The model doesn't always say "postinstall" when the file makes it obvious.
   */
  atInstall?: true;
}

/** Install-hook wording. Not the bare word "install" ("default admin password created on install" is not a hook). */
const INSTALL = /\b(?:post|pre)install\b|\binstall[- ](?:time|scripts?|hooks?)\b|lifecycle scripts?/i;

/** What a hostile hook does, for review findings about a flagged hook file that don't say "postinstall". */
/**
 * What a hostile hook DOES (attack behaviour, not topic nouns: a flagged hook file can be ordinary
 * build or app code, e.g. next.config.js reached through "prepare": "next build").
 */
const HOSTILE = /\b(?:post|pre)install\b|\binstall[- ](?:time|scripts?|hooks?)\b|harvest|steal|exfiltrat|enumerat\w*[^.]*\benv|credential theft|reconnaissance|malicious (?:code|payload|script|package|hook|dependency)|breakout|container escape|docker socket|metadata (?:service|endpoint)|phones? home/i;
/** App-bug wording: a review saying this is about the app, not install-time malware, even in a hook file. */
const APP_BUG = /malicious (?:user|input|request|actor|attacker)|\beval\b|\brce\b|hard-?coded|\bxss\b|inject|travers|\bssrf\b|user[- ]supplied|req\.(?:query|body|params)|\bclient\b|bundle/i;

const WRITE = /delet|updat|modif|overwrit|mass.?assign|escalat|\bset (?:their |a |the )?role/i;

const RULES: Rule[] = [
  // These probes proved a READ; a review about writing (delete, update, escalate) is another bug.
  { target: /^f-users$/, text: /\b(users?|accounts?)\b[^.]*\b(dumps?|lists?|exposed?s?|leaks?|returns?|without (?:auth|login)|unauthenticated|public)\b/i, not: WRITE, anchor: "route" },
  { target: /^f-debug$/, text: /\bdebug\b/i, also: /\benv(?:ironment)?\b|process\.env/i, anchor: "route" },
  { target: /^f-idor$/, text: /\bIDOR\b|insecure direct object|ownership/i, not: WRITE, anchor: "route" },
  { target: /^f-admin-header$/, text: /\bheader\b/i, also: /\b(admin|role)\b[^.]*\b(trust|forg|spoof|client|supplied)|\b(trust|forg|spoof|client|supplied)[^.]*\b(admin|role)\b/i, anchor: "route" },
  { target: /^f-chat$/, text: /\b(AI|openai|llm|chat|completions?|gpt)\b/i, also: /\bproxy\b|unauthenticated|without auth|no auth|rate.?limit|unmetered/i, anchor: "route" },
  { target: /^f-crash$/, text: /stack ?traces?/i, anchor: "none" },
  // The probe tests for "*"; a reflected origin with credentials is a different (worse) bug.
  { target: /^f-cors$/, text: /\bCORS\b/, also: /wildcard|\*|any origin/i, not: /reflect|credential/i, anchor: "none" },
  { target: /^f-open-page-\d+$/, text: /\b(page|panel|dashboard|console|route)\b/i, also: /logged.?out|unauthenticated|without (?:auth|login)|no auth|public|anyone/i, anchor: "route" },
  // Install-time behaviour: the target must be supply_chain and the review must be about install-time code.
  { target: /^f-exfil-\d+$/, text: /exfiltrat|smuggl/i, not: APP_BUG, atInstall: true, anchor: "none", anyCategory: true },
  { target: /^f-egress-/, text: /metadata (?:service|endpoint)|egress|outbound|network connection|docker api|phones? home|bypass(?:es|ing)? (?:the |any )?proxy/i, not: APP_BUG, atInstall: true, anchor: "none", anyCategory: true },
  // Same file: the root's own hook and a dependency's hook are different findings.
  { target: /^f-install-\d+$/, text: HOSTILE, not: APP_BUG, atInstall: true, anchor: "file", anyCategory: true },
  // Same file is taken as the same secret (two keys in one config file merge: accepted).
  { target: /^f-secret-\d+$/, text: /\b(secret|api[ _-]?key|credential|token|password)s?\b/i, also: /hard-?coded|committed|\.env\b|bundle|client|browser|front-?end/i, anchor: "file" },
];

const RANK: Severity[] = ["info", "low", "medium", "high", "critical"];
const family = (c: Finding["category"]) => (c === "open_data" ? "missing_auth" : c);

export function corroborate(findings: readonly Finding[]): Finding[] {
  const targets = new Map(findings.filter((f) => f.source !== "llm_review").map((f) => [f.id, { ...f }]));
  const dropped = new Set<Finding>();
  // Hook files the install-script scanner flagged (not package.json, which only names the command).
  const hookFiles = new Set(
    [...targets.values()]
      .filter((t) => /^f-install-\d+$/.test(t.id) && t.category === "supply_chain")
      .flatMap((t) => t.evidence.flatMap((e) => (e.kind === "code" && !/(^|\/)package\.json$/.test(e.file) ? [e.file] : []))),
  );

  for (const f of findings) {
    if (f.source !== "llm_review") continue;
    const t = pickTarget(f, [...targets.values()], hookFiles);
    if (!t || (t.corroboratedBy?.length ?? 0) >= 10) continue;
    const code = f.evidence.find((e) => e.kind === "code" && e.file !== "(unknown)");
    t.corroboratedBy = [
      ...(t.corroboratedBy ?? []),
      {
        source: "llm_review",
        title: f.title.slice(0, 200),
        severity: f.severity,
        ...(code?.kind === "code" ? { file: code.file.slice(0, 300), ...(code.line ? { line: code.line } : {}) } : {}),
      },
    ];
    dropped.add(f);
  }

  return findings.flatMap((f) => (f.source === "llm_review" ? (dropped.has(f) ? [] : [f]) : [targets.get(f.id)!]));
}

function pickTarget(f: Finding, targets: Finding[], hookFiles: Set<string>): Finding | null {
  const text = `${f.title}\n${f.description}`;
  const files = new Set(f.evidence.flatMap((e) => (e.kind === "code" ? [e.file] : [])));
  const atInstall = INSTALL.test(text) || [...files].some((x) => hookFiles.has(x));
  for (const r of RULES) {
    if (!r.text.test(text) || (r.also && !r.also.test(text)) || r.not?.test(text)) continue;
    if (r.atInstall && !atInstall) continue;
    const t = targets.find(
      (t) =>
        r.target.test(t.id) &&
        (r.anyCategory ? t.category === "supply_chain" : family(t.category) === family(f.category)) &&
        RANK.indexOf(f.severity) <= RANK.indexOf(t.severity) &&
        anchored(r.anchor, t, text, files),
    );
    if (t) return t;
  }
  return null;
}

const METHODS = /\b(GET|POST|PUT|PATCH|DELETE)\b/g;

/**
 * Route anchor: the review's own words (title + description, not its file path: in Next.js every
 * finding in app/api/users/[id]/route.ts would "mention" /api/users) name the route the check
 * hit, as a whole path ("/admin" doesn't match inside "/api/admin/users"; "/api/notes" matches
 * "/api/notes/:id"). If the review names HTTP methods, one must be the method the check used:
 * a proven GET dump says nothing about DELETE.
 */
function anchored(kind: Anchor, t: Finding, text: string, files: Set<string>): boolean {
  if (kind === "none") return true;
  if (kind === "file") return t.evidence.some((e) => e.kind === "code" && files.has(e.file));
  const methods = new Set([...text.matchAll(METHODS)].map((m) => m[1]!));
  return t.evidence.some((e) => {
    if (e.kind !== "http") return false;
    const route = routeOf(e.url);
    if (!route || (methods.size && !methods.has(e.method.toUpperCase()))) return false;
    const esc = route.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // Not inside a longer path, and followed by nothing, punctuation, or a parameter segment.
    return new RegExp(`(?<![\\w/.-])${esc}(?![\\w-]|/(?![:\\[{<0-9]))`, "i").test(text);
  });
}

export function routeOf(url: string): string | null {
  let path = url;
  try {
    if (/^https?:\/\//i.test(url)) path = new URL(url).pathname;
  } catch {
    return null;
  }
  const segs = path.split(/[?#]/, 1)[0]!.split("/").filter((s) => s && !/^\d+$/.test(s) && !/^[0-9a-f-]{16,}$/i.test(s));
  return segs.length ? `/${segs.slice(0, 3).join("/")}`.toLowerCase() : null;
}
