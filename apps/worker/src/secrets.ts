import { createHash } from "node:crypto";
import { z } from "zod";
import type { Evidence, Finding } from "@vibeaudit/shared";
import type { Sandbox } from "./sandbox";

/**
 * Secret scan: known credential formats (and hardcoded credential assignments) in the repo's
 * files and, after a build, in the client bundle it produced. A walker runs IN the sandbox and
 * returns only candidate lines (the sandbox's stdout is capped, and a real repo or a Next.js
 * build is far bigger than that cap); everything it returns is UNTRUSTED data that is only
 * regex-matched here on VM 1, never evaluated.
 *
 * Every secret value is masked before it goes into a finding (and maskSecrets() is applied to
 * the whole report and to build logs), so a public report never republishes a real key.
 */

// ---------------------------------------------------------------- collection (in the sandbox)

/**
 * Output budget for one walk, in serialized bytes (what JSON.stringify of each line and path
 * actually costs, escaping and UTF-8 included). Sandbox.run caps stdout at 256 KB; a final
 * backstop in the script drops files until the output fits under OUT_HARD_CAP.
 */
const OUT_BUDGET = 180_000;
const OUT_HARD_CAP = 240_000;
const MAX_LINE = 2000;
const MAX_WINDOWS_PER_LINE = 200;
const MAX_LINES_PER_FILE = 200;

/** Key formats only (every RULES prefix, PEM, credentialed URLs). Used alone for bundles. */
const KEY_PREFILTER = String.raw`\b(?:AKIA|ASIA)|\b[sr]k_(?:live|test)_|\bsk-|\bnpm_|\bgh[pousr]_|github_pat_|\bxox[baprs]-|\bSG\.|\beyJ|\bAIza|PRIVATE KEY|://[^\s/@:]{0,100}:[^\s/@]{1,200}@`;
/**
 * Repo prefilter: key formats plus the credential words ASSIGN_RE keys on. A line that can't
 * match any rule on VM 1 isn't sent. Must stay a superset of what scanFiles() looks for
 * (.env files send every KEY=value line regardless).
 */
const REPO_PREFILTER = String.raw`${KEY_PREFILTER}|secret|passw|pwd|api_?key|apikey|token|private_?key|auth_?key|access_?key|signing_?key|encrypt|jwt_?key|master_?key|hmac`;

/**
 * The walker. Reads files only (no network, no exec, only node builtins; `node -e` loads no
 * repo code). Returns {files:[{p, c, l:[[lineNo, text]...]}], found:{marker:[paths]}, t}:
 *  - l: candidate lines (KEY=value lines of .env files); long minified lines become windows
 *    around each prefilter hit, keeping the line number; a PEM header also sends the next line.
 *  - c: 1 if the file starts with "use client".
 *  - found: which files contain each planted marker value (bundle scan). Marker search keeps
 *    going after the line budget runs out: it costs no output.
 *  - t: 1 if anything was left out (budget, per-file line cap, backstop): the scan is partial.
 */
export function scanScript(roots: string[], bundle: boolean, markers: string[]): string {
  // Bundles: the exact key-format rules (case-sensitive), not a loose prefilter. Minified chunks
  // are full of "auth"/"token"/"eyJ" noise that would otherwise eat the whole budget in one file.
  const pre = bundle ? bundlePrefilter() : REPO_PREFILTER;
  const flags = bundle ? "" : "i";
  return `
const fs=require("fs"),path=require("path");
const ROOTS=${JSON.stringify(roots)},BUNDLE=${bundle},MARKERS=${JSON.stringify(markers)};
const SKIP=new Set(["node_modules",".git","coverage",".cache",".turbo",".vercel"${bundle ? "" : ',"dist","build",".next","out"'}]);
const EXT=new Set([".js",".jsx",".ts",".tsx",".mjs",".cjs",".html",".vue",".svelte",".json",".yml",".yaml",".toml",".txt",".sh",".py",".map",".env"]);
const PRE=new RegExp(${JSON.stringify(pre)},${JSON.stringify(flags)}),PREG=new RegExp(${JSON.stringify(pre)},${JSON.stringify(`g${flags}`)});
const BUDGET=${OUT_BUDGET},HARD=${OUT_HARD_CAP},MAXLINE=${MAX_LINE},MAXW=${MAX_WINDOWS_PER_LINE},MAXL=${MAX_LINES_PER_FILE},MAXSIZE=4000000;
let used=0,full=0,part=0,walked=0;const files=[],found={};
const cost=s=>Buffer.byteLength(JSON.stringify(s))+12;
const want=n=>/^\\.env/.test(n)||n===".npmrc"||(EXT.has(path.extname(n).toLowerCase())&&!/(^|[-.])lock\\b|shrinkwrap/i.test(n));
function scan(rel,c,isEnv){
  for(const m of MARKERS){if(c.includes(m)){const a=found[m]||(found[m]=[]);if(a.length<5)a.push(rel)}}
  if(full)return;
  const out=[];let fileCost=cost(rel)+24;
  const take=(n,s)=>{const k=cost(s)+(out.length?0:fileCost);if(used+k>BUDGET){full=1;return false}used+=k;out.push([n,s]);return true};
  const lines=c.split("\\n");
  for(let i=0;i<lines.length&&!full;i++){
    if(out.length>=MAXL){part=1;break}
    const l=lines[i];
    if(isEnv?!/^\\s*(?:export\\s+)?[A-Za-z_][A-Za-z0-9_.]*\\s*=/.test(l):!PRE.test(l))continue;
    if(l.length<=MAXLINE){if(!take(i+1,l))break}
    else{
      PREG.lastIndex=0;let m,w=0,last=-1;
      while((m=PREG.exec(l))){
        if(w>=MAXW){part=1;break}
        if(m.index+200<=last)continue;
        const s=Math.max(0,m.index-200),e=Math.min(l.length,m.index+400);
        if(!take(i+1,l.slice(s,e)))break;
        last=e;w++;
      }
    }
    if(/PRIVATE KEY/.test(l)&&i+1<lines.length)take(i+2,lines[i+1].slice(0,MAXLINE));
  }
  if(out.length)files.push({p:rel,c:/^\\s*["']use client["']/.test(c.slice(0,500))?1:0,l:out});
}
function walk(d,depth){
  if(depth>12){part=1;return}
  if(walked>5000||(full&&!MARKERS.length))return;
  let ents;try{ents=fs.readdirSync(d,{withFileTypes:true})}catch{return}
  // Files before subdirectories, so root files (.env, config) are seen before the budget can run out.
  ents.sort((a,b)=>(a.isDirectory()?1:0)-(b.isDirectory()?1:0));
  for(const e of ents){
    if(walked>5000||(full&&!MARKERS.length))break;
    const p=path.join(d,e.name);
    if(e.isDirectory()){if(!SKIP.has(e.name)&&(BUNDLE||!e.name.startsWith(".")||e.name===".github"))walk(p,depth+1);continue}
    if(!e.isFile()||!want(e.name))continue;
    if(BUNDLE&&!/\\.(m?js|html)$/i.test(e.name))continue;
    let st;try{st=fs.statSync(p)}catch{continue}
    if(st.size>MAXSIZE){part=1;continue}
    let c;try{c=fs.readFileSync(p,"utf8")}catch{continue}
    walked++;scan(path.relative(".",p),c,/^\\.env/.test(e.name));
  }
}
for(const r of ROOTS){try{if(fs.statSync(r).isDirectory())walk(r,0)}catch{}}
if(walked>5000)part=1;
let out=JSON.stringify({files,found,t:full||part?1:0});
// Backstop: whatever the accounting missed, never exceed the sandbox's stdout cap.
while(Buffer.byteLength(out)>HARD&&files.length){files.splice(Math.floor(files.length*0.9));out=JSON.stringify({files,found,t:1})}
process.stdout.write(out);
`;
}

/** A file as the scanner sees it: candidate lines with their real line numbers. */
export interface ScanFile {
  path: string;
  /** Starts with "use client" (React client component). */
  client?: boolean;
  lines: [number, string][];
}

export interface Collected {
  files: ScanFile[];
  /** marker value -> files it appears in (bundle scan). */
  found: Record<string, string[]>;
  /** The walk ran out of budget, or its output couldn't be read: results are partial or empty. */
  partial: boolean;
}

const FileItem = z.object({
  p: z.string().max(1000),
  c: z.union([z.literal(0), z.literal(1)]),
  l: z.array(z.tuple([z.number().int().positive(), z.string().max(MAX_LINE + 10)])).max(MAX_LINES_PER_FILE + 5),
});

/** Parse the walker's output. Each file is validated on its own: one bad item doesn't empty the scan. */
export function parseCollected(stdout: string, markers: readonly string[]): Collected {
  let raw: unknown;
  try {
    raw = JSON.parse(stdout.trim() || "null");
  } catch {
    return { files: [], found: {}, partial: true }; // truncated by the output cap, or garbage
  }
  if (!raw || typeof raw !== "object") return { files: [], found: {}, partial: true };
  const r = raw as { files?: unknown; found?: unknown; t?: unknown };
  const files: ScanFile[] = [];
  for (const item of Array.isArray(r.files) ? r.files.slice(0, 5000) : []) {
    const ok = FileItem.safeParse(item);
    if (ok.success) files.push({ path: ok.data.p.slice(0, 400), client: ok.data.c === 1, lines: ok.data.l });
  }
  // Only markers we planted are believed; the paths are sandbox text, length-capped.
  const found: Record<string, string[]> = {};
  if (r.found && typeof r.found === "object") {
    for (const m of markers) {
      const v = (r.found as Record<string, unknown>)[m];
      if (Array.isArray(v)) found[m] = v.filter((x): x is string => typeof x === "string").slice(0, 5).map((x) => x.slice(0, 400));
    }
  }
  return { files, found, partial: r.t === 1 };
}

async function collect(sandbox: Sandbox, image: string, name: string, roots: string[], bundle: boolean, markers: string[] = []): Promise<Collected> {
  const r = await sandbox.run({ role: "app", image, cmd: ["node", "-e", scanScript(roots, bundle, markers)], timeoutMs: 60_000, name });
  return parseCollected(r.stdout, markers);
}

/** Repo files for the secret scan (includes committed .env files, unlike the LLM review). */
export const collectRepoFiles = (sandbox: Sandbox, image: string, id: string) => collect(sandbox, image, `va-${id}-secrets`, ["."], false);

/**
 * Build output that is served to browsers, per framework. Express (and unknown) builds are
 * server code (e.g. tsc into dist/), so they aren't a client bundle; their public/ dir is
 * already covered by the repo scan.
 */
export function bundleRoots(framework: string): string[] {
  if (framework === "nextjs") return [".next/static", "out"];
  if (framework === "vite") return ["dist"];
  return [];
}
export const collectBundleFiles = (sandbox: Sandbox, image: string, id: string, framework: string, markers: string[]) =>
  collect(sandbox, image, `va-${id}-bundle`, bundleRoots(framework), true, markers);

// ---------------------------------------------------------------- patterns

interface Rule {
  id: string;
  label: string;
  re: RegExp;
  /** Severity when it sits in server-side code / config. Browser exposure bumps it (see below). */
  severity: Finding["severity"];
  /** Characters of the match that are a fixed, non-secret prefix (shown unmasked). */
  prefix: number;
  /** Publishable by design (e.g. Firebase web keys): only reported, never escalated. */
  publishable?: boolean;
  /** Extra check on the match. */
  accept?: (m: string) => boolean;
}

/** Supabase-style JWT: secret only when its payload says service_role. Anon keys are public. */
function isServiceRoleJwt(tok: string): boolean {
  const part = tok.split(".")[1];
  if (!part || part.length > 4000) return false;
  try {
    const json = JSON.parse(Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as unknown;
    return typeof json === "object" && json !== null && (json as { role?: unknown }).role === "service_role";
  } catch {
    return false;
  }
}

const PEM_HEADER = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/;
/** Base64 key material: on the line after the header, or inline after an escaped "\n". */
const PEM_BODY = /^[A-Za-z0-9+/=]{40,}\s*$/;
const PEM_INLINE_BODY = /PRIVATE KEY(?: BLOCK)?-----(?:\\n|\s)+[A-Za-z0-9+/=]{40,}/;

// Order matters: more specific formats first (an Anthropic key also looks like an OpenAI one).
const RULES: Rule[] = [
  { id: "aws_key", label: "AWS access key", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: "critical", prefix: 4 },
  // Every quantifier is bounded: the text is sandbox-controlled and an unbounded run after a
  // repeatable prefix ("sk-sk-sk-...") backtracks quadratically.
  { id: "stripe_live", label: "Stripe live secret key", re: /\b[sr]k_live_[0-9a-zA-Z]{20,200}\b/g, severity: "critical", prefix: 8 },
  { id: "stripe_test", label: "Stripe test secret key", re: /\b[sr]k_test_[0-9a-zA-Z]{20,200}\b/g, severity: "medium", prefix: 8 },
  { id: "anthropic", label: "Anthropic API key", re: /\bsk-ant-[A-Za-z0-9_-]{20,300}/g, severity: "critical", prefix: 7 },
  { id: "openai", label: "OpenAI API key", re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,300}/g, severity: "critical", prefix: 3, accept: (m) => !m.startsWith("sk-ant-") && !m.startsWith("sk-PLACEHOLDER-") && /\d/.test(m) && /[A-Za-z]/.test(m.slice(3)) },
  { id: "github", label: "GitHub token", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,300})\b/g, severity: "critical", prefix: 4 },
  { id: "slack", label: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,300}/g, severity: "high", prefix: 5 },
  { id: "sendgrid", label: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{16,100}\.[A-Za-z0-9_-]{16,100}/g, severity: "high", prefix: 3 },
  { id: "npm_token", label: "npm access token", re: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: "critical", prefix: 4 },
  { id: "supabase_service", label: "Supabase service-role key", re: /\beyJ[A-Za-z0-9_-]{8,500}\.eyJ[A-Za-z0-9_-]{8,3000}\.[A-Za-z0-9_-]{8,1000}/g, severity: "critical", prefix: 0, accept: isServiceRoleJwt },
  {
    id: "url_creds",
    label: "Database or service password in a connection URL",
    // scheme://user:password@host — the password is what matters.
    re: /\b[A-Za-z][A-Za-z0-9+.-]{1,20}:\/\/[^\s:@/'"`]{1,100}:[^\s@/'"`]{6,200}@[^\s'"`]{1,300}/gi,
    severity: "high",
    prefix: 0,
    accept: (m) => {
      const pw = /:\/\/[^:]*:([^@]*)@/.exec(m)?.[1] ?? "";
      return !PLACEHOLDER.test(pw.replace(/^\$\{.*\}$/, "<")) && !/^(?:pass(?:word)?|postgres|root|admin|user|secret|changeme|\*+)$/i.test(pw) && !/localhost|127\.0\.0\.1/i.test(m);
    },
  },
  { id: "google_api", label: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "low", prefix: 4, publishable: true },
];
/** The bundle walker's filter: exactly the key formats scanFiles reports for bundles. */
const bundlePrefilter = () => [...RULES.map((r) => r.re.source), PEM_HEADER.source].join("|");
const PRIVATE_KEY_RULE ={ id: "private_key", label: "Private key", severity: "critical" as const };

/** `name = "literal"` / `"name": "literal"` where the name looks like a credential. */
const ASSIGN_RE = /\b([A-Za-z0-9_]{0,40}?(?:secret|passw(?:or)?d|pwd|api_?key|apikey|token|private_?key|auth_?key|access_?key|signing_?key|encrypt\w{0,10}_?key|jwt_?key|master_?key|hmac)[A-Za-z0-9_]{0,40})["']?\s*[:=]\s*(["'`])([^"'`\s]{12,200})\2/gi;
/** Credential-looking names that hold something else (a URL, a header name, a hash, an id...). */
const NOT_A_SECRET_NAME = /(?:url|uri|endpoint|path|regex|pattern|hash|hashed|header|name|field|label|type|id|ids|placeholder|input|class|classname|style|mode|format|length|len|count|expiry|expires|expiresin|ttl|cookie|storagekey|storage|key_name|prefix|version|ver|csrf|csrftoken|xsrf|xsrftoken|event|events|route|routes|scope|scopes|status|algo|algorithm|alg|digest|cipher|encoding|sha256|hex|base64|env)$/i;
const ENV_LINE_RE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\s#]{8,500})["']?\s*(?:#.*)?$/;
const SECRETISH_NAME = /secret|passw(?:or)?d|pwd|_pass$|api_?key|apikey|token|private|auth|access_?key|credential|dsn|database_url|connection|signing|encrypt|jwt_?key|master_?key|hmac/i;
/** For public-prefixed names only words that can't be public count (DSNs, anon/maps keys are public by design). */
const STRONG_SECRET_NAME = /secret|private|service_?role|passw(?:or)?d|pwd/i;
const PUBLIC_BY_DESIGN = /dsn|anon|publishable|firebase|maps|mapbox|algolia|posthog|sentry|analytics|measurement|recaptcha_site|site_?key|client_?id/i;
const PLACEHOLDER = /your|example|changeme|change_me|placeholder|dummy|sample|xxxx|\*\*\*|<|>|\$\{|process\.env|import\.meta|todo|replace|insert|redacted|^test|^demo|^fake|localhost|:\/\/|^none$|^null$|^true$|^false$|^AKIAVIBE[0-9A-F]{18}$/i;

function entropy(s: string): number {
  const f = new Map<string, number>();
  for (const c of s) f.set(c, (f.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of f.values()) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
}
/**
 * Dictionary words: weak passwords are a real flaw, but not this heuristic's to report. (The LLM
 * prompt masks them too, deliberately: the reviewer still sees a hardcoded credential exists.)
 */
const WEAK_WORDS = /password|passwd|secret|admin|qwerty|letmein|welcome|123456|abcdef|token|auth|session/i;
/** Identifier-like values (storage keys, event names, versions): lowercase words with separators, or semver. */
const IDENT_VALUE = /^(?:[a-z][a-z0-9]*(?:[._:/-][a-z0-9]+)+|v?\d+\.\d+(?:\.\d+)?[-+.\w]*)$/;
/** Identifier-shaped AND no random-looking segment (8+ chars mixing letters and digits, as in UUIDs or "key-3ax6..."). */
const isIdentifier = (v: string) => (IDENT_VALUE.test(v) || /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) && !v.split(/[._:/-]/).some((s) => s.length >= 8 && /\d/.test(s) && /[a-z]/i.test(s));
const looksRandom = (v: string) => !PLACEHOLDER.test(v) && !WEAK_WORDS.test(v) && !isIdentifier(v) && entropy(v) >= 3.3 && /[0-9]/.test(v) && /[A-Za-z]/.test(v);
/** Storage/lookup key names (TOKEN_KEY = "app_token" is where a token is kept, not a token). */
const secretAssignName = (n: string) => !NOT_A_SECRET_NAME.test(n) && !/(?:token|storage|cache|cookie|session|local)_?key$/i.test(n);

const PUBLIC_ENV_NAME = /\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|EXPO_PUBLIC_)[A-Z0-9_]*/;
const PUBLIC_PREFIX = /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_|EXPO_PUBLIC_)/;

/** Env names that hold config, not secrets. *_URL only counts when it's a credentialed store. */
const ENV_NOT_SECRET = /(?:_IDS?|_NAME|_PATH|_ENDPOINT|_HEADER|_TYPE|_MODE|_PREFIX|_REGION|_EXPIRES?(?:_IN)?|_TTL)$/i;
const isConfigUrl = (n: string) => /_UR[LI]$/i.test(n) && !/DATABASE|DB_|REDIS|MONGO|POSTGRES|MYSQL|CONNECTION|AMQP|DSN/i.test(n);

/** An env var name that holds a secret. A public-prefixed one needs a word that can't be public. */
export function secretEnvName(name: string): boolean {
  if (ENV_NOT_SECRET.test(name) || isConfigUrl(name)) return false;
  if (PUBLIC_PREFIX.test(name)) {
    const rest = name.replace(PUBLIC_PREFIX, "");
    return STRONG_SECRET_NAME.test(rest) && !PUBLIC_BY_DESIGN.test(rest);
  }
  return SECRETISH_NAME.test(name);
}

/**
 * Which env names the sandbox plants a canary for (planner) and reports when one shows up in
 * the client bundle (bundleLeakFindings): one rule for both. Only secret-looking names: a canary
 * in OPENAI_MODEL, JWT_EXPIRES_IN, MAX_TOKENS or CI would break the app, and canaries only matter
 * where a leak would be a real one. Connection strings stay unset too: a canary there is parsed
 * (and fails) or dialled as a hostname, never sent as a credential.
 */
export function canaryWorthy(name: string): boolean {
  if (/(?:_UR[LI]|_DSN|CONNECTION(?:_STRING)?)$/.test(name)) return false;
  // Numbers, durations, model names and flags (MAX_TOKENS, TOKEN_EXPIRES_IN, OPENAI_MODEL).
  if (/(?:^|_)(?:MAX|MIN|LIMIT|COUNT|NUM|SIZE|LENGTH|TIMEOUT|TTL|EXPIRES?|EXPIRY|IN|MODEL|ENABLED?|DISABLED?|USE|FLAG|DEBUG|VERBOSE)(?:_|$)/.test(name)) return false;
  return secretEnvName(name) || (/_KEY$/.test(name) && !PUBLIC_PREFIX.test(name));
}

// ---------------------------------------------------------------- masking

/** Show the fixed prefix and a few characters, never enough to use the key. */
export function maskValue(v: string, prefix = 0): string {
  const keep = Math.min(prefix + 4, Math.floor(v.length / 3));
  return `${v.slice(0, Math.max(0, keep))}…[redacted ${v.length} chars]`;
}

/**
 * Mask every secret-looking value in `text`: the known formats, credential assignments, .env
 * lines and PEM key bodies. Line count is preserved; idempotent (masked output never matches
 * again). Linear-time patterns only: the text is sandbox-controlled.
 */
export function maskSecrets(text: string): string {
  if (!text) return text;
  // Key material only: base64 runs (with real or escaped newlines) right after a PEM header.
  // Keeps the newlines so line numbers don't shift. A bare header in code has no body to mask.
  let out = text.replace(/(-----BEGIN [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----)((?:\\n|[\r\n \t]|[A-Za-z0-9+/=]){40,20000})/g, (all, begin: string, body: string) =>
    /[A-Za-z0-9+/]{40}/.test(body) ? `${begin}…[redacted]${"\n".repeat((body.match(/\n/g) ?? []).length)}` : all,
  );
  for (const r of RULES) {
    out = out.replace(r.re, (m) => {
      if (r.accept && !r.accept(m)) return m;
      // Connection URLs: only the password is secret; keep scheme, user and host readable.
      if (r.id === "url_creds") return m.replace(/(:\/\/[^:@/]{0,100}:)([^@]{0,200})@/, (_a, head: string, pw: string) => `${head}${maskValue(pw)}@`);
      return maskValue(m, r.prefix);
    });
  }
  out = out.replace(ASSIGN_RE, (all, name: string, q: string, val: string) =>
    // Masking is broader than reporting: any non-placeholder value under a secret-ish name.
    secretAssignName(name) && !PLACEHOLDER.test(val) ? all.replace(`${q}${val}${q}`, `${q}${maskValue(val)}${q}`) : all,
  );
  return out
    .split("\n")
    .map((l) => {
      const m = l.length <= 600 ? ENV_LINE_RE.exec(l) : null;
      if (!m || !SECRETISH_NAME.test(m[1]!) || NOT_A_SECRET_NAME.test(m[1]!) || PLACEHOLDER.test(m[2]!) || m[2]!.includes("…[redacted")) return l;
      return l.replace(m[2]!, maskValue(m[2]!));
    })
    .join("\n");
}

/** Mask every free-text field of a finding (evidence included). */
export function maskFinding(f: Finding): Finding {
  const m = maskSecrets;
  return {
    ...f,
    title: m(f.title),
    description: m(f.description),
    ...(f.fix ? { fix: m(f.fix) } : {}),
    evidence: f.evidence.map((e): Evidence => {
      switch (e.kind) {
        case "code":
          return { ...e, snippet: m(e.snippet) };
        case "http":
          return {
            ...e,
            url: m(e.url),
            ...(e.bodyExcerpt !== undefined ? { bodyExcerpt: m(e.bodyExcerpt) } : {}),
            ...(e.headers ? { headers: Object.fromEntries(Object.entries(e.headers).map(([k, v]) => [k, m(v)])) } : {}),
          };
        case "bundle":
          return { ...e, match: m(e.match) };
        case "network":
          return { ...e, target: m(e.target), ...(e.detail !== undefined ? { detail: m(e.detail) } : {}) };
        case "screenshot":
          return { ...e, ...(e.verdict !== undefined ? { verdict: m(e.verdict) } : {}) };
      }
    }),
  };
}

// ---------------------------------------------------------------- scanning

type Where = "browser" | "env" | "server";

export interface SecretHit {
  rule: { id: string; label: string; severity: Finding["severity"]; publishable?: boolean };
  file: string;
  line: number;
  /** The line, already masked. */
  snippet: string;
  where: Where;
  /** Hash of the raw value, to recognise the same secret across scans without keeping it. */
  fingerprint: string;
}

const fingerprint = (v: string) => createHash("sha256").update(v).digest("hex").slice(0, 16);

/** Example/sample/test files: their "secrets" are placeholders or fixtures. */
export const EXAMPLE_FILE = /\.(?:example|sample|template|dist|defaults?)$|(?:^|[/\\])(?:examples?|fixtures?|__tests__|test|tests|spec|__mocks__)[/\\]|\.(?:test|spec)\.[a-z]+$|\.md$/i;

/** Where a file's contents end up. Bundle files are, by definition, in the browser. */
function classify(f: ScanFile, line: string, framework: string, bundle: boolean): Where {
  if (bundle) return "browser";
  const base = f.path.split(/[/\\]/).pop() ?? f.path;
  if (/^\.env/.test(base)) return PUBLIC_ENV_NAME.test(line) ? "browser" : "env";
  if (/(?:^|[/\\])(?:public|static|assets)[/\\]/.test(f.path) || /\.html?$/i.test(f.path)) return "browser";
  if (PUBLIC_ENV_NAME.test(line)) return "browser";
  if (f.client) return "browser";
  // Vite: everything under src/ is bundled for the browser (no server code there).
  if (framework === "vite" && /^src[/\\]/.test(f.path) && !/server|api[/\\]/i.test(f.path)) return "browser";
  return "server";
}

/** A whole file as a ScanFile (tests, and callers that already hold the content). */
export function fromContent(path: string, content: string): ScanFile {
  return { path, client: /^\s*["']use client["']/.test(content.slice(0, 500)), lines: content.split("\n").map((l, i) => [i + 1, l]) };
}

/** Find secrets in files. `bundle`: the files are built client assets. */
export function scanFiles(files: readonly ScanFile[], opts: { framework: string; bundle?: boolean }): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    if (EXAMPLE_FILE.test(f.path)) continue;
    const isEnv = /^\.env/.test(f.path.split(/[/\\]/).pop() ?? "");
    const byNo = new Map<number, string>();
    for (const [n, t] of f.lines) if (!byNo.has(n)) byNo.set(n, t);
    for (const [n, raw] of f.lines) {
      if (hits.length >= 200) break;
      const ln = raw.length > MAX_LINE ? raw.slice(0, MAX_LINE) : raw;
      const add = (rule: SecretHit["rule"], value: string) => {
        const key = `${rule.id}|${value}`;
        if (seen.has(key)) return; // the same key repeated (e.g. two chunks): report once
        seen.add(key);
        hits.push({ rule, file: f.path, line: n, snippet: maskSecrets(snippetAround(ln, value)), where: classify(f, ln, opts.framework, !!opts.bundle), fingerprint: fingerprint(value) });
      };
      let known = false;
      // A private key needs key material after the header; a bare header in code (a
      // startsWith check, a replace) is not a key.
      if (PEM_HEADER.test(ln) && (PEM_INLINE_BODY.test(ln) || PEM_BODY.test(byNo.get(n + 1) ?? ""))) {
        known = true;
        add(PRIVATE_KEY_RULE, `${f.path}:${n}`);
      }
      for (const r of RULES) {
        for (const m of ln.matchAll(r.re)) {
          if (r.accept && !r.accept(m[0])) continue;
          known = true;
          add(r, m[0]);
        }
      }
      // Generic assignments in minified code are mostly noise, and a line a known format already
      // matched (e.g. a public Firebase key) shouldn't be reported a second time as generic.
      if (opts.bundle || known) continue;
      if (isEnv) {
        const m = ENV_LINE_RE.exec(ln);
        if (m && secretEnvName(m[1]!) && looksRandom(m[2]!)) add({ id: "env_value", label: `${m[1]} value`, severity: "high" }, m[2]!);
        continue;
      }
      for (const m of ln.matchAll(ASSIGN_RE)) {
        if (secretAssignName(m[1]!) && looksRandom(m[3]!)) add({ id: "hardcoded", label: "Hardcoded credential", severity: "medium" }, m[3]!);
      }
    }
  }
  return hits;
}

/** A window of the line around the value (minified lines are huge). */
function snippetAround(line: string, value: string): string {
  const t = line.trim();
  if (t.length <= 200) return t;
  const at = t.indexOf(value);
  const from = Math.max(0, (at < 0 ? 0 : at) - 80);
  return `${from > 0 ? "…" : ""}${t.slice(from, from + 200)}${from + 200 < t.length ? "…" : ""}`;
}

const SEV_RANK: Finding["severity"][] = ["info", "low", "medium", "high", "critical"];
const bump = (s: Finding["severity"]): Finding["severity"] => SEV_RANK[Math.min(SEV_RANK.length - 1, SEV_RANK.indexOf(s) + 1)]!;
const MAX_SECRET_FINDINGS = 12;
const MAX_LOCATIONS = 5;

/**
 * Group hits into findings: one per (secret type, where it lives). A secret that reaches the
 * browser is a step worse than the same one in server code (anyone can read it); one in a
 * committed .env is as bad as in server code (it's in git history either way).
 */
export function secretFindings(hits: readonly SecretHit[], opts: { bundle?: boolean } = {}): Finding[] {
  const groups = new Map<string, SecretHit[]>();
  for (const h of hits) {
    const k = `${h.rule.id}|${h.where}`;
    const g = groups.get(k);
    if (g) g.push(h);
    else groups.set(k, [h]);
  }
  const out: Finding[] = [];
  for (const [, g] of groups) {
    if (out.length >= MAX_SECRET_FINDINGS) break;
    const h = g[0]!;
    const browser = h.where === "browser";
    const severity = h.rule.publishable ? h.rule.severity : browser ? bump(h.rule.severity) : h.rule.severity;
    const label = h.rule.label;
    const files = [...new Set(g.map((x) => x.file))];
    const title = opts.bundle
      ? `${label} in the built client bundle`
      : browser
        ? `${label} exposed to the browser`
        : h.where === "env"
          ? `Secret committed in ${h.file.split(/[/\\]/).pop()}`
          : h.rule.id === "hardcoded"
            ? "Hardcoded credential in source"
            : `${label} hardcoded in source`;
    const list = files.slice(0, 3).join(", ");
    const description = opts.bundle
      ? `The production build ships ${g.length > 1 ? `${g.length} ${label} values` : `a ${label}`} to every visitor (${list}). Anyone can open the page's JavaScript and copy it.`
      : browser
        ? `${list} ${files.length > 1 ? "contain" : "contains"} a ${label} in code that is served to the browser${PUBLIC_ENV_NAME.test(h.snippet) ? " (a public env var prefix inlines it into the bundle)" : ""}. Anyone visiting the app can read it.`
        : h.where === "env"
          ? `${h.file} is committed to the repository with a real-looking ${label}. Anyone with read access to the repo, or its history, has it.`
          : `${list} ${files.length > 1 ? "contain" : "contains"} a ${label} written into the source. It is in git history even if removed later.`;
    out.push({
      id: `f-secret-${opts.bundle ? "bundle-" : ""}${out.length + 1}`,
      severity,
      category: "secret_exposure",
      title,
      description: h.rule.publishable
        ? `${description} This key type is meant to be public, so lock it down by API and referrer restrictions rather than hiding it.`
        : description,
      // A key-format match is the key itself, sitting in the file: that is proof, not suspicion.
      // A generic "looks like a password" assignment is a heuristic.
      confirmed: h.rule.id !== "hardcoded",
      evidence: g.slice(0, MAX_LOCATIONS).map((x): Evidence =>
        opts.bundle ? { kind: "bundle", asset: x.file, match: x.snippet } : { kind: "code", file: x.file, line: x.line, snippet: x.snippet },
      ),
      fix: h.rule.publishable
        ? "Restrict the key (allowed APIs, HTTP referrers) in the provider console."
        : "Revoke and rotate this key now (it has been exposed), move it to a server-side environment variable, and remove it from the repo history.",
      source: "secret_scan",
    });
  }
  return out;
}

/**
 * Env vars inlined into the client bundle. During the build every declared env var holds a
 * unique marker (a canary or key placeholder) that the sandbox chose, so a marker found in the
 * built assets proves the build copies that variable into code every visitor downloads; in
 * production it would be the real value. Public-prefixed vars (NEXT_PUBLIC_...) are meant to be
 * inlined and are only reported when their name says they hold a real secret.
 */
export function bundleLeakFindings(found: Readonly<Record<string, string[]>>, planted: Readonly<Record<string, string>>): Finding[] {
  const out: Finding[] = [];
  for (const [name, value] of Object.entries(planted)) {
    if (value.length < 12 || out.length >= MAX_SECRET_FINDINGS) continue;
    const where = (found[value] ?? []).slice(0, MAX_LOCATIONS);
    if (!where.length) continue;
    const isPublic = PUBLIC_PREFIX.test(name);
    const keyVar = value.startsWith("sk-PLACEHOLDER-");
    // Config that isn't a secret (APP_VERSION inlined via next.config env) is not a leak.
    if (!keyVar && !secretEnvName(name) && !canaryWorthy(name)) continue;
    out.push({
      id: `f-bundle-env-${out.length + 1}`,
      severity: "critical",
      category: "secret_exposure",
      title: `${name} is built into the client bundle`,
      description:
        `During the build the sandbox set ${name} to a unique marker value, and that marker turned up in the built browser assets (${where.join(", ")}). ` +
        `In production the real ${name} would be shipped to every visitor${isPublic ? ": the public prefix tells the bundler to inline it, which is wrong for a secret" : ""}.`,
      confirmed: true,
      evidence: where.map((asset): Evidence => ({ kind: "bundle", asset, match: `${name} (the sandbox's marker value for it)` })),
      fix: `Read ${name} only in server code (an API route or server action) and never under a public env prefix; rotate the real value if it has been deployed.`,
      source: "secret_scan",
    });
  }
  return out;
}
