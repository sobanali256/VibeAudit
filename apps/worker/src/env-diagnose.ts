import { ENV_VAR_RE } from "@vibeaudit/shared";

/**
 * Why a build or start failed, when the log says it was configuration. Builds of vibe-coded
 * apps most often die on an env var the sandbox couldn't provide (a secret it only has a canary
 * for, a value with a format we didn't guess). Naming it turns "build failed" into something the
 * owner can act on.
 *
 * The log is sandbox output: untrusted. Only env-var-shaped names (ENV_VAR_RE, upper case) and
 * fixed phrases come out of here, never log text.
 */

const MAX_NAMES = 3;
const MAX_SCAN = 200_000;

/** Patterns whose first group is an env var name. */
const NAMED: RegExp[] = [
  /missing (?:required )?(?:environment|env)(?: variables?)?[:\s]+["'`]?([A-Z][A-Z0-9_]{2,63})/gi,
  /\b([A-Z][A-Z0-9_]{2,63})\b["'`]?\s+(?:(?:environment|env)(?: variable)?\s+)?(?:is|was|are)\s+(?:not set|not defined|missing|required|undefined|empty)/g,
  /(?:environment|env)(?: variable)?\s+["'`]?([A-Z][A-Z0-9_]{2,63})["'`]?\s+(?:is|was)\s+(?:not set|missing|required|undefined|empty|invalid)/gi,
  /\b([A-Z][A-Z0-9_]{2,63})["']?\s*:\s*\[?\s*["']?(?:Required|Invalid|Expected|String must|Invalid url)/g, // zod / t3-env
  /Invalid environment variables?:?[^\n]{0,200}?\b([A-Z][A-Z0-9_]{2,63})\b/g,
  /(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]{2,63})\b[^\n]{0,80}(?:undefined|missing|required|not set)/g,
];

/** Fixed hints for errors that don't name the variable. */
const SHAPES: [RegExp, string][] = [
  [/supabaseUrl is required|Invalid supabaseUrl/i, "a Supabase URL"],
  [/supabaseKey is required/i, "a Supabase key"],
  [/OPENAI_API_KEY environment variable is missing|apiKey.{0,40}(?:missing|required)/i, "an API key"],
  [/TypeError(?: \[ERR_INVALID_URL\])?: Invalid URL/i, "a URL (one was empty or not a valid URL)"],
  [/Error: Invalid `?prisma|Environment variable not found: (?:DATABASE_URL|\w+)/i, "a database URL"],
  [/\bMongo(?:ose|Server|Parse)?\w{0,20}Error\b.{0,80}\b(?:uri|URI)\b/, "a MongoDB connection string"],
  [/NEXTAUTH_SECRET|\[next-auth\]\[error\]\[NO_SECRET\]/, "NEXTAUTH_SECRET"],
];

/** Words that look like env names in these patterns but aren't. */
const NOT_ENV = new Set(["ERROR", "TYPEERROR", "WARN", "INFO", "DEBUG", "HTTP", "HTTPS", "URL", "API", "JSON", "NODE", "THE", "ENV", "PATH", "GET", "POST"]);

export interface EnvDiagnosis {
  /** Env var names the log points at (validated, deduped, capped). */
  names: string[];
  /** A fixed phrase when no name was given, e.g. "a Supabase URL". */
  shape?: string;
}

/** Lines that mention a variable without failing on it ("SENTRY_AUTH_TOKEN is not set, skipping upload"). */
const SOFT = /\b(?:warn(?:ing)?|skipp(?:ing|ed)|optional|deprecat\w{0,10}|not required|will be ignored|falling back)\b/i;

export function diagnoseEnvFailure(log: string): EnvDiagnosis | null {
  const text = log
    .slice(-MAX_SCAN)
    .split("\n")
    .filter((l) => !SOFT.test(l))
    .join("\n");
  const names: string[] = [];
  for (const re of NAMED) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const n = m[1]!;
      if (n !== n.toUpperCase() || !n.includes("_") || NOT_ENV.has(n) || !ENV_VAR_RE.test(n) || names.includes(n)) continue;
      names.push(n);
      if (names.length >= MAX_NAMES) break;
    }
    if (names.length >= MAX_NAMES) break;
  }
  const shape = SHAPES.find(([re]) => re.test(text))?.[1];
  if (!names.length && !shape) return null;
  return { names, ...(shape && !names.length ? { shape } : {}) };
}

/** "needs DATABASE_URL and JWT_SECRET" / "needs a Supabase URL", for the static-only reason. */
export function describeEnvNeed(d: EnvDiagnosis): string {
  const list = d.names.length ? d.names.join(d.names.length === 2 ? " and " : ", ") : d.shape!;
  return `it looks like it needs ${list}. The sandbox never gets real secrets or config, so the report covers the code without the running app`;
}
