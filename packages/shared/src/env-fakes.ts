/**
 * Well-formed fake values for env vars that point at a REMOTE DEPENDENCY (a database, a cache,
 * a backend-as-a-service), chosen from the variable NAME only (values from the repo never
 * leave the sandbox). Apps often validate these at build or start time (`createClient(url,
 * key)`, a zod env schema, a connection-string parser) and crash when they're unset. A fake of
 * the right shape gets past that; anything that then really connects goes to a fixed `.invalid`
 * host (RFC 2606: never resolves) that every app container pins to 127.0.0.1 (FAKE_HOSTS), so it
 * fails at once, locally.
 *
 * Deliberately NOT faked: the app's own address and anything derived from it (BASE_URL,
 * SITE_URL, NEXTAUTH_URL, VERCEL_URL, ORIGIN/CORS, COOKIE_DOMAIN, listen HOSTs). Apps fall back
 * to localhost or "*" for those, and a fake would break the app or hide a CORS finding.
 *
 * No secrets here: these are the same for every audit and shown on the approval screen.
 * Secret-shaped names get canaries instead; shapeless names (flags, numbers) get nothing.
 */

export const FAKE_HOST = "vibeaudit-placeholder.invalid";
const DB = `db.${FAKE_HOST}`;
const REDIS = `redis.${FAKE_HOST}`;
const MQ = `mq.${FAKE_HOST}`;
const SENTRY = `sentry.${FAKE_HOST}`;
const SMTP = `smtp.${FAKE_HOST}`;

/** Every hostname a fake can point at: app containers map these to 127.0.0.1. */
export const FAKE_HOSTS = [FAKE_HOST, DB, REDIS, MQ, SENTRY, SMTP] as const;

const PUBLIC_PREFIX = "(?:NEXT_PUBLIC|VITE|PUBLIC|EXPO_PUBLIC|REACT_APP|NUXT_PUBLIC)_";

// First match wins: specific schemes before the generic database rule.
const RULES: [RegExp, string][] = [
  // HTTP REST fronts of KV stores (@upstash/redis, @vercel/kv require https).
  [/_REST(?:_API)?_UR[LI]$/, `https://${REDIS}`],
  [/(?:^|_)MONGO(?:DB)?(?:_[A-Z0-9]+)*_UR[LI]$/, `mongodb://vibeaudit:vibeaudit@${DB}:27017/app`],
  [/(?:^|_)MYSQL(?:_[A-Z0-9]+)*_UR[LI]$|(?:^|_)PLANETSCALE(?:_[A-Z0-9]+)*_UR[LI]$/, `mysql://vibeaudit:vibeaudit@${DB}:3306/app`],
  [/(?:^|_)(?:REDIS|KV|VALKEY)(?:_[A-Z0-9]+)*_UR[LI]$/, `redis://${REDIS}:6379`],
  [/(?:^|_)(?:AMQP|RABBIT(?:MQ)?)(?:_[A-Z0-9]+)*_UR[LI]$/, `amqp://${MQ}:5672`],
  [/^(?:DATABASE|DIRECT|SHADOW_DATABASE)_UR[LI]$|(?:^|_)(?:POSTGRES(?:QL)?|PG|NEON|SUPABASE_DB|DB)(?:_[A-Z0-9]+)*_UR[LI]$/, `postgresql://vibeaudit:vibeaudit@${DB}:5432/app`],
  // Backend-as-a-service endpoints the app's SDK is constructed with.
  [new RegExp(`^(?:${PUBLIC_PREFIX})?(?:SUPABASE|POCKETBASE|PB|CONVEX|APPWRITE|HASURA|STRAPI|DIRECTUS|FIREBASE_DATABASE)_(?:URL|ENDPOINT|API_URL)$`), `https://${FAKE_HOST}`],
  [/(?:^|_)SENTRY_DSN$/, `https://public@${SENTRY}/1`],
  [/^(?:SMTP|MAIL|EMAIL)_HOST$/, SMTP],
  [/^(?:SMTP_FROM|MAIL_FROM|EMAIL_FROM|FROM_EMAIL)$/, `audit@${FAKE_HOST}`],
  // Public client keys (Supabase anon key, Firebase web key...): shipped to browsers by design,
  // so not secrets, but SDK constructors throw without one.
  [new RegExp(`^${PUBLIC_PREFIX}[A-Z0-9_]*(?:_ANON_KEY|_PUBLISHABLE_KEY|_API_KEY|_PUBLIC_KEY)$`), "vibeaudit-placeholder-public-key"],
];

/** The fake value for a remote-dependency var, or null if the name isn't one we fake. */
export function fakeEnvValue(name: string): string | null {
  for (const [re, value] of RULES) if (re.test(name)) return value;
  return null;
}
