import { describe, expect, it } from "vitest";
import { FAKE_HOSTS, fakeEnvValue } from "./env-fakes";

const hostOf = (v: string) => new URL(v).hostname;

describe("fakeEnvValue", () => {
  it("fakes remote dependencies with the right scheme, on a pinned .invalid host", () => {
    const cases: [string, RegExp][] = [
      ["DATABASE_URL", /^postgresql:/],
      ["DIRECT_URL", /^postgresql:/],
      ["POSTGRES_PRISMA_URL", /^postgresql:/],
      ["MONGODB_URI", /^mongodb:/],
      ["MONGO_DB_URI", /^mongodb:/],
      ["MONGO_DATABASE_URL", /^mongodb:/],
      ["MYSQL_DATABASE_URL", /^mysql:/],
      ["REDIS_URL", /^redis:/],
      ["REDIS_DB_URL", /^redis:/],
      ["UPSTASH_REDIS_REST_URL", /^https:/],
      ["KV_REST_API_URL", /^https:/],
      ["NEXT_PUBLIC_SUPABASE_URL", /^https:/],
      ["SUPABASE_URL", /^https:/],
      ["VITE_POCKETBASE_URL", /^https:/],
      ["SENTRY_DSN", /^https:\/\/public@/],
      ["NEXT_PUBLIC_SENTRY_DSN", /^https:\/\/public@/],
    ];
    for (const [name, scheme] of cases) {
      const v = fakeEnvValue(name)!;
      expect(v, name).toMatch(scheme);
      expect(FAKE_HOSTS as readonly string[], name).toContain(hostOf(v));
    }
    expect(FAKE_HOSTS as readonly string[]).toContain(fakeEnvValue("SMTP_HOST"));
    expect(fakeEnvValue("NEXT_PUBLIC_SUPABASE_ANON_KEY")).toBe("vibeaudit-placeholder-public-key");
    expect(fakeEnvValue("VITE_FIREBASE_API_KEY")).toBe("vibeaudit-placeholder-public-key");
  });

  it("never fakes the app's own address, cookie/CORS settings, listen hosts or secrets", () => {
    for (const n of [
      "NEXT_PUBLIC_BASE_URL", "NEXT_PUBLIC_SITE_URL", "APP_URL", "SITE_URL", "VERCEL_URL", "NEXTAUTH_URL", "AUTH_URL", "BETTER_AUTH_URL",
      "CORS_ORIGIN", "ALLOWED_ORIGIN", "COOKIE_DOMAIN", "SERVER_HOST", "APP_HOST", "HOST", "HOSTNAME", "PORT", "NODE_ENV",
      "API_URL", "VITE_API_URL", "DATABASE_DSN", "PG_DSN", "R2_ACCOUNT_ID", "S3_BUCKET", "SANITY_PROJECT_ID",
      "OPENAI_MODEL", "MAX_TOKENS", "SUPABASE_SERVICE_ROLE_KEY", "STRIPE_SECRET_KEY", "OMDB_API_KEY", "SMS_SENDER",
    ]) expect(fakeEnvValue(n), n).toBeNull();
  });
});
