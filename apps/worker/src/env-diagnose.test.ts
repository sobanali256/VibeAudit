import { describe, expect, it } from "vitest";
import { describeEnvNeed, diagnoseEnvFailure } from "./env-diagnose";

describe("diagnoseEnvFailure", () => {
  it("names the variable from common error shapes", () => {
    expect(diagnoseEnvFailure("Error: Missing environment variable: STRIPE_WEBHOOK_SECRET\n    at build")?.names).toEqual(["STRIPE_WEBHOOK_SECRET"]);
    expect(diagnoseEnvFailure("Error: RESEND_API_KEY is not set")?.names).toEqual(["RESEND_API_KEY"]);
    // t3-env / zod
    expect(diagnoseEnvFailure('❌ Invalid environment variables: { DATABASE_URL: [ "Required" ], NEXTAUTH_SECRET: [ "Required" ] }')?.names).toEqual(["DATABASE_URL", "NEXTAUTH_SECRET"]);
    expect(diagnoseEnvFailure("  CLERK_SECRET_KEY: Required\n  NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY: Required")?.names).toEqual(["CLERK_SECRET_KEY", "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY"]);
    expect(diagnoseEnvFailure("Error: The OPENAI_API_KEY environment variable is missing or empty")?.names).toEqual(["OPENAI_API_KEY"]);
  });

  it("falls back to a fixed phrase when the error doesn't name it", () => {
    expect(diagnoseEnvFailure("Error: supabaseUrl is required.\n at new SupabaseClient")).toEqual({ names: [], shape: "a Supabase URL" });
    expect(diagnoseEnvFailure("TypeError: Invalid URL\n    input: ''")).toEqual({ names: [], shape: "a URL (one was empty or not a valid URL)" });
  });

  it("returns null for failures that aren't about config, and ignores non-env words", () => {
    expect(diagnoseEnvFailure("Type error: Property 'x' does not exist on type 'Y'.\nFailed to compile.")).toBeNull();
    expect(diagnoseEnvFailure("ERROR is required\nHTTP was undefined")).toBeNull();
    expect(diagnoseEnvFailure("")).toBeNull();
  });

  it("caps names and never echoes log text", () => {
    const log = ["A_ONE", "A_TWO", "A_THREE", "A_FOUR"].map((n) => `${n} is not set <script>alert(1)</script>`).join("\n");
    const d = diagnoseEnvFailure(log)!;
    expect(d.names).toEqual(["A_ONE", "A_TWO", "A_THREE"]);
    expect(describeEnvNeed(d)).not.toContain("<script>");
    expect(describeEnvNeed(d)).toMatch(/^it looks like it needs A_ONE, A_TWO, A_THREE. The sandbox never gets real secrets/);
  });
});

describe("diagnoseEnvFailure (review fixes)", () => {
  it("ignores warning lines and stays fast on hostile logs", () => {
    expect(diagnoseEnvFailure("warn - SENTRY_AUTH_TOKEN is not set, skipping source map upload\nType error: x")).toBeNull();
    const t0 = Date.now();
    diagnoseEnvFailure("MONGO".repeat(40_000));
    diagnoseEnvFailure("A".repeat(200_000));
    diagnoseEnvFailure("Invalid environment variables:" + " x".repeat(100_000));
    expect(Date.now() - t0).toBeLessThan(1000);
  });
});

describe("outOfMemory", () => {
  it("spots V8 and kernel memory kills, not ordinary failures", async () => {
    const { outOfMemory } = await import("./pipeline");
    expect(outOfMemory("FATAL ERROR: Ineffective mark-compacts near heap limit Allocation failed - JavaScript heap out of memory")).toBe(true);
    expect(outOfMemory("FATAL ERROR: Reached heap limit Allocation failed")).toBe(true);
    expect(outOfMemory("Type error: Property 'x' does not exist")).toBe(false);
  });
});
