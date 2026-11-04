// Leaf module (no imports from the rest of shared) so audit.ts and sandbox.ts can both use
// these without an ESM import cycle. These MUST match infra/cp/proxy/vibeaudit_proxy.py;
// sandbox.contract.test.ts checks that.

export const AUDIT_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
export const ENV_VAR_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
export const HOST_RE =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
export const HEADER_NAME_RE = /^[a-z0-9-]{1,64}$/;
/** Secrets and canaries: printable ASCII, no spaces, 8-512 chars (identical rule in the proxy). */
export const SECRET_VALUE_RE = /^[\x21-\x7e]{8,512}$/;

/** Stages where test keys may be swapped in (proxy KEY_STAGES). */
export const KEY_STAGES = ["run", "dynamic", "verify"] as const;

/**
 * Known API providers: the ONLY source of the hosts a user's real test key may be sent to.
 * Never take key hosts from the LLM planner: it reads untrusted repo content, and a prompt
 * injection could scope the key to an attacker's host.
 */
export const KEY_PROVIDERS: Record<string, readonly string[]> = {
  OPENAI_API_KEY: ["api.openai.com"],
  ANTHROPIC_API_KEY: ["api.anthropic.com"],
  GEMINI_API_KEY: ["generativelanguage.googleapis.com"],
  GOOGLE_API_KEY: ["generativelanguage.googleapis.com"],
  GROQ_API_KEY: ["api.groq.com"],
  MISTRAL_API_KEY: ["api.mistral.ai"],
  OPENROUTER_API_KEY: ["openrouter.ai"],
  RESEND_API_KEY: ["api.resend.com"],
  STRIPE_SECRET_KEY: ["api.stripe.com"],
  REPLICATE_API_TOKEN: ["api.replicate.com"],
};
