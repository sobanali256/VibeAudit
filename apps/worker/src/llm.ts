// Minimal client for Vultr Serverless Inference (OpenAI-compatible chat/completions). Runs on
// VM 1. The model has NO tools: it only ever returns text, which the caller treats as untrusted
// (validated against a schema, never evaluated). glm-* models put chain-of-thought in
// `message.reasoning`, separate from `message.content`; we only read `content`.

export interface LlmClient {
  /** One non-streaming completion. Returns the assistant message content (may be empty). */
  complete(opts: { system: string; user: string; maxTokens?: number; timeoutMs?: number }): Promise<string>;
}

export interface LlmConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
}

export function createLlm(cfg: LlmConfig): LlmClient {
  return {
    async complete({ system, user, maxTokens = 1500, timeoutMs = 60_000 }) {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), timeoutMs);
      try {
        const res = await fetch(`${cfg.baseUrl.replace(/\/$/, "")}/chat/completions`, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${cfg.apiKey}` },
          body: JSON.stringify({
            model: cfg.model,
            temperature: 0,
            max_tokens: maxTokens,
            messages: [
              { role: "system", content: system },
              { role: "user", content: user },
            ],
          }),
          signal: ctl.signal,
        });
        if (!res.ok) {
          // Never include the response body: it could echo the prompt (repo content).
          throw new Error(`inference HTTP ${res.status}`);
        }
        const data = (await res.json()) as { choices?: { message?: { content?: unknown } }[] };
        const content = data.choices?.[0]?.message?.content;
        return typeof content === "string" ? content : "";
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
