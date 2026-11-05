// Minimal client for Vultr Serverless Inference (OpenAI-compatible chat/completions). Runs on
// VM 1. The model has NO tools: it only ever returns text, which the caller treats as untrusted
// (validated against a schema, never evaluated). glm-* models put chain-of-thought in
// `message.reasoning`, separate from `message.content`; we only read `content`.

export interface LlmClient {
  /** One non-streaming completion. Returns the assistant message content (may be empty). */
  complete(opts: { system: string; user: string; maxTokens?: number; timeoutMs?: number; images?: readonly Buffer[]; reasoningEffort?: ReasoningEffort }): Promise<string>;
}

/**
 * OpenAI-style `reasoning_effort`. glm-5.3 on Vultr otherwise reasons at length in a hidden
 * field before answering: 47-88 s per review, and about 1 in 3 replies used the whole token
 * budget on reasoning and came back with empty content. With it set, the same review returned
 * a full answer in ~6 s on every try.
 */
export type ReasoningEffort = "low" | "medium" | "high";

export interface LlmConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
}

export function createLlm(cfg: LlmConfig): LlmClient {
  return {
    async complete({ system, user, maxTokens = 1500, timeoutMs = 60_000, images, reasoningEffort }) {
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
            ...(reasoningEffort ? { reasoning_effort: reasoningEffort } : {}),
            messages: [
              { role: "system", content: system },
              {
                role: "user",
                // Images (JPEG screenshots for the vision model) ride along as data URLs.
                content: images?.length
                  ? [
                      { type: "text", text: user },
                      ...images.map((b) => ({ type: "image_url", image_url: { url: `data:image/jpeg;base64,${b.toString("base64")}` } })),
                    ]
                  : user,
              },
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
