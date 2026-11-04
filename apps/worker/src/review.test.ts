import { describe, it, expect } from "vitest";
import { llmReview, collectSources, type SourceFile } from "./review";
import type { LlmClient } from "./llm";
import type { Sandbox, ExecResult, RunSpec } from "./sandbox";

const fixedLlm = (reply: string): LlmClient => ({ async complete() { return reply; } });

const files: SourceFile[] = [
  { path: "server.js", content: "const x = 1;\napp.get('/api/users', (r,s)=>s.json(users));\nconst secret = 'abc';" },
];

describe("llmReview", () => {
  it("parses a valid JSON array into findings (source llm_review, confirmed false)", async () => {
    const llm = fixedLlm(JSON.stringify([
      { file: "server.js", line: 2, severity: "critical", category: "missing_auth", title: "Unauthenticated user list", description: "Returns all users.", fix: "Require auth." },
    ]));
    const out = await llmReview(files, llm);
    expect(out).toHaveLength(1);
    const f = out[0]!;
    expect(f.source).toBe("llm_review");
    expect(f.confirmed).toBe(false);
    expect(f.severity).toBe("critical");
    expect(f.category).toBe("missing_auth");
    expect(f.evidence[0]).toMatchObject({ kind: "code", file: "server.js", line: 2 });
    // snippet is the real source line, not the model's say-so.
    expect(f.evidence[0]!.kind === "code" && f.evidence[0]!.snippet).toContain("/api/users");
  });

  it("tolerates markdown fences around the JSON", async () => {
    const llm = fixedLlm("```json\n[{\"title\":\"X\",\"severity\":\"high\",\"category\":\"open_data\",\"file\":\"server.js\",\"line\":1}]\n```");
    const out = await llmReview(files, llm);
    expect(out).toHaveLength(1);
    expect(out[0]!.severity).toBe("high");
  });

  it("falls back to safe defaults for unknown severity/category", async () => {
    const llm = fixedLlm(JSON.stringify([{ title: "Weird", severity: "apocalyptic", category: "made_up" }]));
    const out = await llmReview(files, llm);
    expect(out[0]!.severity).toBe("medium");
    expect(out[0]!.category).toBe("unsafe_defaults");
    expect(out[0]!.evidence[0]).toMatchObject({ kind: "code", file: "(unknown)" });
  });

  it("drops malformed items but keeps valid ones", async () => {
    const llm = fixedLlm(JSON.stringify([{ nope: true }, { title: "", severity: "low" }, { title: "Real", category: "unsafe_defaults" }]));
    const out = await llmReview(files, llm);
    expect(out.map((f) => f.title)).toEqual(["Real"]);
  });

  it("caps at 10 findings", async () => {
    const many = Array.from({ length: 25 }, (_, i) => ({ title: `f${i}`, severity: "low", category: "unsafe_defaults" }));
    const out = await llmReview(files, fixedLlm(JSON.stringify(many)));
    expect(out).toHaveLength(10);
  });

  it("returns [] on non-array / garbage / empty output", async () => {
    expect(await llmReview(files, fixedLlm("not json at all"))).toEqual([]);
    expect(await llmReview(files, fixedLlm("{\"title\":\"obj not array\"}"))).toEqual([]);
    expect(await llmReview(files, fixedLlm(""))).toEqual([]);
  });

  it("returns [] when the LLM call throws (inference down), never rejects", async () => {
    const llm: LlmClient = { async complete() { throw new Error("inference HTTP 503"); } };
    await expect(llmReview(files, llm)).resolves.toEqual([]);
  });

  it("returns [] with no files (never calls the model)", async () => {
    let called = false;
    const llm: LlmClient = { async complete() { called = true; return "[]"; } };
    expect(await llmReview([], llm)).toEqual([]);
    expect(called).toBe(false);
  });

  it("clamps an over-long title", async () => {
    const long = "A".repeat(500);
    const out = await llmReview(files, fixedLlm(JSON.stringify([{ title: long, category: "unsafe_defaults", severity: "low" }])));
    expect(out[0]!.title.length).toBe(140);
  });
});

function fakeSandbox(stdout: string): Sandbox {
  return {
    auditId: "t",
    async run(_spec: RunSpec): Promise<ExecResult> { return { code: 0, stdout, stderr: "", timedOut: false }; },
  } as unknown as Sandbox;
}

describe("collectSources", () => {
  it("parses the sandbox file dump", async () => {
    const payload = JSON.stringify([{ path: "a.js", content: "x" }, { path: "b.ts", content: "y" }]);
    const out = await collectSources(fakeSandbox(payload), "img", "t");
    expect(out.map((f) => f.path)).toEqual(["a.js", "b.ts"]);
  });

  it("returns [] on unparseable output", async () => {
    expect(await collectSources(fakeSandbox("not json"), "img", "t")).toEqual([]);
  });

  it("drops entries that don't match the shape", async () => {
    const out = await collectSources(fakeSandbox(JSON.stringify([{ path: "a.js" }, { path: "b.js", content: "ok" }])), "img", "t");
    expect(out).toEqual([]);
  });
});
