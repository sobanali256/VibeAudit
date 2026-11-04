import { describe, expect, it, vi } from "vitest";
import { parseGitHubUrl } from "@vibeaudit/shared";
import { IntakeError, openTarball, resolveRepo } from "./intake";

// A fetch stub driven by a route table. Each entry matches a URL substring.
function stubFetch(routes: { match: string; status?: number; json?: unknown; headers?: Record<string, string>; body?: Uint8Array }[]) {
  return vi.fn(async (url: string | URL | Request) => {
    const u = String(url);
    const r = routes.find((x) => u.includes(x.match));
    if (!r) return new Response(null, { status: 404 });
    if (r.body !== undefined) {
      const stream = new ReadableStream({
        start(c) {
          c.enqueue(r.body!);
          c.close();
        },
      });
      return new Response(stream, { status: r.status ?? 200, headers: r.headers });
    }
    return new Response(r.json !== undefined ? JSON.stringify(r.json) : null, {
      status: r.status ?? 200,
      headers: { "content-type": "application/json", ...r.headers },
    });
  }) as unknown as typeof fetch;
}

const ref = (u: string) => parseGitHubUrl(u)!;

describe("resolveRepo", () => {
  it("uses the default branch when no ref is given", async () => {
    const fetchImpl = stubFetch([{ match: "/repos/a/b", json: { default_branch: "main" } }]);
    const r = await resolveRepo(ref("https://github.com/a/b"), { fetchImpl });
    expect(r.ref).toBe("main");
    expect(r.tarballUrl).toBe("https://api.github.com/repos/a/b/tarball/main");
    expect(r.subpath).toBeUndefined();
  });

  it("prefers the longest matching ref (branch with a slash)", async () => {
    // /tree/feature/x/src: branch is "feature/x", subpath "src".
    const fetchImpl = stubFetch([
      { match: "/commits/feature%2Fx%2Fsrc", status: 404 },
      { match: "/commits/feature%2Fx", status: 200, json: { sha: "abc" } },
      { match: "/commits/feature", status: 200, json: { sha: "def" } },
    ]);
    const r = await resolveRepo(ref("https://github.com/a/b/tree/feature/x/src"), { fetchImpl });
    expect(r.ref).toBe("feature/x");
    expect(r.subpath).toBe("src");
    expect(r.tarballUrl).toContain("/tarball/feature%2Fx");
  });

  it("falls back to a shorter ref + subpath", async () => {
    const fetchImpl = stubFetch([
      { match: "/commits/feature%2Fx", status: 404 },
      { match: "/commits/feature", status: 200, json: { sha: "def" } },
    ]);
    const r = await resolveRepo(ref("https://github.com/a/b/tree/feature/x"), { fetchImpl });
    expect(r.ref).toBe("feature");
    expect(r.subpath).toBe("x");
  });

  it("throws ref_not_found when no candidate exists", async () => {
    const fetchImpl = stubFetch([{ match: "/commits/", status: 404 }]);
    await expect(resolveRepo(ref("https://github.com/a/b/tree/nope"), { fetchImpl })).rejects.toMatchObject({
      code: "ref_not_found",
    });
  });

  it("maps 404 and rate limit", async () => {
    await expect(
      resolveRepo(ref("https://github.com/a/b"), { fetchImpl: stubFetch([{ match: "/repos/a/b", status: 404 }]) }),
    ).rejects.toMatchObject({ code: "not_found" });
    await expect(
      resolveRepo(ref("https://github.com/a/b"), {
        fetchImpl: stubFetch([{ match: "/repos/a/b", status: 403, headers: { "x-ratelimit-remaining": "0" } }]),
      }),
    ).rejects.toMatchObject({ code: "rate_limited" });
  });

  it("sends the token when given", async () => {
    const fetchImpl = stubFetch([{ match: "/repos/a/b", json: { default_branch: "main" } }]);
    await resolveRepo(ref("https://github.com/a/b"), { fetchImpl, token: "ghp_x" });
    const call = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[0]!;
    expect((call[1] as RequestInit).headers).toMatchObject({ Authorization: "Bearer ghp_x" });
  });
});

describe("openTarball", () => {
  const resolved = { owner: "a", repo: "b", ref: "main", tarballUrl: "https://api.github.com/repos/a/b/tarball/main" };

  it("streams bytes and reports the total", async () => {
    const body = new Uint8Array(1000).fill(7);
    const { stream, done } = await openTarball(resolved, { fetchImpl: stubFetch([{ match: "/tarball/", body }]) });
    const chunks: Buffer[] = [];
    for await (const c of stream) chunks.push(c as Buffer);
    expect(Buffer.concat(chunks).byteLength).toBe(1000);
    expect(await done).toBe(1000);
  });

  it("rejects early when content-length exceeds the cap", async () => {
    const fetchImpl = stubFetch([{ match: "/tarball/", body: new Uint8Array(10), headers: { "content-length": "999999" } }]);
    await expect(openTarball(resolved, { fetchImpl, maxBytes: 100 })).rejects.toMatchObject({ code: "too_large" });
  });

  it("aborts mid-stream when the running count passes the cap", async () => {
    const body = new Uint8Array(500).fill(1); // no content-length header
    const { stream, done } = await openTarball(resolved, { fetchImpl: stubFetch([{ match: "/tarball/", body }]), maxBytes: 100 });
    const read = (async () => {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for await (const _ of stream) { /* drain */ }
    })();
    await expect(read).rejects.toMatchObject({ code: "too_large" });
    await expect(done).rejects.toMatchObject({ code: "too_large" });
  });
});
