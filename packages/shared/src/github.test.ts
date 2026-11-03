import { describe, expect, it } from "vitest";
import { parseGitHubUrl } from "./github";

describe("parseGitHubUrl", () => {
  it.each([
    ["https://github.com/vercel/next.js", { owner: "vercel", repo: "next.js" }],
    ["https://github.com/vercel/next.js.git", { owner: "vercel", repo: "next.js" }],
    ["https://github.com/vercel/next.js/", { owner: "vercel", repo: "next.js" }],
    ["http://www.github.com/a/b", { owner: "a", repo: "b" }],
    ["github.com/a/b", { owner: "a", repo: "b" }],
    ["git@github.com:a-b/c_d.git", { owner: "a-b", repo: "c_d" }],
    ["https://github.com/a/b/tree/main", { owner: "a", repo: "b", ref: "main" }],
    ["https://github.com/a/b/tree/feature/x", { owner: "a", repo: "b", ref: "feature/x" }],
    ["https://github.com/a/b/issues/3", { owner: "a", repo: "b" }],
    ["  https://github.com/a/b  ", { owner: "a", repo: "b" }],
  ])("parses %s", (input, expected) => {
    expect(parseGitHubUrl(input)).toEqual(expected);
  });

  it.each([
    "",
    "https://gitlab.com/a/b",
    "https://github.com.evil.com/a/b",
    "https://evil.com/github.com/a/b",
    "https://user:pass@github.com/a/b",
    "https://github.com:8443/a/b",
    "ftp://github.com/a/b",
    "file:///etc/passwd",
    "https://github.com/onlyowner",
    "https://github.com/-bad/repo",
    "https://github.com/a/..",
    "https://github.com/a/b/tree/../../etc",
    "https://github.com/a/b/tree/x%20y",
    "https://github.com/a/b%2F..%2F..",
  ])("rejects %s", (input) => {
    expect(parseGitHubUrl(input)).toBeNull();
  });
});
