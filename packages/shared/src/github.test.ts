import { describe, expect, it } from "vitest";
import { parseGitHubUrl, refCandidates } from "./github";

describe("parseGitHubUrl", () => {
  it.each([
    ["https://github.com/vercel/next.js", { owner: "vercel", repo: "next.js" }],
    ["https://github.com/vercel/next.js.git", { owner: "vercel", repo: "next.js" }],
    ["https://github.com/vercel/next.js/", { owner: "vercel", repo: "next.js" }],
    ["http://www.github.com/a/b", { owner: "a", repo: "b" }],
    ["github.com/a/b", { owner: "a", repo: "b" }],
    ["git@github.com:a-b/c_d.git", { owner: "a-b", repo: "c_d" }],
    ["https://github.com/a/b/tree/main", { owner: "a", repo: "b", ref: "main" }],
    [
      "https://github.com/a/b/tree/feature/x",
      { owner: "a", repo: "b", ref: "feature", subpath: "x" },
    ],
    [
      "https://github.com/a/b/blob/v1.2/src/index.ts",
      { owner: "a", repo: "b", ref: "v1.2", subpath: "src/index.ts" },
    ],
    ["https://github.com/a/b/commit/abc123", { owner: "a", repo: "b", ref: "abc123" }],
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
    // Backslash / whitespace / control-char smuggling (URL parser normalises these)
    "github.com/evil/x\\..\\..\\vercel\\next.js",
    "https://github.com/evil\\vercel/next.js",
    "https://github.com/evil/x/\t../../vercel/next.js",
    "https://github.com/evil/x\r\n/../vercel/next.js",
    "https://github.com/a/b c",
    "https://github.com/a/b\u0000",
    "https://github.com/a/b\u007f",
    "https://github.com/a/b%5C..%5Cc",
    // Ref forms
    "https://github.com/a/b/tree",
    "https://github.com/a/b/blob/",
    "https://github.com/a/b/tree/main/../../x",
    "https://github.com/a/b/blob/main/a%20b",
  ])("rejects %s", (input) => {
    expect(parseGitHubUrl(input)).toBeNull();
  });
});

describe("refCandidates", () => {
  it("lists every ref split, longest first", () => {
    const r = parseGitHubUrl("https://github.com/a/b/tree/feature/x/src")!;
    expect(refCandidates(r)).toEqual(["feature/x/src", "feature/x", "feature"]);
  });
  it("is empty without a ref", () => {
    expect(refCandidates({ owner: "a", repo: "b" })).toEqual([]);
  });
});
