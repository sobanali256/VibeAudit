import { describe, expect, it } from "vitest";
import { finding, report } from "./fixture.test-helpers";
import { code, fence, inline, reportToMarkdown } from "./markdown";
import { exportFilename } from "./shared";

const ORIGIN = "https://va.example";
const now = new Date("2026-11-07T00:00:00Z");
const md = (r = report()) => reportToMarkdown(r, { origin: ORIGIN, now });

/** Every fence opens (with the fixed info string) and closes at column 0 with the same length. */
function fencesBalanced(s: string) {
  let open: string | null = null;
  for (const l of s.split("\n")) {
    const m = /^(`{3,})(text)?$/.exec(l);
    if (!m) continue;
    if (open === null) {
      expect(m[2]).toBe("text");
      open = m[1]!;
    } else if (m[1] === open && !m[2]) open = null;
  }
  expect(open).toBeNull();
}

describe("reportToMarkdown", () => {
  it("has the main sections, the score and a link back", () => {
    const s = md();
    expect(s).toContain("# VibeAudit report: acme/shop");
    expect(s).toContain("Score **42/100** · Runtime audit");
    expect(s).toContain(`[${ORIGIN}/audit/abc123xyz](${ORIGIN}/audit/abc123xyz)`);
    for (const h of ["## Summary", "## Fix these first", "## Findings", "## Sandbox"]) expect(s).toContain(h);
    expect(s).toContain("### 1. **HIGH** · Admin console open");
    expect(s).toContain("**Evidence 1: code** in `server.js:3`");
    expect(s).toContain("For coding agents");
    fencesBalanced(s);
  });

  it("sorts by severity, separates dependency findings and numbers them D1..", () => {
    const s = md(
      report({
        findings: [
          finding({ id: "low", severity: "low", title: "Low one" }),
          finding({ id: "crit", severity: "critical", title: "Crit one" }),
          finding({ id: "dep", severity: "high", title: "lodash", source: "dep_audit", category: "vulnerable_dependency" }),
        ],
      }),
    );
    expect(s.indexOf("Crit one")).toBeLessThan(s.indexOf("Low one"));
    expect(s).toContain("### D1. **HIGH** · lodash");
    const top = s.slice(s.indexOf("## Fix these first"), s.indexOf("## Findings"));
    expect(top).toContain("Crit one");
    expect(top).not.toContain("lodash");
    expect(s).toContain("incl. 1 dependency advisory");
  });

  it("static-only, failed and empty wording", () => {
    expect(md(report({ mode: "static_only", staticOnlyReason: "build failed" }))).toContain("The app wasn't run: build failed.");
    expect(md(report({ status: "failed" }))).toContain("Partial results");
    expect(md(report({ findings: [] }))).toContain("No findings in the app itself.");
  });

  it("zip source", () => {
    const r = report({ source: { kind: "zip", filename: "my app.zip", sizeBytes: 10 } });
    expect(md(r)).toContain("# VibeAudit report: my app.zip");
    expect(exportFilename(r, "md")).toBe("vibeaudit-my-app-abc123xyz.md");
  });

  it("hostile banner", () => {
    const s = md(report({ findings: [finding({ category: "supply_chain", severity: "critical", title: "postinstall exfil" })] }));
    expect(s).toContain("## WARNING: malicious install-time behaviour");
    expect(s).toContain("capped at 40");
  });

  it("escapes HTML, links, images, math and autolinks in untrusted inline text", () => {
    const s = md(
      report({
        findings: [
          finding({
            title: "<script>alert(1)</script> [x](javascript:alert(1)) ![i](http://evil/p.png)",
            description: "visit https://evil.example or www.evil.example or mail a@evil.example $x$ *bold*",
          }),
        ],
      }),
    );
    expect(s).not.toMatch(/<script>/);
    // Brackets escaped: no link or image can form (an unescaped "](" or "![" never appears).
    expect(s).not.toMatch(/(?<!\\)\]\(javascript:/);
    expect(s).not.toMatch(/(?<!\\)!\[i/);
    expect(s).toContain("\\[x\\](javascript:");
    expect(s).not.toContain("https://evil.example");
    expect(s).not.toMatch(/\bwww\.evil/);
    expect(s).toContain("a\\@evil");
    expect(s).toContain("\\$x\\$");
    expect(s).toContain("\\*bold\\*");
  });

  it("inline(): CR newlines, leading block markers, table pipes", () => {
    expect(inline("a\rb\r\nc")).toBe("a b c");
    expect(inline("# heading")).toBe("\\# heading");
    expect(inline("- item")).toBe("\\- item");
    expect(inline("1. item")).toBe("1\\. item");
    expect(inline("a|b")).toBe("a\\|b");
  });

  it("code spans and fences grow past backticks inside", () => {
    expect(code("a`b")).toBe("``a`b``");
    expect(code("`x")).toBe("`` `x ``");
    const f = fence("```\n````evil\nx");
    expect(f.startsWith("`````text\n")).toBe(true);
    expect(f.endsWith("\n`````")).toBe(true);
  });

  it("a snippet with unindented HTML/fence/heading lines stays inside a top-level fence", () => {
    const s = md(
      report({
        findings: [finding({ evidence: [{ kind: "code", file: "a.js", snippet: "x\n<img src=x onerror=alert(1)>\n```\n</details>\n# Injected" }] })],
      }),
    );
    fencesBalanced(s);
    const before = s.slice(0, s.indexOf("<img src=x"));
    // Opened at column 0 right after a blank line (not inside a list item), not closed since.
    expect(before.endsWith("\n\n````text\nx\n")).toBe(true);
  });

  it("masks canaries everywhere, including containment rows and bundle matches", () => {
    const canary = "AKIAVIBE0123456789ABCDEF01";
    const s = md(
      report({
        findings: [finding({ evidence: [{ kind: "bundle", asset: "main.js", match: canary }], title: `leak ${canary}` })],
        containment: [
          { source: "proxy", at: "2026-11-06T10:01:00Z", stage: "install", verdict: "exfil", host: "registry.npmjs.org", path: `/-/v1/search?text=${canary}` },
        ],
      }),
    );
    expect(s).not.toContain(canary);
    expect(s).toContain("AKIAVIBE…");
    expect(s).toContain("contains a planted canary secret");
    expect(s).toContain("What the code tried");
  });

  it("links only to our origin, screenshots only with valid artifact names", () => {
    const s = md(
      report({
        findings: [
          finding({
            evidence: [
              { kind: "screenshot", path: "page-2.jpg", verdict: "admin console visible" },
              { kind: "screenshot", path: "../../etc/passwd" },
            ],
          }),
        ],
        pages: [{ path: "/admin", status: 200, finalPath: "/admin", title: "Admin | panel", screenshot: "page-2.jpg" }],
      }),
    );
    expect(s).toContain(`[open screenshot](${ORIGIN}/api/audits/abc123xyz/artifacts/page-2.jpg)`);
    expect(s).not.toContain("](../../etc");
    expect(s).toContain("Admin \\| panel");
    for (const m of s.matchAll(/\]\(([^)]+)\)/g)) expect(m[1]!.startsWith(ORIGIN)).toBe(true);
  });

  it("caps evidence per finding and the total size", () => {
    const many = Array.from({ length: 15 }, (_, i) => ({ kind: "code" as const, file: `f${i}.js`, snippet: "x" }));
    expect(md(report({ findings: [finding({ evidence: many })] }))).toContain("5 more evidence items");
    const huge = Array.from({ length: 500 }, (_, i) =>
      finding({ id: `f${i}`, evidence: Array.from({ length: 10 }, () => ({ kind: "code" as const, file: "a", snippet: "y".repeat(5000) })) }),
    );
    const s = md(report({ findings: huge }));
    expect(s.length).toBeLessThan(1_100_000);
    expect(s).toContain("the export reached its size limit");
    fencesBalanced(s);
  });

  it("a timestamp that isn't a date is never echoed (no injection through `at`)", () => {
    const evil = "<b>x</b>\n```\n![i](http://evil/x.png)";
    const s = md(
      report({
        finishedAt: evil,
        findings: [finding({ evidence: [{ kind: "network", control: "firewall", at: evil, stage: null, target: "tcp 1.2.3.4:443" }] })],
        containment: [{ source: "firewall", at: evil, stage: "install", direction: "egress", proto: "tcp", dst: "1.2.3.4", dport: 443 }],
      }),
    );
    expect(s).not.toContain("<b>");
    expect(s).not.toContain("![i]");
    expect(s).toContain("unknown time");
    fencesBalanced(s);
  });

  it("defangs www. after an underscore and masks lowercase canaries", () => {
    const s = md(report({ findings: [finding({ title: "see _www.evil.com", description: "akiavibe0123456789abcdef" })] }));
    expect(s).not.toMatch(/www\.evil/);
    expect(s).not.toContain("akiavibe0123456789abcdef");
  });

  it("Fix-these-first never points at a finding the size limit left out", () => {
    const huge = Array.from({ length: 60 }, (_, i) =>
      finding({ id: `f${i}`, severity: "critical", evidence: Array.from({ length: 10 }, () => ({ kind: "code" as const, file: "a", snippet: "y".repeat(4000) })) }),
    );
    const s = md(report({ findings: huge }));
    const included = (s.match(/^### \d+\. /gm) ?? []).length;
    expect(included).toBeLessThan(60);
    expect(s).toContain(`(finding ${included}, `);
    expect(s).not.toContain(`(finding ${included + 1}, `);
    expect(s).toContain("(only in the live report, ");
  });

  it("filename is header-safe", () => {
    const r = report({ source: { kind: "zip", filename: 'evil"\r\nX-Header: 1.zip', sizeBytes: 1 } });
    expect(exportFilename(r, "pdf")).toMatch(/^[A-Za-z0-9._-]+$/);
    expect(exportFilename(report({ source: { kind: "zip", filename: "日本.zip", sizeBytes: 1 } }), "md")).toBe("vibeaudit-abc123xyz.md");
  });
});
