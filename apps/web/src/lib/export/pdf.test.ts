import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { finding, report } from "./fixture.test-helpers";
import { reportToPdf } from "./pdf";
import { screenshotNames } from "./shared";

// Tests run from the repo root, where pnpm doesn't hoist the font package: resolve via apps/web.
const fontDir = fileURLToPath(new URL("../../../node_modules/dejavu-fonts-ttf/ttf/", import.meta.url));
const ORIGIN = "https://va.example";
// 1x1 JPEG (has an SOF2 marker, which is all pdfkit reads).
const JPEG = Buffer.from(
  "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=",
  "base64",
);

const pdf = (r = report(), images?: Map<string, Buffer>) => reportToPdf(r, { origin: ORIGIN, fontDir, images, now: new Date("2026-11-07T00:00:00Z") });
const pageCount = (b: Buffer) => (b.toString("latin1").match(/\/Type \/Page\b/g) ?? []).length;

describe("reportToPdf", () => {
  it("makes a PDF", async () => {
    const b = await pdf();
    expect(b.subarray(0, 5).toString()).toBe("%PDF-");
    expect(b.subarray(-6).toString("latin1")).toContain("%%EOF");
    expect(pageCount(b)).toBeGreaterThanOrEqual(1);
  });

  it("embeds screenshots and skips malformed ones without throwing", async () => {
    const r = report({
      findings: [finding({ evidence: [{ kind: "screenshot", path: "page-1.jpg", verdict: "ok" }, { kind: "screenshot", path: "page-2.jpg" }] })],
      pages: [{ path: "/", status: 200, finalPath: "/", title: "Home", screenshot: "page-1.jpg" }],
    });
    expect(screenshotNames(r)).toEqual(["page-1.jpg", "page-2.jpg"]);
    const bad = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x02, 0x00, 0x00, 0x13, 0x37]);
    const b = await pdf(r, new Map([["page-1.jpg", JPEG], ["page-2.jpg", bad]]));
    expect(b.toString("latin1")).toContain("/Subtype /Image");
  });

  it("embeds a screenshot once however often it is referenced", async () => {
    const big = Buffer.concat([JPEG.subarray(0, -2), Buffer.alloc(200_000, 0), JPEG.subarray(-2)]);
    const r = report({
      findings: Array.from({ length: 20 }, (_, i) => finding({ id: `f${i}`, evidence: [{ kind: "screenshot", path: "page-1.jpg" }] })),
      pages: [{ path: "/", status: 200, finalPath: "/", title: "Home", screenshot: "page-1.jpg" }],
    });
    const b = await pdf(r, new Map([["page-1.jpg", big]]));
    expect((b.toString("latin1").match(/\/Subtype \/Image/g) ?? []).length).toBe(1);
    expect(b.length).toBeLessThan(400_000);
  });

  it("survives hostile and huge input and paginates", async () => {
    const weird = "日本語 😀 \u0000\u0007‮evil\uD800 tab\tend\r\nline";
    const r = report({
      findings: Array.from({ length: 300 }, (_, i) =>
        finding({
          id: `f${i}`,
          title: `${weird} ${i}`,
          description: weird.repeat(20),
          evidence: [
            { kind: "code", file: weird, line: 1, snippet: "x".repeat(20_000) },
            { kind: "http", method: "GET", url: "/admin", status: 200, headers: { a: weird }, bodyExcerpt: weird, request: { headers: ["x: y"], body: "{}" } },
            { kind: "network", control: "firewall", at: "bad date", stage: null, target: "tcp 192.0.2.1:443" },
            { kind: "bundle", asset: "main.js", match: "AKIAVIBE0123456789ABCDEF" },
          ],
          fix: weird,
        }),
      ),
      containment: Array.from({ length: 400 }, () => ({ source: "firewall" as const, at: "2026-11-06T10:01:00Z", stage: "install" as const, direction: "egress" as const, proto: "tcp", dst: "192.0.2.1", dport: 443 })),
      controls: {
        runtime: "runsc",
        user: "1000:1000",
        privileged: false,
        capDrop: ["ALL"],
        capAdd: [],
        noNewPrivileges: true,
        pidsLimit: 1024,
        memoryBytes: 3 * 1024 ** 3,
        cpus: 1.5,
        network: "va-net",
        mounts: [{ destination: "/workspace", rw: true }],
        egressProxy: true,
        planted: { canaries: 2, placeholders: 1 },
      },
      lighthouse: { url: "/", scores: { performance: 90, accessibility: 80, bestPractices: 70, seo: 60 }, metrics: { lcpMs: 1200, cls: 0.01 } },
    });
    const b = await pdf(r);
    expect(b.subarray(0, 5).toString()).toBe("%PDF-");
    expect(pageCount(b)).toBeGreaterThan(5);
    // The canary never appears whole (text is hex-encoded glyph ids, so also check the raw source isn't there).
    expect(b.toString("latin1")).not.toContain("AKIAVIBE0123456789ABCDEF");
  }, 30_000);
});
