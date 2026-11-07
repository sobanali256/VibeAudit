import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

vi.mock("server-only", () => ({}));
const { demoArtifactPath, demoEvents, demoView } = await import("./demo");

const IDS = ["dednztomddj2xfgtr5c2", "xgiengqylqdrxpzbxj2n"];
const PUBLIC = fileURLToPath(new URL("../../public", import.meta.url));

describe("read-only demo data", () => {
  it("serves only the snapshotted audits, never as owner", () => {
    for (const id of IDS) {
      const v = demoView(id);
      expect(v?.status).toBe("completed");
      expect(v?.report?.auditId).toBe(id);
      expect(v?.isOwner).toBe(false);
      expect(demoEvents(id).length).toBeGreaterThan(0);
    }
    expect(demoView("aaaaaaaaaaaaaaaaaaaa")).toBeNull();
    expect(demoView("constructor")).toBeNull();
    expect(demoView("__proto__")).toBeNull();
    expect(demoEvents("toString")).toEqual([]);
  });

  it("maps artifact names to static files and rejects anything else", () => {
    expect(demoArtifactPath(IDS[0]!, "page-2.jpg")).toBe(`/demo/${IDS[0]}/page-2.jpg`);
    for (const bad of ["../x.jpg", "page-2.png", "a/b.jpg", "PAGE.jpg", ""]) expect(demoArtifactPath(IDS[0]!, bad)).toBeNull();
    expect(demoArtifactPath("aaaaaaaaaaaaaaaaaaaa", "page-1.jpg")).toBeNull();
  });

  it("has a file for every screenshot and replay frame the reports reference", () => {
    for (const id of IDS) {
      const names = new Set<string>();
      JSON.stringify([demoView(id), demoEvents(id)], (_k, v) => {
        if (typeof v === "string" && /^[a-z0-9-]{1,40}\.jpg$/.test(v)) names.add(v);
        return v;
      });
      expect(names.size).toBeGreaterThan(0);
      for (const n of names) expect(existsSync(`${PUBLIC}/demo/${id}/${n}`), `${id}/${n}`).toBe(true);
    }
  });
});
