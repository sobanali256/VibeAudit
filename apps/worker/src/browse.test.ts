import { describe, expect, it } from "vitest";
import { BROWSE_SCRIPT, type PageCapture, decodeJpeg, parseBrowse, relativePath, sameContent, worthKeeping } from "./browse";

// Smallest byte strings that pass the JPEG signature/end checks.
const jpeg = (n = 32) => Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(n, 7), Buffer.from([0xff, 0xd9])]);
const b64 = (b: Buffer) => b.toString("base64");
const BASE = "http://172.30.0.2:3000";
const line = (o: unknown) => `__VA_PAGE__${JSON.stringify(o)}`;

describe("decodeJpeg", () => {
  it("accepts a JPEG", () => {
    expect(decodeJpeg(b64(jpeg()))?.equals(jpeg())).toBe(true);
  });
  it("rejects non-JPEG bytes, bad base64, truncation and oversize", () => {
    expect(decodeJpeg(b64(Buffer.from("<svg onload=alert(1)></svg>")))).toBeNull();
    expect(decodeJpeg(b64(Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])))).toBeNull(); // PNG
    expect(decodeJpeg(b64(jpeg()).slice(0, -4))).toBeNull(); // no end marker
    expect(decodeJpeg("not base64!!!!!!")).toBeNull();
    expect(decodeJpeg(null)).toBeNull();
    expect(decodeJpeg(12)).toBeNull();
    expect(decodeJpeg("A".repeat(600_004))).toBeNull();
  });
});

describe("relativePath", () => {
  it("keeps same-origin paths with query", () => {
    expect(relativePath(`${BASE}/login?next=/admin`, BASE)).toBe("/login?next=/admin");
  });
  it("returns null when the page left the app, undefined when there's no usable URL", () => {
    expect(relativePath("http://evil.example/x", BASE)).toBeNull();
    expect(relativePath("http://172.30.0.2:4000/", BASE)).toBeNull();
    expect(relativePath("chrome-error://chromewebdata/", BASE)).toBeNull();
    expect(relativePath("::", BASE)).toBeUndefined();
    expect(relativePath(undefined, BASE)).toBeUndefined();
  });
});

describe("parseBrowse", () => {
  const req = ["/", "/admin", "/dashboard"];

  it("parses pages in request order and decodes screenshots", () => {
    const out = [
      "chromium noise",
      line({ p: "/admin", status: 200, loaded: true, u: `${BASE}/admin/`, t: "Admin", x: "Users", pw: 0, img: b64(jpeg()) }),
      line({ p: "/", status: 200, loaded: true, u: `${BASE}/`, t: "Home", x: "Welcome", pw: 0, img: b64(jpeg()) }),
    ].join("\n");
    const { pages, fatal } = parseBrowse(out, req, BASE);
    expect(fatal).toBeUndefined();
    expect(pages.map((p) => p.path)).toEqual(["/", "/admin"]);
    expect(pages[1]).toMatchObject({ status: 200, finalPath: "/admin/", title: "Admin", text: "Users", hasPassword: false, loaded: true });
    expect(pages[1]!.screenshot?.length).toBe(jpeg().length);
  });

  it("ignores unrequested paths, duplicates, bad JSON and bad shapes", () => {
    const out = [
      line({ p: "/etc/passwd", status: 200 }),
      line({ p: "/", status: 200, t: "first" }),
      line({ p: "/", status: 500, t: "second" }),
      "__VA_PAGE__{not json",
      line({ p: 42 }),
      line({ p: "/dashboard", status: 1e9 }),
    ].join("\n");
    const { pages } = parseBrowse(out, req, BASE);
    expect(pages.map((p) => [p.path, p.status, p.title])).toEqual([["/", 200, "first"], ["/dashboard", 0, ""]]);
  });

  it("keeps a page whose individual fields are malformed (one bad value doesn't drop it)", () => {
    const { pages } = parseBrowse(line({ p: "/admin", status: 200, pw: -1, u: 5, t: { x: 1 }, img: b64(jpeg()) }), req, BASE);
    expect(pages[0]).toMatchObject({ path: "/admin", status: 200, hasPassword: false, finalPath: undefined, title: "" });
    expect(pages[0]!.screenshot).not.toBeNull();
  });

  it("caps page-controlled strings and drops a bad screenshot", () => {
    const { pages } = parseBrowse(line({ p: "/", status: 200, t: "T".repeat(5000), x: "X".repeat(10_000), img: "AAAA" }), req, BASE);
    expect(pages[0]!.title).toHaveLength(300);
    expect(pages[0]!.text).toHaveLength(3000);
    expect(pages[0]!.screenshot).toBeNull();
  });

  it("reports a fatal error and per-page errors", () => {
    const { pages, fatal } = parseBrowse([line({ fatal: "chromium did not start" }), line({ p: "/", err: "net::ERR_CONNECTION_REFUSED" })].join("\n"), req, BASE);
    expect(fatal).toBe("chromium did not start");
    expect(pages[0]).toMatchObject({ path: "/", status: 0, error: "net::ERR_CONNECTION_REFUSED", screenshot: null });
  });

  it("marks a page that left the app", () => {
    const { pages } = parseBrowse(line({ p: "/", status: 200, u: "https://accounts.example.com/login" }), req, BASE);
    expect(pages[0]!.finalPath).toBeNull();
  });
});

describe("worthKeeping", () => {
  const cap = (o: Partial<PageCapture>): PageCapture => ({
    path: "/", status: 200, finalPath: o.path ?? "/", title: "App", text: "Welcome", hasPassword: false, loaded: true, screenshot: jpeg(), frames: [], ...o,
  });

  it("keeps home and distinct 2xx pages, drops 404s, SPA fallbacks and missing screenshots", () => {
    const home = cap({});
    const admin = cap({ path: "/admin", title: "Admin", text: "All users" });
    const missing = cap({ path: "/dashboard", status: 404, text: "Not found" });
    const spa = cap({ path: "/settings", text: " Welcome\n" });
    const noShot = cap({ path: "/account", text: "Account", screenshot: null });
    expect(worthKeeping([home, admin, missing, spa, noShot])).toEqual([home, admin]);
    expect(sameContent(home, spa)).toBe(true);
  });

  it("drops redirects elsewhere (a 302 to /login arrives as the login page's 200) and login forms", () => {
    const home = cap({});
    const toLogin = cap({ path: "/admin", finalPath: "/login?next=/admin", title: "Sign in", text: "Sign in" });
    const offsite = cap({ path: "/dashboard", finalPath: null, title: "SSO", text: "SSO" });
    const form = cap({ path: "/settings", finalPath: "/settings", hasPassword: true, title: "Settings", text: "Password" });
    const slash = cap({ path: "/account", finalPath: "/account/?tab=1", title: "Account", text: "Account" });
    const unknown = cap({ path: "/users", finalPath: undefined, title: "Users", text: "Users" });
    expect(worthKeeping([home, toLogin, offsite, form, slash, unknown])).toEqual([home, slash, unknown]);
  });

  it("keeps a home page even when it errored", () => {
    const home = cap({ status: 500 });
    expect(worthKeeping([home])).toEqual([home]);
  });
});

describe("BROWSE_SCRIPT", () => {
  it("is valid JavaScript and takes its inputs from env, not interpolation", () => {
    expect(() => new Function(BROWSE_SCRIPT)).not.toThrow();
    expect(BROWSE_SCRIPT).toContain("process.env.VA_BASE");
    expect(BROWSE_SCRIPT).toContain("--proxy-bypass-list=");
    expect(BROWSE_SCRIPT).toContain("disable_non_proxied_udp");
    expect(BROWSE_SCRIPT).toContain("Page.createIsolatedWorld");
  });
});

describe("parseBrowse replay frames", () => {
  it("keeps valid JPEG frames, drops anything else, and caps the count per page", () => {
    const good = b64(jpeg());
    const out = [
      line({ p: "/", status: 200, img: good, fr: [good, "<svg/>", b64(Buffer.from("not a jpeg at all")), good, "A".repeat(150_004)] }),
      line({ p: "/admin", status: 404, fr: Array(7).fill(good) }), // over the per-page cap: the field is dropped
      line({ p: "/dashboard", status: 200, fr: "nope" }),
    ].join("\n");
    const { pages } = parseBrowse(out, ["/", "/admin", "/dashboard"], BASE);
    expect(pages.map((p) => p.frames.length)).toEqual([2, 0, 0]);
    expect(pages[0]!.frames[0]!.equals(jpeg())).toBe(true);
    expect(pages[0]!.screenshot).not.toBeNull();
  });

  it("asks Chromium for a bounded screencast and acks every frame", () => {
    expect(BROWSE_SCRIPT).toContain("Page.startScreencast");
    expect(BROWSE_SCRIPT).toContain("Page.screencastFrameAck");
    expect(BROWSE_SCRIPT).toContain("Page.stopScreencast");
  });
});
