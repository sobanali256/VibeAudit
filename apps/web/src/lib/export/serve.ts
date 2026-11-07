import "server-only";
import { join } from "node:path";
import { getArtifact } from "@vibeaudit/db";
import type { Report } from "@vibeaudit/shared";
import { loadAuditView } from "../audits";
import { db } from "../db";
import { DEMO, demoArtifactBytes } from "../demo";
import { limits } from "../rate-limit";
import { clientIp, jsonError } from "../request";
import { isTerminal } from "../view";
import { EXPORT_LIMITS, exportFilename, screenshotNames } from "./shared";

/**
 * Shared front half of the export routes: rate limit, then the finished report. Same visibility
 * as GET /api/audits/[id] (anyone with the id), and only the report the web view already shows.
 */
export async function exportableReport(req: Request, id: string): Promise<Report | Response> {
  const wait = limits.export!.take(clientIp(req));
  if (wait) return jsonError(429, "slow down", { "retry-after": String(wait) });
  const view = await loadAuditView(id, () => false);
  if (!view) return jsonError(404, "audit not found");
  if (!isTerminal(view.status)) return jsonError(409, "the audit hasn't finished yet");
  if (!view.report) return jsonError(404, "this audit has no report");
  return view.report;
}

/**
 * Links in the files point back here. `req.url` is Next's own listen address (127.0.0.1:3000 behind
 * Caddy), so use the Host header: Caddy only routes our own domain to the app and passes Host through
 * (checkMutation relies on the same header). Scheme from Caddy's X-Forwarded-Proto.
 */
export function requestOrigin(req: Request): string {
  const url = new URL(req.url);
  const host = req.headers.get("host") ?? "";
  if (!/^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$/.test(host)) return url.origin;
  const fwd = req.headers.get("x-forwarded-proto");
  const proto = fwd === "https" || fwd === "http" ? fwd : url.protocol.replace(":", "");
  return `${proto}://${host}`;
}

export function fileResponse(body: string | Buffer, r: Report, ext: "md" | "pdf"): Response {
  const bytes = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  return new Response(new Uint8Array(bytes), {
    headers: {
      "content-type": ext === "md" ? "text/markdown; charset=utf-8" : "application/pdf",
      "content-length": String(bytes.length),
      "content-disposition": `attachment; filename="${exportFilename(r, ext)}"`,
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; sandbox",
      "cache-control": "private, max-age=60",
    },
  });
}

// --- PDF: bounded work on VM 1 -------------------------------------------------------------
// A render holds up to 16 screenshots plus the document in memory and burns CPU: at most two run at
// once (the rest get 503 + Retry-After), and finished PDFs are cached (a terminal report never
// changes), so a featured audit opened by a whole room costs one render.
const MAX_RENDERS = 2;
const CACHE_BYTES = 64 * 1024 * 1024;
const MAX_CACHED_PDF = 16 * 1024 * 1024;
interface PdfState {
  active: number;
  cache: Map<string, Buffer>;
  bytes: number;
  /** Renders in progress: a second request for the same PDF waits for the first. */
  inflight: Map<string, Promise<Buffer>>;
}
const g = globalThis as typeof globalThis & { __vibeauditPdf2?: PdfState };
const state = (g.__vibeauditPdf2 ??= { active: 0, cache: new Map(), bytes: 0, inflight: new Map() });

/** The three DejaVu faces the PDF uses, vendored (license beside them) so every host ships them. */
export const fontDir = () => join(process.cwd(), "assets", "fonts");

export async function loadScreenshots(r: Report): Promise<Map<string, Buffer>> {
  const names = screenshotNames(r);
  const arts = await Promise.all(
    names.map(async (n) => {
      if (DEMO) {
        const data = await demoArtifactBytes(r.auditId, n);
        return data ? { mime: "image/jpeg", data } : null;
      }
      return getArtifact(db(), r.auditId, n).catch(() => null);
    }),
  );
  const out = new Map<string, Buffer>();
  arts.forEach((a, i) => {
    if (!a || a.mime !== "image/jpeg" || a.data.length > EXPORT_LIMITS.imageBytes) return;
    if (a.data[0] !== 0xff || a.data[1] !== 0xd8 || a.data[2] !== 0xff) return;
    out.set(names[i]!, a.data);
  });
  return out;
}

/** Runs `render` under the concurrency cap, shares it with concurrent callers and caches it; null = busy. */
export async function cachedPdf(key: string, render: () => Promise<Buffer>): Promise<Buffer | null> {
  const hit = state.cache.get(key);
  if (hit) {
    state.cache.delete(key);
    state.cache.set(key, hit); // most recently used last
    return hit;
  }
  const running = state.inflight.get(key);
  if (running) return running;
  if (state.active >= MAX_RENDERS) return null;
  state.active++;
  const p = render().then((pdf) => {
    if (pdf.length <= MAX_CACHED_PDF) {
      state.cache.set(key, pdf);
      state.bytes += pdf.length;
      for (const [k, v] of state.cache) {
        if (state.bytes <= CACHE_BYTES) break;
        state.cache.delete(k);
        state.bytes -= v.length;
      }
    }
    return pdf;
  });
  state.inflight.set(key, p);
  try {
    return await p;
  } finally {
    state.inflight.delete(key);
    state.active--;
  }
}
