import "server-only";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Client IP. The app only listens on 127.0.0.1 behind Caddy, which replaces any
 * client-sent X-Forwarded-For with the real peer address, so the last entry is trustworthy.
 */
export function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) {
    const last = xff.split(",").pop()?.trim();
    if (last) return ipKey(last.slice(0, 64));
  }
  return "local";
}

/**
 * Rate-limit key for an address. IPv6 clients usually control a whole /64, so per-address
 * limits would be trivially bypassed by rotating: key them by their /64 prefix instead.
 */
export function ipKey(ip: string): string {
  if (!ip.includes(":")) return ip;
  const v4mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (v4mapped) return v4mapped[1]!;
  const [head = "", tail = ""] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = ip.includes("::") ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t] : h;
  return `${groups.slice(0, 4).map((g) => (parseInt(g, 16) || 0).toString(16)).join(":")}::/64`;
}

/**
 * CSRF guard for state-changing requests: same-origin JSON only. Browsers always send
 * Origin on cross-origin POSTs, and a JSON content type can't be sent cross-site without a
 * preflight we never answer.
 */
export function checkMutation(req: Request): string | null {
  const ct = req.headers.get("content-type") ?? "";
  if (!/^application\/json\b/i.test(ct)) return "expected application/json";
  const origin = req.headers.get("origin");
  const host = req.headers.get("host");
  if (origin) {
    try {
      if (new URL(origin).host !== host) return "cross-origin request refused";
    } catch {
      return "bad origin";
    }
  } else if (req.headers.get("sec-fetch-site") && req.headers.get("sec-fetch-site") !== "same-origin") {
    return "cross-site request refused";
  }
  return null;
}

/** Read a JSON body with a hard size cap (never buffer an unbounded upload). */
export async function readJson(req: Request, maxBytes = 8 * 1024): Promise<unknown> {
  const len = Number(req.headers.get("content-length") ?? "0");
  if (len > maxBytes) throw new BodyError("request body too large");
  const reader = req.body?.getReader();
  if (!reader) throw new BodyError("missing body");
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new BodyError("request body too large");
    }
    chunks.push(value);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new BodyError("invalid JSON");
  }
}

export class BodyError extends Error {}

export function jsonError(status: number, error: string, headers?: HeadersInit): Response {
  return Response.json({ error }, { status, headers: { "cache-control": "no-store", ...headers } });
}

// --- owner token -------------------------------------------------------------------
// The creator of an audit gets a random token in an HttpOnly cookie scoped to that audit's
// API path; the db stores only its sha256. Watching a shared link needs no token, but
// answering the approval step (which can start running repo code, with test keys) does.

export const ownerCookieName = (auditId: string) => `va_owner_${auditId}`;
export const ownerCookiePath = (auditId: string) => `/api/audits/${auditId}`;

export function newOwnerToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString("base64url");
  return { token, hash: hashToken(token) };
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function isOwner(req: Request, auditId: string, ownerHash: string | null): boolean {
  if (!ownerHash) return false;
  const token = readCookie(req, ownerCookieName(auditId));
  if (!token || token.length > 128) return false;
  const a = Buffer.from(hashToken(token), "hex");
  const b = Buffer.from(ownerHash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

function readCookie(req: Request, name: string): string | null {
  const header = req.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export function ownerCookie(auditId: string, token: string): string {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  // 1 day is far longer than any audit (20 min cap + 30 min approval window).
  return `${ownerCookieName(auditId)}=${token}; Path=${ownerCookiePath(auditId)}; Max-Age=86400; HttpOnly; SameSite=Strict${secure}`;
}
