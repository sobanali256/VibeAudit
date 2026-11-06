import { getArtifact } from "@vibeaudit/db";
import { db } from "@/lib/db";
import { limits } from "@/lib/rate-limit";
import { clientIp, jsonError } from "@/lib/request";

/**
 * Evidence files (browser screenshots and replay frames) for an audit. Readable by anyone with the audit link,
 * like the report that references them. The pixels come from the audited app, so: served
 * only as image/jpeg (the worker stored only bytes with a JPEG signature), nosniff, and a CSP
 * that lets nothing run if a browser opens it directly.
 */
export async function GET(req: Request, ctx: RouteContext<"/api/audits/[id]/artifacts/[name]">) {
  const { id, name } = await ctx.params;
  const wait = limits.artifact!.take(clientIp(req));
  if (wait) return jsonError(429, "slow down", { "retry-after": String(wait) });
  const art = await getArtifact(db(), id, name);
  if (!art || art.mime !== "image/jpeg") return jsonError(404, "not found");
  return new Response(new Uint8Array(art.data), {
    headers: {
      "content-type": "image/jpeg",
      "content-length": String(art.data.length),
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; sandbox",
      "content-disposition": `inline; filename="${name}"`,
      // Immutable per audit: the worker writes each screenshot once, before the report exists.
      "cache-control": "public, max-age=86400, immutable",
    },
  });
}
