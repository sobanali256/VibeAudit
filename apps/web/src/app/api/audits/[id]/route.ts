import { loadAuditView } from "@/lib/audits";
import { limits } from "@/lib/rate-limit";
import { clientIp, isOwner, jsonError } from "@/lib/request";

export async function GET(req: Request, ctx: RouteContext<"/api/audits/[id]">) {
  const { id } = await ctx.params;
  const wait = limits.read.take(clientIp(req));
  if (wait) return jsonError(429, "slow down", { "retry-after": String(wait) });
  const view = await loadAuditView(id, (row) => isOwner(req, id, row.owner_hash));
  if (!view) return jsonError(404, "audit not found");
  return Response.json(view, { headers: { "cache-control": "no-store" } });
}
