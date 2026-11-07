import { decideApproval, getAuditSummary } from "@vibeaudit/db";
import { ApprovalDecision, ApprovalSecrets } from "@vibeaudit/shared";
import { z } from "zod";
import { db } from "@/lib/db";
import { DEMO, DEMO_MESSAGE } from "@/lib/demo";
import { limits } from "@/lib/rate-limit";
import { BodyError, checkMutation, clientIp, isOwner, jsonError, readJson } from "@/lib/request";

const Body = z.object({
  requestId: z.string().min(8).max(64),
  decision: z.enum(["approve", "static_only", "cancel"]),
  ignoreScripts: z.boolean().optional(),
  /** Real test keys, only with approve. Blank entries are dropped before validation. */
  testKeys: z.record(z.string().max(64), z.string().max(600)).optional(),
});

/**
 * Answer the human-approval step. Only the audit's creator (owner cookie) may answer.
 * Test keys are validated and stored by decideApproval in audit_secrets, never echoed back,
 * and never included in any error message (which is why parse errors are generic here).
 */
export async function POST(req: Request, ctx: RouteContext<"/api/audits/[id]/approval">) {
  if (DEMO) return jsonError(503, DEMO_MESSAGE);
  const { id } = await ctx.params;
  const bad = checkMutation(req);
  if (bad) return jsonError(403, bad);
  const wait = limits.approve.take(clientIp(req));
  if (wait) return jsonError(429, "slow down", { "retry-after": String(wait) });

  const sql = db();
  const row = await getAuditSummary(sql, id);
  if (!row) return jsonError(404, "audit not found");
  if (!isOwner(req, id, row.owner_hash)) return jsonError(403, "Only the person who started this audit can answer it.");
  if (row.status !== "awaiting_approval") return jsonError(409, "This audit isn't waiting for approval.");

  let raw: unknown;
  try {
    raw = await readJson(req, 16 * 1024);
  } catch (e) {
    return jsonError(400, e instanceof BodyError ? e.message : "bad request");
  }
  const body = Body.safeParse(raw);
  if (!body.success) return jsonError(400, "invalid approval");
  const { requestId, decision } = body.data;

  const testKeys = Object.fromEntries(
    Object.entries(body.data.testKeys ?? {})
      .map(([k, v]) => [k, v.trim()] as const)
      .filter(([, v]) => v !== ""),
  );
  const hasKeys = Object.keys(testKeys).length > 0;
  if (hasKeys && decision !== "approve") return jsonError(400, "test keys are only used when running the app");

  const parsedDecision = ApprovalDecision.safeParse(
    decision === "approve"
      ? { decision, auditId: id, requestId, ignoreScripts: body.data.ignoreScripts ?? false, testKeyVars: Object.keys(testKeys) }
      : { decision, auditId: id, requestId },
  );
  if (!parsedDecision.success) return jsonError(400, "invalid approval");
  let secrets: ApprovalSecrets | undefined;
  if (hasKeys) {
    const s = ApprovalSecrets.safeParse({ testKeys });
    if (!s.success) return jsonError(400, "A test key is malformed: use 8-512 printable characters with no spaces.");
    secrets = s.data;
  }

  let ok: boolean;
  try {
    ok = await decideApproval(sql, parsedDecision.data, secrets);
  } catch (e) {
    // decideApproval's own errors name env vars at most, never values.
    const msg = e instanceof Error && /^test key/.test(e.message) ? e.message : "could not record the decision";
    return jsonError(400, msg);
  }
  if (!ok) return jsonError(409, "This approval request has expired or was already answered.");
  return Response.json({ ok: true }, { headers: { "cache-control": "no-store" } });
}
