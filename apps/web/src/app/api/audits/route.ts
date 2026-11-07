import { countOpenAudits, createAudit } from "@vibeaudit/db";
import { MAX_OPEN_AUDITS, parseGitHubUrl } from "@vibeaudit/shared";
import { db } from "@/lib/db";
import { DEMO, DEMO_MESSAGE } from "@/lib/demo";
import { limits } from "@/lib/rate-limit";
import { BodyError, checkMutation, clientIp, jsonError, newOwnerToken, ownerCookie, readJson } from "@/lib/request";

/** Create an audit from a GitHub URL. The URL is re-validated here; the form's check is UX only. */
export async function POST(req: Request) {
  if (DEMO) return jsonError(503, DEMO_MESSAGE);
  const bad = checkMutation(req);
  if (bad) return jsonError(403, bad);
  const wait = limits.create.take(clientIp(req));
  if (wait) return jsonError(429, "Too many audits from this address. Try again shortly.", { "retry-after": String(wait) });

  let body: unknown;
  try {
    body = await readJson(req, 2048);
  } catch (e) {
    return jsonError(400, e instanceof BodyError ? e.message : "bad request");
  }
  const url = typeof body === "object" && body && "url" in body ? (body as { url: unknown }).url : null;
  const parsed = typeof url === "string" ? parseGitHubUrl(url) : null;
  if (!parsed) return jsonError(400, "That isn't a github.com repository URL.");

  const sql = db();
  if ((await countOpenAudits(sql)) >= MAX_OPEN_AUDITS) {
    return jsonError(503, "The audit queue is full right now. Try again in a few minutes.", { "retry-after": "120" });
  }

  const { token, hash } = newOwnerToken();
  const row = await createAudit(
    sql,
    { kind: "github", owner: parsed.owner, repo: parsed.repo, ref: parsed.ref, subpath: parsed.subpath },
    { ownerHash: hash },
  );
  return Response.json(
    { id: row.id },
    { status: 201, headers: { "set-cookie": ownerCookie(row.id, token), "cache-control": "no-store" } },
  );
}
