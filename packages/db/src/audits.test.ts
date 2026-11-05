// Integration tests. Need a throwaway Postgres: set TEST_DATABASE_URL (skipped otherwise).
// The schema is dropped and recreated, so never point this at a real database.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  addEvent,
  claimNextAudit,
  createAudit,
  createDb,
  decideApproval,
  deleteSecrets,
  failStaleAudits,
  finishAudit,
  countOpenAudits,
  getArtifact,
  getAudit,
  putArtifact,
  getAuditSummary,
  getReport,
  getSecrets,
  queuePosition,
  heartbeat,
  listEvents,
  migrate,
  newAuditId,
  requestApproval,
  type Sql,
} from "./index";
import { AUDIT_ID_RE, type ApprovalRequest } from "@vibeaudit/shared";

// Guard hard: this suite DROPs the schema, so only run against a database literally named
// *_test (parse the URL path, don't substring-match the whole URL — a password or role
// containing "_test" must not arm the drop).
const url = process.env.TEST_DATABASE_URL;
function isTestDb(u: string | undefined): u is string {
  if (!u) return false;
  try {
    return /_test$/.test(new URL(u).pathname.replace(/^\//, ""));
  } catch {
    return false;
  }
}
const d = isTestDb(url) ? describe : describe.skip;

const src = { kind: "github" as const, owner: "a", repo: "b" };
const req = (auditId: string, requestId = "req-0000001"): ApprovalRequest => ({
  auditId,
  requestId,
  plan: { framework: "nextjs", packageManager: "npm", installCommand: "npm ci", buildCommand: null, startCommand: null, port: null },
  env: [{ name: "OPENAI_API_KEY", provide: "placeholder" }],
  installScripts: [],
  expiresAt: new Date(Date.now() + 600_000).toISOString(),
});

it("newAuditId is valid and unique", () => {
  const ids = new Set(Array.from({ length: 1000 }, newAuditId));
  expect(ids.size).toBe(1000);
  for (const id of ids) expect(id).toMatch(AUDIT_ID_RE);
});

d("audits (postgres)", { timeout: 60_000 }, () => {
  let sql: Sql;
  beforeAll(async () => {
    sql = createDb(url!, { max: 4 });
    const [dbrow] = await sql<{ current_database: string }[]>`SELECT current_database()`;
    if (!dbrow || !/_test$/.test(dbrow.current_database)) throw new Error(`refusing to drop non-test db ${dbrow?.current_database}`);
    await sql`DROP SCHEMA public CASCADE`;
    await sql`CREATE SCHEMA public`;
    expect(await migrate(sql)).toEqual([1, 2, 3]);
    expect(await migrate(sql)).toEqual([]); // idempotent
  });
  beforeEach(async () => {
    await sql`TRUNCATE audits CASCADE`;
  });
  afterAll(async () => {
    await sql?.end();
  });

  it("claims in FIFO order, one active audit at a time", async () => {
    const a = await createAudit(sql, src);
    const b = await createAudit(sql, src);
    const first = await claimNextAudit(sql);
    expect(first?.id).toBe(a.id);
    expect(first?.status).toBe("running");
    expect(await claimNextAudit(sql)).toBeNull(); // a still active
    await finishAudit(sql, a.id, { status: "completed" });
    expect((await claimNextAudit(sql))?.id).toBe(b.id);
  });

  it("parallel claimers never double-claim", async () => {
    for (let i = 0; i < 5; i++) await createAudit(sql, src);
    const results = await Promise.all(Array.from({ length: 8 }, () => claimNextAudit(sql, 3)));
    const claimed = results.filter(Boolean).map((r) => r!.id);
    expect(claimed.length).toBe(3);
    expect(new Set(claimed).size).toBe(3);
  });

  it("approval: binds to request id, stores secrets apart, wipes them on finish", async () => {
    const a = await createAudit(sql, src);
    await claimNextAudit(sql);
    await requestApproval(sql, a.id, req(a.id));
    expect((await getAudit(sql, a.id))?.status).toBe("awaiting_approval");

    const decision = { decision: "approve" as const, auditId: a.id, requestId: "req-0000001", ignoreScripts: false, testKeyVars: ["OPENAI_API_KEY"] };
    // wrong request id
    expect(await decideApproval(sql, { ...decision, requestId: "req-stale00" })).toBe(false);
    // key for an undeclared var
    await expect(
      decideApproval(sql, { ...decision, testKeyVars: [] }, { testKeys: { OPENAI_API_KEY: "sk-1234567890" } }),
    ).rejects.toThrow();
    expect(await decideApproval(sql, decision, { testKeys: { OPENAI_API_KEY: "sk-1234567890" } })).toBe(true);
    // can't decide twice
    expect(await decideApproval(sql, decision)).toBe(false);

    const row = await getAudit(sql, a.id);
    expect(row?.status).toBe("running");
    expect(JSON.stringify(row)).not.toContain("sk-1234567890");
    expect(await getSecrets(sql, a.id)).toEqual({ OPENAI_API_KEY: "sk-1234567890" });

    await finishAudit(sql, a.id, { status: "completed" });
    expect(await getSecrets(sql, a.id)).toEqual({});
  });

  it("cancel decision ends the audit", async () => {
    const a = await createAudit(sql, src);
    await claimNextAudit(sql);
    await requestApproval(sql, a.id, req(a.id));
    expect(await decideApproval(sql, { decision: "cancel", auditId: a.id, requestId: "req-0000001" })).toBe(true);
    const row = await getAudit(sql, a.id);
    expect(row?.status).toBe("cancelled");
    expect(row?.finished_at).not.toBeNull();
  });

  it("events: ordered, resumable after an id", async () => {
    const a = await createAudit(sql, src);
    const e1 = await addEvent(sql, a.id, "stage", { stage: "intake" });
    await addEvent(sql, a.id, "stage", { stage: "plan" });
    const all = await listEvents(sql, a.id);
    expect(all.map((e) => e.payload.stage)).toEqual(["intake", "plan"]);
    expect((await listEvents(sql, a.id, e1)).map((e) => e.payload.stage)).toEqual(["plan"]);
    expect(await listEvents(sql, a.id, "1; DROP TABLE audits")).toHaveLength(2); // bad cursor -> from start
  });

  it("heartbeat reports cancellation; stale leases fail and wipe secrets", async () => {
    const a = await createAudit(sql, src);
    await claimNextAudit(sql);
    expect(await heartbeat(sql, a.id, "install")).toBe(true);
    expect((await getAudit(sql, a.id))?.stage).toBe("install");
    await sql`INSERT INTO audit_secrets (audit_id, test_keys) VALUES (${a.id}, '{"X":"y"}')`;
    await sql`UPDATE audits SET heartbeat_at = now() - interval '10 minutes' WHERE id = ${a.id}`;
    expect(await failStaleAudits(sql, 60_000, 3_600_000)).toEqual([a.id]);
    const row = await getAudit(sql, a.id);
    expect(row?.status).toBe("failed");
    expect(await getSecrets(sql, a.id)).toEqual({});
    expect(await heartbeat(sql, a.id)).toBe(false);
  });

  it("frees an awaiting_approval slot on a stale lease, and expires unanswered approvals", async () => {
    // stale lease during approval -> failed
    const a = await createAudit(sql, src);
    await claimNextAudit(sql);
    await requestApproval(sql, a.id, req(a.id));
    await sql`UPDATE audits SET heartbeat_at = now() - interval '10 minutes' WHERE id = ${a.id}`;
    expect(await failStaleAudits(sql, 60_000, 3_600_000)).toContain(a.id);
    expect((await getAudit(sql, a.id))?.status).toBe("failed");

    // fresh heartbeat but the deadline passed -> cancelled (approval expired)
    await sql`TRUNCATE audits CASCADE`;
    const b = await createAudit(sql, src);
    await claimNextAudit(sql);
    await requestApproval(sql, b.id, { ...req(b.id), expiresAt: new Date(Date.now() - 1000).toISOString() });
    const affected = await failStaleAudits(sql, 600_000, 3_600_000);
    expect(affected).toContain(b.id);
    expect((await getAudit(sql, b.id))?.status).toBe("cancelled");
  });

  it("cancels audits that sit queued past the max age", async () => {
    const a = await createAudit(sql, src);
    await sql`UPDATE audits SET created_at = now() - interval '2 hours' WHERE id = ${a.id}`;
    expect(await failStaleAudits(sql, 600_000, 3_600_000)).toEqual([a.id]);
    expect((await getAudit(sql, a.id))?.status).toBe("cancelled");
  });

  it("static_only decision clears any previously stored keys", async () => {
    const a = await createAudit(sql, src);
    await claimNextAudit(sql);
    await requestApproval(sql, a.id, req(a.id));
    await sql`INSERT INTO audit_secrets (audit_id, test_keys) VALUES (${a.id}, '{"OPENAI_API_KEY":"sk-leftover-123"}')`;
    expect(await decideApproval(sql, { decision: "static_only", auditId: a.id, requestId: "req-0000001" })).toBe(true);
    expect((await getAudit(sql, a.id))?.status).toBe("running");
    expect(await getSecrets(sql, a.id)).toEqual({});
  });

  it("rejects a key for a var the plan never offered as a placeholder", async () => {
    const a = await createAudit(sql, src);
    await claimNextAudit(sql);
    // request offers only OPENAI_API_KEY as placeholder
    await requestApproval(sql, a.id, req(a.id));
    const decision = { decision: "approve" as const, auditId: a.id, requestId: "req-0000001", ignoreScripts: false, testKeyVars: ["STRIPE_SECRET_KEY"] };
    await expect(
      decideApproval(sql, decision, { testKeys: { STRIPE_SECRET_KEY: "sk-1234567890" } }),
    ).rejects.toThrow(/didn't offer|undeclared/);
    // the audit stays awaiting_approval (transaction rolled back)
    expect((await getAudit(sql, a.id))?.status).toBe("awaiting_approval");
  });

  it("rejects an invalid decision shape", async () => {
    const a = await createAudit(sql, src);
    await claimNextAudit(sql);
    await requestApproval(sql, a.id, req(a.id));
    // @ts-expect-error bogus decision value
    await expect(decideApproval(sql, { decision: "bogus", auditId: a.id, requestId: "req-0000001" })).rejects.toThrow();
    expect((await getAudit(sql, a.id))?.status).toBe("awaiting_approval");
  });

  it("finish is idempotent and doesn't resurrect terminal audits", async () => {
    const a = await createAudit(sql, src);
    await claimNextAudit(sql);
    await finishAudit(sql, a.id, { status: "failed", error: "boom" });
    await finishAudit(sql, a.id, { status: "completed" });
    const row = await getAudit(sql, a.id);
    expect(row?.status).toBe("failed");
    expect(row?.error).toBe("boom");
  });

  it("getAudit rejects malformed ids without querying", async () => {
    expect(await getAudit(sql, "x' OR 1=1 --")).toBeNull();
  });

  it("deleteSecrets is a no-op when absent", async () => {
    await expect(deleteSecrets(sql, "nonexistentauditid00")).resolves.toBeUndefined();
  });

  it("summary omits the report; owner hash stored; queue position and open count", async () => {
    const a = await createAudit(sql, src, { ownerHash: "ab".repeat(32) });
    const b = await createAudit(sql, src);
    const c = await createAudit(sql, src);
    expect(await countOpenAudits(sql)).toBe(3);
    expect(await queuePosition(sql, b.id)).toBe(2);
    await claimNextAudit(sql);
    expect(await queuePosition(sql, a.id)).toBeNull(); // running, not queued
    expect(await queuePosition(sql, b.id)).toBe(2); // behind the active one
    expect(await queuePosition(sql, c.id)).toBe(3);

    const report = { auditId: a.id, source: src, status: "completed" as const, score: 90, mode: "runtime" as const,
      findings: [], containment: [], startedAt: "x", finishedAt: "y" };
    await finishAudit(sql, a.id, { status: "completed", report });
    const sum = await getAuditSummary(sql, a.id);
    expect(sum?.owner_hash).toBe("ab".repeat(32));
    expect(sum && "report" in sum).toBe(false);
    expect((await getReport(sql, a.id))?.score).toBe(90);
    expect(await countOpenAudits(sql)).toBe(2);
    expect(await getAuditSummary(sql, "bad id")).toBeNull();
  });

  it("refuses a decision once the approval deadline has passed, even before the sweep", async () => {
    const a = await createAudit(sql, src);
    await claimNextAudit(sql);
    await requestApproval(sql, a.id, { ...req(a.id), expiresAt: new Date(Date.now() - 1000).toISOString() });
    expect(await decideApproval(sql, { decision: "static_only", auditId: a.id, requestId: "req-0000001" })).toBe(false);
    expect((await getAudit(sql, a.id))?.status).toBe("awaiting_approval");
  });
  it("stores and reads artifacts; rejects bad names, oversize and unknown audits", async () => {
    const a = await createAudit(sql, src);
    const jpg = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 0xff, 0xd9]);
    await putArtifact(sql, a.id, "page-1.jpg", jpg);
    await putArtifact(sql, a.id, "page-1.jpg", jpg); // replace is fine
    const got = await getArtifact(sql, a.id, "page-1.jpg");
    expect(got?.mime).toBe("image/jpeg");
    expect(Buffer.from(got!.data).equals(jpg)).toBe(true);
    expect(await getArtifact(sql, a.id, "page-2.jpg")).toBeNull();
    expect(await getArtifact(sql, a.id, "../x.jpg")).toBeNull();
    await expect(putArtifact(sql, a.id, "x.svg", jpg)).rejects.toThrow();
    await expect(putArtifact(sql, a.id, "big.jpg", Buffer.alloc(1024 * 1024 + 1))).rejects.toThrow();
    await expect(putArtifact(sql, "zzzzzzzzzzzzzzzzzzzz", "page-1.jpg", jpg)).rejects.toThrow(); // FK
  });
});
