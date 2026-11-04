import { randomBytes } from "node:crypto";
import type { JSONValue, Sql } from "postgres";
import {
  AUDIT_ID_RE,
  ApprovalDecision,
  ApprovalRequest,
  ApprovalSecrets,
  type AuditSource,
  type AuditStage,
  type AuditStatus,
  type Report,
} from "@vibeaudit/shared";

export interface AuditRow {
  id: string;
  source: AuditSource;
  status: AuditStatus;
  stage: AuditStage | null;
  created_at: Date;
  updated_at: Date;
  started_at: Date | null;
  finished_at: Date | null;
  heartbeat_at: Date | null;
  error: string | null;
  approval_request: ApprovalRequest | null;
  approval_decision: ApprovalDecision | null;
  report: Report | null;
  owner_hash: string | null;
}

export interface AuditEventRow {
  id: string; // bigserial comes back as string
  audit_id: string;
  at: Date;
  kind: string;
  payload: Record<string, unknown>;
}

/** 20 chars of lowercase base32: unguessable (100 bits) and valid as AUDIT_ID_RE. */
export function newAuditId(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const bytes = randomBytes(20);
  let out = "";
  for (const b of bytes) out += alphabet[b & 31];
  return out;
}

/** Postgres NOTIFY channels. Payloads are just ids; listeners re-read the rows. */
export const CHANNEL_QUEUE = "vibeaudit_queue";
export const CHANNEL_EVENTS = "vibeaudit_events";

const TERMINAL: AuditStatus[] = ["completed", "static_only", "failed", "cancelled"];

const json = (v: unknown) => v as JSONValue;

export async function createAudit(sql: Sql, source: AuditSource, opts: { ownerHash?: string } = {}): Promise<AuditRow> {
  const id = newAuditId();
  const [row] = await sql<AuditRow[]>`
    INSERT INTO audits (id, source, owner_hash)
    VALUES (${id}, ${sql.json(json(source))}, ${opts.ownerHash ?? null}) RETURNING *`;
  await sql`SELECT pg_notify(${CHANNEL_QUEUE}, ${id})`;
  return row!;
}

export async function getAudit(sql: Sql, id: string): Promise<AuditRow | null> {
  if (!AUDIT_ID_RE.test(id)) return null;
  const [row] = await sql<AuditRow[]>`SELECT * FROM audits WHERE id = ${id}`;
  return row ?? null;
}

/** Audit row without the (possibly large) report, for frequent progress reads. */
export type AuditSummaryRow = Omit<AuditRow, "report">;

export async function getAuditSummary(sql: Sql, id: string): Promise<AuditSummaryRow | null> {
  if (!AUDIT_ID_RE.test(id)) return null;
  const [row] = await sql<AuditSummaryRow[]>`
    SELECT id, source, status, stage, created_at, updated_at, started_at, finished_at,
           heartbeat_at, error, approval_request, approval_decision, owner_hash
    FROM audits WHERE id = ${id}`;
  return row ?? null;
}

export async function getReport(sql: Sql, id: string): Promise<Report | null> {
  if (!AUDIT_ID_RE.test(id)) return null;
  const [row] = await sql<{ report: Report | null }[]>`SELECT report FROM audits WHERE id = ${id}`;
  return row?.report ?? null;
}

/** Audits not yet finished (queued, running or awaiting approval): for intake back-pressure. */
export async function countOpenAudits(sql: Sql): Promise<number> {
  const [row] = await sql<{ n: number }[]>`
    SELECT count(*)::int AS n FROM audits WHERE status IN ('queued','running','awaiting_approval')`;
  return row?.n ?? 0;
}

/** 1-based position of a queued audit (audits ahead of it, including the active one, + 1). */
export async function queuePosition(sql: Sql, id: string): Promise<number | null> {
  const [row] = await sql<{ n: number | null }[]>`
    SELECT CASE WHEN a.status = 'queued' THEN (
      SELECT count(*)::int FROM audits b
      WHERE b.status IN ('running','awaiting_approval')
         OR (b.status = 'queued' AND b.created_at < a.created_at)
    ) + 1 END AS n
    FROM audits a WHERE a.id = ${id}`;
  return row?.n ?? null;
}

/**
 * Claim the oldest queued audit, if no other audit is currently active (one at a time on
 * VM 2). Concurrency-safe across worker processes: the global advisory lock serializes
 * claimers, SKIP LOCKED keeps the queue scan cheap.
 */
export async function claimNextAudit(sql: Sql, maxActive = 1): Promise<AuditRow | null> {
  return sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(${0x636c61696d})`; // "claim"
    const [counts] = await tx<{ active: number }[]>`
      SELECT count(*)::int AS active FROM audits WHERE status IN ('running','awaiting_approval')`;
    if ((counts?.active ?? 0) >= maxActive) return null;
    const [row] = await tx<AuditRow[]>`
      UPDATE audits SET status = 'running', started_at = now(), heartbeat_at = now(), updated_at = now()
      WHERE id = (
        SELECT id FROM audits WHERE status = 'queued' ORDER BY created_at
        FOR UPDATE SKIP LOCKED LIMIT 1
      )
      RETURNING *`;
    return row ?? null;
  });
}

/**
 * Refresh the lease and record the current stage. Returns false if the audit is no longer
 * active (e.g. cancelled). The stage is only updated while running, so a heartbeat can't
 * clobber the `approve` stage set during awaiting_approval.
 */
export async function heartbeat(sql: Sql, id: string, stage?: AuditStage): Promise<boolean> {
  const rows = await sql`
    UPDATE audits SET heartbeat_at = now(), updated_at = now(),
      stage = CASE WHEN status = 'running' THEN COALESCE(${stage ?? null}, stage) ELSE stage END
    WHERE id = ${id} AND status IN ('running','awaiting_approval')
    RETURNING id`;
  return rows.length === 1;
}

export async function addEvent(
  sql: Sql,
  auditId: string,
  kind: string,
  payload: Record<string, unknown> = {},
): Promise<string> {
  const [row] = await sql<{ id: string }[]>`
    INSERT INTO audit_events (audit_id, kind, payload)
    VALUES (${auditId}, ${kind}, ${sql.json(json(payload))}) RETURNING id`;
  await sql`SELECT pg_notify(${CHANNEL_EVENTS}, ${auditId})`;
  return row!.id;
}

/** Events after `afterId` (for SSE resume via Last-Event-ID). */
export async function listEvents(sql: Sql, auditId: string, afterId = "0", limit = 500): Promise<AuditEventRow[]> {
  if (!/^\d{1,19}$/.test(afterId)) afterId = "0";
  return sql<AuditEventRow[]>`
    SELECT * FROM audit_events WHERE audit_id = ${auditId} AND id > ${afterId}
    ORDER BY id LIMIT ${limit}`;
}

/** Park a running audit for human approval. Returns false if it wasn't running. */
export async function requestApproval(sql: Sql, id: string, req: ApprovalRequest): Promise<boolean> {
  const parsed = ApprovalRequest.parse(req);
  if (parsed.auditId !== id) throw new Error("approval request auditId mismatch");
  const rows = await sql`
    UPDATE audits SET status = 'awaiting_approval', stage = 'approve',
      approval_request = ${sql.json(json(parsed))},
      approval_expires_at = ${parsed.expiresAt}, heartbeat_at = now(), updated_at = now()
    WHERE id = ${id} AND status = 'running'
    RETURNING id`;
  return rows.length === 1;
}

/**
 * Record the user's decision (and, for approve, the test keys in their own table).
 * Only succeeds if the audit is waiting on exactly this request.
 */
export async function decideApproval(
  sql: Sql,
  decisionInput: ApprovalDecision,
  secrets?: ApprovalSecrets,
): Promise<boolean> {
  const decision = ApprovalDecision.parse(decisionInput);
  const keys = secrets ? ApprovalSecrets.parse(secrets).testKeys : {};
  if (decision.decision !== "approve" && Object.keys(keys).length) {
    throw new Error("test keys only with approve");
  }
  // approve|static_only resume the worker; cancel ends the audit. No other value reaches here.
  const nextStatus: AuditStatus = decision.decision === "cancel" ? "cancelled" : "running";

  const ok = await sql.begin(async (tx) => {
    const [row] = await tx<{ approval_request: ApprovalRequest | null }[]>`
      SELECT approval_request FROM audits
      WHERE id = ${decision.auditId} AND status = 'awaiting_approval'
        AND approval_request->>'requestId' = ${decision.requestId}
        AND approval_expires_at > now()
      FOR UPDATE`;
    if (!row) return false;

    if (decision.decision === "approve" && Object.keys(keys).length) {
      // Keys only for vars the stored request actually offered as a placeholder.
      const offered = new Set(
        (row.approval_request?.env ?? []).filter((e) => e.provide === "placeholder").map((e) => e.name),
      );
      const declared = new Set(decision.testKeyVars);
      for (const k of Object.keys(keys)) {
        if (!declared.has(k)) throw new Error("test key for an undeclared var");
        if (!offered.has(k)) throw new Error(`test key for a var the plan didn't offer: ${k}`);
      }
    }

    await tx`
      UPDATE audits SET approval_decision = ${tx.json(json(decision))}, status = ${nextStatus},
        finished_at = ${decision.decision === "cancel" ? tx`now()` : null},
        updated_at = now(), heartbeat_at = now()
      WHERE id = ${decision.auditId}`;

    // Always clear first: static_only/cancel, or approve-without-keys, must leave no secrets.
    await tx`DELETE FROM audit_secrets WHERE audit_id = ${decision.auditId}`;
    if (decision.decision === "approve" && Object.keys(keys).length) {
      try {
        await tx`INSERT INTO audit_secrets (audit_id, test_keys)
                 VALUES (${decision.auditId}, ${tx.json(json(keys))})`;
      } catch {
        // Never surface a postgres error here: it carries bound parameters (the keys).
        throw new Error("failed to store test keys");
      }
    }
    return true;
  });
  if (ok && decision.decision === "cancel") await sql`SELECT pg_notify(${CHANNEL_QUEUE}, ${decision.auditId})`;
  if (ok) await sql`SELECT pg_notify(${CHANNEL_EVENTS}, ${decision.auditId})`;
  return ok;
}

/** Worker-only: read the audit's test keys. */
export async function getSecrets(sql: Sql, auditId: string): Promise<Record<string, string>> {
  const [row] = await sql<{ test_keys: Record<string, string> }[]>`
    SELECT test_keys FROM audit_secrets WHERE audit_id = ${auditId}`;
  return row?.test_keys ?? {};
}

export async function deleteSecrets(sql: Sql, auditId: string): Promise<void> {
  await sql`DELETE FROM audit_secrets WHERE audit_id = ${auditId}`;
}

export async function finishAudit(
  sql: Sql,
  id: string,
  outcome: { status: Extract<AuditStatus, "completed" | "static_only" | "failed" | "cancelled">; report?: Report; error?: string },
): Promise<void> {
  await sql.begin(async (tx) => {
    await tx`
      UPDATE audits SET status = ${outcome.status}, finished_at = now(), updated_at = now(),
        report = ${outcome.report ? tx.json(json(outcome.report)) : null},
        error = ${outcome.error ?? null}
      WHERE id = ${id} AND status NOT IN ${tx(TERMINAL)}`;
    await tx`DELETE FROM audit_secrets WHERE audit_id = ${id}`;
  });
  await sql`SELECT pg_notify(${CHANNEL_EVENTS}, ${id})`;
  await sql`SELECT pg_notify(${CHANNEL_QUEUE}, ${id})`; // a slot may have freed
}

/**
 * Crash recovery and timeouts, meant to run on a timer. Frees the single audit slot so the
 * queue can't wedge:
 *  - a running/awaiting_approval audit whose worker stopped heartbeating -> failed (never
 *    silently re-run: a half-run hostile repo shouldn't get a second go);
 *  - an approval nobody answered by its deadline (or with no deadline) -> cancelled;
 *  - a queued audit never picked up within queuedMaxMs -> cancelled.
 * Secrets of every affected audit are wiped. Returns the affected ids.
 */
export async function failStaleAudits(sql: Sql, leaseMs: number, queuedMaxMs: number): Promise<string[]> {
  const ids = await sql.begin(async (tx) => {
    const lease = await tx<{ id: string }[]>`
      UPDATE audits SET status = 'failed', error = 'worker lease expired', finished_at = now(), updated_at = now()
      WHERE status IN ('running','awaiting_approval')
        AND (heartbeat_at IS NULL OR heartbeat_at < now() - ${leaseMs / 1000} * interval '1 second')
      RETURNING id`;
    const expired = await tx<{ id: string }[]>`
      UPDATE audits SET status = 'cancelled', error = 'approval expired', finished_at = now(), updated_at = now()
      WHERE status = 'awaiting_approval'
        AND (approval_expires_at IS NULL OR approval_expires_at < now())
      RETURNING id`;
    const abandoned = await tx<{ id: string }[]>`
      UPDATE audits SET status = 'cancelled', error = 'queued too long', finished_at = now(), updated_at = now()
      WHERE status = 'queued' AND created_at < now() - ${queuedMaxMs / 1000} * interval '1 second'
      RETURNING id`;
    const all = [...lease, ...expired, ...abandoned].map((r) => r.id);
    if (all.length) await tx`DELETE FROM audit_secrets WHERE audit_id IN ${tx(all)}`;
    return all;
  });
  for (const id of ids) {
    await sql`SELECT pg_notify(${CHANNEL_EVENTS}, ${id})`;
    await sql`SELECT pg_notify(${CHANNEL_QUEUE}, ${id})`;
  }
  return ids;
}
