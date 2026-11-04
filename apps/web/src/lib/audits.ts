import "server-only";
import { type AuditEventRow, type AuditSummaryRow, getAuditSummary, getReport, listEvents, queuePosition } from "@vibeaudit/db";
import { db, generation } from "./db";
import { type AuditEventView, type AuditView, isTerminal } from "./view";

const iso = (d: Date | null) => (d ? d.toISOString() : null);

/** Load the public view of an audit. The report column is only read once it's final. */
export async function loadAuditView(id: string, owner: (row: AuditSummaryRow) => boolean): Promise<AuditView | null> {
  const sql = db();
  const row = await getAuditSummary(sql, id);
  if (!row) return null;
  const terminal = isTerminal(row.status);
  const [report, pos] = await Promise.all([
    terminal ? getReport(sql, id) : null,
    row.status === "queued" ? queuePosition(sql, id) : null,
  ]);
  return {
    id: row.id,
    source: row.source,
    status: row.status,
    stage: row.stage,
    createdAt: row.created_at.toISOString(),
    startedAt: iso(row.started_at),
    finishedAt: iso(row.finished_at),
    error: row.error,
    approval: row.status === "awaiting_approval" ? row.approval_request : null,
    decision: row.approval_decision,
    report,
    queuePosition: pos,
    isOwner: owner(row),
  };
}

export function toEventView(e: AuditEventRow): AuditEventView {
  return { id: e.id, at: e.at.toISOString(), kind: e.kind, payload: e.payload };
}

// --- shared reads for SSE ---------------------------------------------------------------
// One NOTIFY wakes every stream watching that audit. Instead of each stream querying on its
// own (2N queries per notify for N viewers), streams share one read per notify generation.
// A read is only reused if it started after the latest NOTIFY, so nobody gets a stale view.
const shared = new Map<string, { gen: number; at: number; p: Promise<unknown> }>();

function share<T>(key: string, id: string, fresh: boolean, load: () => Promise<T>): Promise<T> {
  const gen = generation(id);
  const hit = shared.get(key);
  if (!fresh && hit && hit.gen === gen) return hit.p as Promise<T>;
  const now = Date.now();
  if (shared.size > 500) for (const [k, v] of shared) if (now - v.at > 5000) shared.delete(k);
  const p = load();
  shared.set(key, { gen, at: now, p });
  p.catch(() => shared.delete(key));
  return p;
}

/**
 * The public view without the per-viewer owner flag, shared across streams. `fresh` skips
 * the cache (the backstop poll exists to catch changes that never produced a NOTIFY).
 */
export function sharedAuditView(id: string, fresh = false): Promise<AuditView | null> {
  return share(`v:${id}`, id, fresh, () => loadAuditView(id, () => false));
}

/** Events after `afterId`, shared across streams at the same position. */
export function sharedEvents(id: string, afterId: string, limit: number, fresh = false): Promise<AuditEventRow[]> {
  return share(`e:${id}:${afterId}:${limit}`, id, fresh, () => listEvents(db(), id, afterId, limit));
}
