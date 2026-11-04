// The public shape of an audit, as sent to the browser (SSR props and SSE `state` events).
// Built only from whitelisted columns: never owner_hash, never anything from audit_secrets.
import type { ApprovalDecision, ApprovalRequest, AuditSource, AuditStage, AuditStatus, Report } from "@vibeaudit/shared";

export interface AuditView {
  id: string;
  source: AuditSource;
  status: AuditStatus;
  stage: AuditStage | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
  /** Only while the audit is waiting on it. */
  approval: ApprovalRequest | null;
  decision: ApprovalDecision | null;
  /** Only once the audit has finished. */
  report: Report | null;
  /** 1-based, only while queued. */
  queuePosition: number | null;
  /** Whether this viewer created the audit (may answer the approval step). */
  isOwner: boolean;
}

export interface AuditEventView {
  id: string;
  at: string;
  kind: string;
  payload: Record<string, unknown>;
}

export const TERMINAL_STATUSES: readonly AuditStatus[] = ["completed", "static_only", "failed", "cancelled"];
export const isTerminal = (s: AuditStatus) => TERMINAL_STATUSES.includes(s);
