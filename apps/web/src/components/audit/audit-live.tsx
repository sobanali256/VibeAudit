"use client";

import { useEffect, useRef, useState } from "react";
import { type AuditEventView, type AuditView, isTerminal } from "@/lib/view";
import { ApprovalPanel } from "./approval-panel";
import { EventLog } from "./event-log";
import { ReportView } from "./report-view";
import { StageTimeline } from "./stage-timeline";
import { StatusBadge } from "./status-badge";

const MAX_EVENTS = 500;
type Conn = "connecting" | "live" | "reconnecting" | "done";

/** Live view of one audit: initial SSR snapshot, then kept current over SSE. */
export function AuditLive({ initial }: { initial: AuditView }) {
  const [view, setView] = useState(initial);
  const [events, setEvents] = useState<AuditEventView[]>([]);
  const [conn, setConn] = useState<Conn>("connecting");
  // Kept apart from `events` (which is capped), so early stages stay "done" on long audits.
  const [seenStages, setSeenStages] = useState<ReadonlySet<string>>(() => new Set());
  const lastId = useRef("0");
  const buffer = useRef<AuditEventView[]>([]);
  const frame = useRef<number | null>(null);

  useEffect(() => {
    let es: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let stopped = false;
    let backoff = 2000;

    // Replays can deliver hundreds of events at once: batch them into one render per frame.
    const flush = () => {
      frame.current = null;
      const batch = buffer.current;
      buffer.current = [];
      if (!batch.length) return;
      setEvents((prev) => [...prev, ...batch].slice(-MAX_EVENTS));
      const stages = batch.filter((e) => e.kind === "stage" && typeof e.payload.stage === "string");
      if (stages.length) {
        setSeenStages((prev) => {
          const next = new Set(prev);
          for (const e of stages) next.add(e.payload.stage as string);
          return next.size === prev.size ? prev : next;
        });
      }
    };

    const open = () => {
      // EventSource resumes with Last-Event-ID on its own reconnects; `after` covers the
      // manual reconnect below (a non-200 response closes an EventSource for good).
      es = new EventSource(`/api/audits/${initial.id}/events?after=${lastId.current}`);
      es.onopen = () => {
        backoff = 2000;
        setConn("live");
      };
      es.addEventListener("state", (e) => setView(JSON.parse((e as MessageEvent).data)));
      es.addEventListener("ev", (e) => {
        const me = e as MessageEvent;
        if (BigInt(me.lastEventId || "0") <= BigInt(lastId.current)) return; // duplicate after resume
        lastId.current = me.lastEventId;
        buffer.current.push(JSON.parse(me.data));
        frame.current ??= requestAnimationFrame(flush);
      });
      es.addEventListener("end", () => {
        es?.close();
        stopped = true;
        setConn("done");
      });
      es.onerror = () => {
        if (stopped) return;
        setConn("reconnecting");
        if (es?.readyState !== EventSource.CLOSED) return; // EventSource retries by itself
        es = null;
        // A non-200 answer closed it for good. Stop if the audit is gone; else back off.
        retry = setTimeout(async () => {
          const res = await fetch(`/api/audits/${initial.id}`, { cache: "no-store" }).catch(() => null);
          if (stopped) return;
          if (res?.status === 404) {
            stopped = true;
            setConn("done");
            return;
          }
          open();
        }, backoff);
        backoff = Math.min(backoff * 2, 60_000);
      };
    };
    open();
    return () => {
      stopped = true;
      es?.close();
      if (retry) clearTimeout(retry);
      if (frame.current) cancelAnimationFrame(frame.current);
    };
  }, [initial.id]);

  const src = view.source;
  const title = src.kind === "github" ? `${src.owner}/${src.repo}` : src.filename;
  const terminal = isTerminal(view.status);

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="font-mono text-2xl font-semibold tracking-tight break-all">{title}</h1>
          <StatusBadge status={view.status} />
        </div>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          {src.kind === "github" && src.ref ? (
            <>
              ref <span className="font-mono">{src.ref}</span> ·{" "}
            </>
          ) : null}
          started {new Date(view.createdAt).toLocaleString()}
          {!terminal ? <ConnIndicator conn={conn} /> : null}
        </p>
      </header>

      <StageTimeline view={view} seen={seenStages} />

      {view.status === "queued" ? (
        <Notice>
          Waiting in the queue{view.queuePosition ? ` (position ${view.queuePosition})` : ""}. The sandbox runs one audit
          at a time.
        </Notice>
      ) : null}

      {view.status === "awaiting_approval" && view.approval ? (
        view.isOwner ? (
          <ApprovalPanel key={view.approval.requestId} auditId={view.id} request={view.approval} />
        ) : (
          <Notice>The plan is ready and waiting for the person who started this audit to approve it.</Notice>
        )
      ) : null}

      {view.status === "failed" ? (
        <Notice tone="error">
          The audit failed{view.error ? ":" : "."} {view.error ? <span className="font-mono">{view.error}</span> : null}
        </Notice>
      ) : null}
      {view.status === "cancelled" ? (
        <Notice>This audit was cancelled{view.error ? ` (${view.error})` : ""}.</Notice>
      ) : null}

      {view.report ? <ReportView report={view.report} /> : null}

      <EventLog events={events} />
    </div>
  );
}

function ConnIndicator({ conn }: { conn: Conn }) {
  const label = conn === "live" ? "live" : conn === "reconnecting" ? "reconnecting…" : "connecting…";
  return (
    <span className="ml-2 inline-flex items-center gap-1.5 align-middle" aria-live="polite">
      <span
        className={`inline-block size-2 rounded-full ${conn === "live" ? "bg-emerald-500" : "bg-amber-500"} ${conn === "live" ? "animate-pulse" : ""}`}
        aria-hidden
      />
      {label}
    </span>
  );
}

function Notice({ children, tone = "info" }: { children: React.ReactNode; tone?: "info" | "error" }) {
  const cls =
    tone === "error"
      ? "border-red-300 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200"
      : "border-zinc-200 bg-zinc-50 text-zinc-800 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-200";
  return (
    <div role="status" className={`rounded-lg border px-4 py-3 text-sm break-words ${cls}`}>
      {children}
    </div>
  );
}
