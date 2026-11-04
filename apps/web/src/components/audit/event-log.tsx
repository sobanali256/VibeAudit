"use client";

import { memo, useEffect, useRef } from "react";
import type { AuditEventView } from "@/lib/view";

const ANSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;

/**
 * Worker progress log. Messages can carry sandbox output (build logs etc.), which is
 * untrusted: rendered strictly as text, never as HTML.
 */
export const EventLog = memo(function EventLog({ events }: { events: AuditEventView[] }) {
  const box = useRef<HTMLDivElement>(null);
  const pinned = useRef(true);

  useEffect(() => {
    const el = box.current;
    if (el && pinned.current) el.scrollTop = el.scrollHeight;
  }, [events]);

  if (!events.length) return null;
  return (
    <section className="flex flex-col gap-2">
      <h2 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">Activity</h2>
      <div
        ref={box}
        onScroll={(e) => {
          const el = e.currentTarget;
          pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
        }}
        className="max-h-96 overflow-y-auto rounded-lg border border-zinc-200 bg-zinc-50 p-3 font-mono text-xs leading-5 dark:border-zinc-800 dark:bg-zinc-950"
      >
        {events.map((e) => (
          <Line key={e.id} e={e} />
        ))}
      </div>
    </section>
  );
});

const Line = memo(function Line({ e }: { e: AuditEventView }) {
  const time = new Date(e.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const stage = typeof e.payload.stage === "string" ? e.payload.stage : null;
  const text = describe(e);
  const long = text.includes("\n") || text.length > 200;
  return (
    <div className="flex gap-2 border-b border-zinc-200/60 py-0.5 last:border-0 dark:border-zinc-800/60">
      <span className="shrink-0 text-zinc-400">{time}</span>
      {stage ? <span className="shrink-0 text-sky-700 dark:text-sky-400">[{stage}]</span> : null}
      {long ? (
        <details className="min-w-0 flex-1">
          <summary className="cursor-pointer truncate text-zinc-700 dark:text-zinc-300">{firstLine(text)}</summary>
          <pre className="mt-1 whitespace-pre-wrap break-all text-zinc-600 dark:text-zinc-400">{text}</pre>
        </details>
      ) : (
        <span className={`min-w-0 flex-1 break-all ${TONE[e.kind] ?? "text-zinc-700 dark:text-zinc-300"}`}>{text}</span>
      )}
    </div>
  );
});

const TONE: Record<string, string> = {
  error: "text-red-700 dark:text-red-400",
  done: "text-emerald-700 dark:text-emerald-400",
  awaiting_approval: "text-amber-700 dark:text-amber-400",
};

function describe(e: AuditEventView): string {
  const p = e.payload;
  switch (e.kind) {
    case "stage":
      return `→ ${String(p.stage ?? "")}`;
    case "log":
      return String(p.msg ?? "").replace(ANSI, "");
    case "awaiting_approval":
      return "plan ready, waiting for approval";
    case "done":
      return `done: ${String(p.status ?? "")}, score ${String(p.score ?? "?")}, ${String(p.findings ?? 0)} finding(s)`;
    case "error":
      return `error: ${String(p.message ?? "")}`;
    case "cancelled":
      return "cancelled";
    default:
      return e.kind;
  }
}

function firstLine(s: string): string {
  const line = s.trim().split("\n")[0] ?? "";
  return line.length > 160 ? `${line.slice(0, 160)}…` : line || "(output)";
}
