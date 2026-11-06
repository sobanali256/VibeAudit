"use client";

import type { Report } from "@vibeaudit/shared";
import { useEffect, useMemo, useRef, useState } from "react";
import { type LineKind, consoleLines } from "./console-lines";

const STYLE: Record<LineKind, string> = {
  comment: "text-zinc-500",
  cmd: "text-zinc-100",
  out: "text-zinc-400",
  proven: "font-semibold text-red-400",
  blocked: "font-semibold text-emerald-400",
  dim: "text-zinc-600",
};
const TYPE_MS = 14; // per tick while a command types out
const CHARS_PER_TICK = 3;
const PAUSE_MS: Record<LineKind, number> = { comment: 500, cmd: 300, out: 70, proven: 650, blocked: 550, dim: 120 };

/**
 * Terminal-style replay of the audit: the repo's own install-time attempts and the control
 * that stopped each, then every request that proved a finding and what the app answered. It
 * types itself out once when scrolled into view (all at once for reduced-motion users).
 * Everything shown comes from the stored report; app-derived text is rendered as text.
 */
export function AttackConsole({ report }: { report: Report }) {
  const lines = useMemo(() => consoleLines(report), [report]);
  const [line, setLine] = useState(0); // lines fully shown
  const [chars, setChars] = useState(0); // chars of the line being typed
  const [running, setRunning] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const started = useRef(false);
  const done = line >= lines.length;
  const playing = running && !done;

  // Start the first time it's on screen (reduced motion: show it all at once instead).
  useEffect(() => {
    const el = box.current;
    if (!el || started.current) return;
    const io = new IntersectionObserver(
      (es) => {
        if (!es.some((e) => e.isIntersecting) || started.current) return;
        started.current = true;
        if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) setLine(lines.length);
        else setRunning(true);
      },
      { threshold: 0.3 },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [lines.length]);

  useEffect(() => {
    if (!playing) return;
    const cur = lines[line]!;
    if (cur.kind === "cmd" && chars < cur.text.length) {
      const t = setTimeout(() => setChars((c) => Math.min(cur.text.length, c + CHARS_PER_TICK)), TYPE_MS);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => {
      setLine((l) => l + 1);
      setChars(0);
    }, PAUSE_MS[cur.kind]);
    return () => clearTimeout(t);
  }, [playing, line, chars, lines]);

  // Keep the newest line in view while it plays, unless the viewer scrolled up to read.
  useEffect(() => {
    const el = box.current;
    if (el && playing && el.scrollHeight - el.scrollTop - el.clientHeight < 60) el.scrollTop = el.scrollHeight;
  }, [line, chars, playing]);

  if (!lines.length) return null;
  const shown = lines.slice(0, Math.min(line + 1, lines.length));

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-baseline justify-between gap-2">
        <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">Attack replay</h3>
        <div className="flex gap-2 text-xs">
          {!done ? (
            <button type="button" onClick={() => { started.current = true; setRunning(false); setLine(lines.length); }} className="text-zinc-600 underline underline-offset-2 dark:text-zinc-400">
              Show all
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => {
              started.current = true;
              setLine(0);
              setChars(0);
              setRunning(true);
            }}
            className="text-zinc-600 underline underline-offset-2 dark:text-zinc-400"
          >
            Replay
          </button>
        </div>
      </div>
      <div
        ref={box}
        aria-hidden
        className="max-h-96 overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950 p-4 font-mono text-xs leading-5"
      >
        {shown.map((l, i) => {
          const typing = i === line && !done && l.kind === "cmd";
          const text = typing ? l.text.slice(0, chars) : l.text;
          return (
            <div key={i} className={`break-all whitespace-pre-wrap ${STYLE[l.kind]}`}>
              {l.kind === "cmd" ? <span className="text-emerald-500">$ </span> : null}
              {text || " "}
              {typing ? <span className="animate-pulse text-zinc-100">▍</span> : null}
            </div>
          );
        })}
      </div>
      {/* The full transcript for screen readers; the animated pane above is decorative. */}
      <pre className="sr-only">{lines.map((l) => (l.kind === "cmd" ? `$ ${l.text}` : l.text)).join("\n")}</pre>
      <p className="text-xs text-zinc-500">
        Rebuilt from this audit&apos;s evidence: the containment log and the requests that proved each finding.
      </p>
    </div>
  );
}
