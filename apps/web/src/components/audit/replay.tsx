"use client";

import type { PageVisit } from "@vibeaudit/shared";
import { useEffect, useMemo, useState } from "react";

const FRAME_MS = 600;
/** Hold each page's final screenshot long enough to read it. */
const FINAL_MS = 1500;
const NAME_RE = /^[a-z0-9-]{1,40}\.jpg$/;

interface Shot {
  src: string;
  /** e.g. "/admin · 404". Page-derived: rendered as text only. */
  label: string;
  final: boolean;
}

/**
 * Replay of the browser pass: the frames Chromium recorded while each page loaded in the
 * sandbox, then that page's screenshot, page after page. Never autoplays: the viewer presses
 * Play or scrubs. Images come only from this audit's artifact route.
 */
export function Replay({ auditId, pages }: { auditId: string; pages: PageVisit[] }) {
  const shots = useMemo(() => {
    const url = (n: string) => (NAME_RE.test(n) ? `/api/audits/${encodeURIComponent(auditId)}/artifacts/${n}` : null);
    const out: Shot[] = [];
    for (const p of pages) {
      const label = `${p.path} · ${p.status || "no response"}`;
      for (const f of p.frames ?? []) {
        const src = url(f);
        if (src) out.push({ src, label, final: false });
      }
      const shot = p.screenshot ? url(p.screenshot) : null;
      if (shot) out.push({ src: shot, label, final: true });
    }
    return out;
  }, [auditId, pages]);

  const [i, setI] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [broken, setBroken] = useState(false);

  useEffect(() => {
    if (!playing) return;
    const t = setTimeout(() => {
      if (i + 1 >= shots.length) setPlaying(false);
      else setI(i + 1);
    }, shots[i]?.final ? FINAL_MS : FRAME_MS);
    return () => clearTimeout(t);
  }, [playing, i, shots]);

  // Preload the next frame so playback doesn't flicker.
  useEffect(() => {
    const next = shots[i + 1];
    if (next) new Image().src = next.src;
  }, [i, shots]);

  if (shots.length < 2) return null;
  // Clamp: the report can be swapped for a newer one with fewer frames while i is high.
  const at = Math.min(i, shots.length - 1);
  const cur = shots[at]!;
  const end = at + 1 >= shots.length;

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-baseline justify-between gap-2">
        <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">Replay: the app running in the sandbox</h3>
        <span className="text-xs text-zinc-500 tabular-nums">
          {at + 1} / {shots.length}
        </span>
      </div>
      <div className="relative overflow-hidden rounded-lg border border-zinc-200 bg-zinc-100 dark:border-zinc-800 dark:bg-zinc-900">
        {/* eslint-disable-next-line @next/next/no-img-element -- artifact JPEGs, not optimisable assets */}
        <img
          src={cur.src}
          onLoad={() => setBroken(false)}
          onError={() => setBroken(true)}
          alt={`${cur.final ? "Screenshot" : "Frame"} of ${cur.label}`}
          className="aspect-[16/10] w-full object-contain object-top"
        />
        <span aria-hidden className="absolute top-2 left-2 rounded bg-black/70 px-2 py-0.5 font-mono text-xs text-white">
          GET {cur.label}
        </span>
        {broken ? (
          <span className="absolute inset-0 flex items-center justify-center text-xs text-zinc-500">Frame didn&apos;t load. Try again in a moment.</span>
        ) : null}
      </div>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => {
            if (!playing && end) setI(0);
            setPlaying(!playing);
          }}
          aria-label={playing ? "Pause replay" : "Play replay"}
          className="h-8 rounded-md bg-zinc-900 px-3 text-xs font-medium text-white dark:bg-zinc-100 dark:text-zinc-900"
        >
          {playing ? "Pause" : end ? "Replay again" : "Play"}
        </button>
        <input
          type="range"
          min={0}
          max={shots.length - 1}
          value={at}
          aria-valuetext={`${at + 1} of ${shots.length}: ${cur.label}`}
          onChange={(e) => {
            setPlaying(false);
            setI(Number(e.target.value));
          }}
          aria-label="Replay position"
          className="flex-1"
        />
      </div>
      <p className="text-xs text-zinc-500">
        Recorded by headless Chromium inside the sandbox while it visited each page logged out. The browser had no
        route to anything but the app.
      </p>
    </div>
  );
}
