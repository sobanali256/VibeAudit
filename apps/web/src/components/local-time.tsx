"use client";

import { useSyncExternalStore } from "react";

const subscribe = () => () => {};

/**
 * A timestamp in the viewer's locale and timezone. The server renders a fixed UTC form and
 * the client swaps in local time after hydration, so SSR (VM 1, UTC) never mismatches.
 */
export function LocalTime({ iso, mode = "time" }: { iso: string; mode?: "time" | "datetime" }) {
  const hydrated = useSyncExternalStore(subscribe, () => true, () => false);
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return <time>{iso}</time>;
  const text = hydrated
    ? mode === "time"
      ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
      : d.toLocaleString()
    : mode === "time"
      ? `${d.toISOString().slice(11, 19)} UTC`
      : `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
  return <time dateTime={iso}>{text}</time>;
}
