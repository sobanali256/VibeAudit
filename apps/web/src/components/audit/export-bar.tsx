"use client";

import type { Report } from "@vibeaudit/shared";
import { useState } from "react";
import { reportToMarkdown } from "@/lib/export/markdown";
import { exportFilename } from "@/lib/export/shared";

type Busy = "idle" | "pdf" | "copied" | "error";

function save(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/**
 * Export the finished report. Markdown is built right here from the report already on the page
 * (so "Copy" keeps the click's user gesture, which Safari needs for the clipboard); the PDF is
 * made by the server. Agents can fetch either directly: /api/audits/<id>/report.md or .pdf.
 */
export function ExportBar({ report }: { report: Report }) {
  const [state, setState] = useState<Busy>("idle");
  const [msg, setMsg] = useState("");
  const md = () => reportToMarkdown(report, { origin: window.location.origin });

  const downloadMd = () => save(new Blob([md()], { type: "text/markdown;charset=utf-8" }), exportFilename(report, "md"));

  const copyMd = async () => {
    try {
      await navigator.clipboard.writeText(md());
      setState("copied");
      setMsg("Markdown copied: paste it into your coding agent.");
    } catch {
      setState("error");
      setMsg("Couldn't copy here. Use the Markdown button to download it instead.");
    }
  };

  const downloadPdf = async () => {
    setState("pdf");
    setMsg("Making the PDF…");
    try {
      const res = await fetch(`/api/audits/${encodeURIComponent(report.auditId)}/report.pdf`);
      if (!res.ok) {
        const err = (await res.json().catch(() => null)) as { error?: string } | null;
        throw new Error(err?.error ?? `HTTP ${res.status}`);
      }
      save(await res.blob(), exportFilename(report, "pdf"));
      setState("idle");
      setMsg("");
    } catch (e) {
      setState("error");
      setMsg(`PDF failed: ${e instanceof Error ? e.message : "unknown error"}.`);
    }
  };

  const btn =
    "rounded-md border border-zinc-300 px-2.5 py-1 text-xs font-medium text-zinc-700 hover:border-zinc-500 disabled:opacity-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:border-zinc-500";
  return (
    <div className="flex flex-wrap items-center gap-2 print:hidden">
      <span className="text-xs text-zinc-500">Export</span>
      <button type="button" onClick={downloadMd} className={btn}>
        Markdown
      </button>
      <button type="button" onClick={downloadPdf} disabled={state === "pdf"} className={btn}>
        {state === "pdf" ? "PDF…" : "PDF"}
      </button>
      <button type="button" onClick={copyMd} className={btn}>
        Copy for AI agent
      </button>
      <span role="status" aria-live="polite" className={`text-xs ${state === "error" ? "text-red-700 dark:text-red-400" : "text-zinc-500"}`}>
        {msg}
      </span>
    </div>
  );
}
