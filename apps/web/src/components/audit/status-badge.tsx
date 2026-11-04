import type { AuditStatus } from "@vibeaudit/shared";

const STYLES: Record<AuditStatus, [string, string]> = {
  queued: ["Queued", "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"],
  running: ["Running", "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300"],
  awaiting_approval: ["Needs approval", "bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-300"],
  completed: ["Completed", "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300"],
  static_only: ["Static only", "bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-300"],
  failed: ["Failed", "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300"],
  cancelled: ["Cancelled", "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400"],
};

export function StatusBadge({ status }: { status: AuditStatus }) {
  const [label, cls] = STYLES[status];
  return <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${cls}`}>{label}</span>;
}
