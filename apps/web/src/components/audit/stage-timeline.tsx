import type { AuditStage } from "@vibeaudit/shared";
import { AUDIT_STAGES } from "@vibeaudit/shared/stages";
import { type AuditView, isTerminal } from "@/lib/view";

const LABELS: Record<AuditStage, string> = {
  intake: "Fetch",
  plan: "Plan",
  approve: "Approve",
  static: "Static scan",
  install: "Install",
  build: "Build",
  run: "Run",
  dynamic: "Probe",
  verify: "Verify",
  report: "Report",
};

type StepState = "done" | "active" | "failed" | "skipped" | "pending";

/**
 * Stage progress. Stages the worker announced (`stage` events) are done; the current one is
 * active (or failed); stages it jumped over are skipped. Before the event log has loaded,
 * everything before the current stage counts as done.
 */
export function StageTimeline({ view, seen }: { view: AuditView; seen: ReadonlySet<string> }) {
  const terminal = isTerminal(view.status);
  const cur = view.stage ? AUDIT_STAGES.indexOf(view.stage) : -1;
  const haveLog = seen.size > 0;

  const stateOf = (s: AuditStage, i: number): StepState => {
    if (view.status === "queued") return "pending";
    if (i === cur && !terminal) return "active";
    if (i === cur && (view.status === "failed" || view.status === "cancelled")) return "failed";
    if (haveLog) {
      if (seen.has(s)) return i <= cur || terminal ? "done" : "pending";
      return i < cur || terminal ? "skipped" : "pending";
    }
    if (terminal) return view.status === "completed" || i <= cur ? "done" : "skipped";
    return i < cur ? "done" : "pending";
  };

  return (
    <ol className="grid grid-cols-5 gap-2 sm:grid-cols-10" aria-label="Audit stages">
      {AUDIT_STAGES.map((s, i) => {
        const st = stateOf(s, i);
        return (
          <li key={s} className="flex flex-col gap-1.5" aria-current={st === "active" ? "step" : undefined}>
            <span className={`h-1.5 rounded-full ${BAR[st]}`} />
            <span className={`text-xs ${TEXT[st]}`}>
              {LABELS[s]}
              <span className="sr-only"> ({st})</span>
            </span>
          </li>
        );
      })}
    </ol>
  );
}

const BAR: Record<StepState, string> = {
  done: "bg-emerald-500",
  active: "bg-sky-500 animate-pulse",
  failed: "bg-red-500",
  skipped: "bg-zinc-200 dark:bg-zinc-800",
  pending: "bg-zinc-200 dark:bg-zinc-800",
};
const TEXT: Record<StepState, string> = {
  done: "text-zinc-700 dark:text-zinc-300",
  active: "font-medium text-sky-700 dark:text-sky-300",
  failed: "font-medium text-red-700 dark:text-red-400",
  skipped: "text-zinc-400 line-through dark:text-zinc-600",
  pending: "text-zinc-500 dark:text-zinc-500",
};
