"use client";

import type { ContainmentEntry, Evidence, Finding, PageVisit, Report, SandboxControls, Severity } from "@vibeaudit/shared";
import { type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { LocalTime } from "@/components/local-time";
import { describeAttempt } from "./attempts";
import { Replay } from "./replay";
import { AttackConsole } from "./attack-console";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_STYLE: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-400 text-amber-950",
  low: "bg-sky-200 text-sky-900 dark:bg-sky-900 dark:text-sky-100",
  info: "bg-zinc-200 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};
const CATEGORY: Record<Finding["category"], string> = {
  secret_exposure: "Secret exposure",
  missing_auth: "Missing auth",
  open_data: "Open data",
  unsafe_defaults: "Unsafe defaults",
  fragile_setup: "Fragile setup",
  vulnerable_dependency: "Vulnerable dependency",
  supply_chain: "Supply chain",
};

/** Screenshot URL for an artifact name, or null if the name isn't one the worker writes. */
function artifactUrl(auditId: string, name: string): string | null {
  if (!/^[a-z0-9-]{1,40}\.jpg$/.test(name)) return null;
  return `/api/audits/${encodeURIComponent(auditId)}/artifacts/${name}`;
}

/** Checks that prove a finding by running the app, as opposed to confirming it from the code. */
const RUNTIME_SOURCES = new Set<Finding["source"]>(["probe", "proxy", "vision"]);
type Proof = "runtime" | "code" | "suspicion";
function proofOf(f: Finding): Proof {
  // A planted marker found in the bundle the sandbox built is proof too, though its source is the scanner.
  if (f.confirmed && (RUNTIME_SOURCES.has(f.source) || f.evidence.some((e) => e.kind === "bundle"))) return "runtime";
  return f.confirmed ? "code" : "suspicion";
}
const PROOF_LABEL: Record<Proof, string> = { runtime: "Proven at runtime", code: "Confirmed in the code", suspicion: "Static suspicion" };

const isDep = (f: Finding) => f.source === "dep_audit" && f.category === "vulnerable_dependency";
const isAttempt = (e: ContainmentEntry) => !(e.source === "proxy" && e.verdict === "allowed");

type TabId = "overview" | "findings" | "sandbox" | "browser" | "dependencies" | "activity";
const TAB_IDS: TabId[] = ["overview", "findings", "sandbox", "browser", "dependencies", "activity"];

/**
 * The scorecard: a summary that always shows, then tabs. Everything in it can contain repo- or
 * sandbox-derived text: plain text only. The open tab is kept in the URL hash (#findings) so a
 * link lands on it.
 */
export function ReportView({ report, activity }: { report: Report; activity?: ReactNode }) {
  const findings = useMemo(
    () =>
      [...report.findings].sort(
        (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || Number(b.confirmed) - Number(a.confirmed),
      ),
    [report.findings],
  );
  // Supply-chain findings that look hostile get a banner above everything else.
  const hostile = findings.filter((f) => f.category === "supply_chain" && (f.severity === "critical" || f.severity === "high"));
  const appFindings = useMemo(() => findings.filter((f) => !isDep(f)), [findings]);
  const depFindings = useMemo(() => findings.filter(isDep), [findings]);
  const counts = SEV_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n);
  const attempts = report.containment.filter(isAttempt).length;

  const tabs = useMemo(() => {
    const t: { id: TabId; label: string; count?: number }[] = [{ id: "overview", label: "Overview" }];
    t.push({ id: "findings", label: "Findings", count: appFindings.length });
    t.push({ id: "sandbox", label: "Sandbox", count: attempts || undefined });
    if (report.pages?.length) t.push({ id: "browser", label: "Browser", count: report.pages.length });
    if (depFindings.length) t.push({ id: "dependencies", label: "Dependencies", count: depFindings.length });
    if (activity) t.push({ id: "activity", label: "Activity log" });
    return t;
  }, [appFindings.length, attempts, report.pages, depFindings.length, activity]);

  const [tab, setTabState] = useState<TabId>("overview");
  // The finding to open next (set together with a focusSeq bump; read by the effect below).
  const focusTarget = useRef<string | null>(null);
  // Bumped whenever a finding is opened from outside the Findings tab: remounts it with no filters.
  const [focusSeq, setFocusSeq] = useState(0);

  const depIds = useMemo(() => new Set(depFindings.map((f) => f.id)), [depFindings]);
  const writeHash = (h: string) => {
    try {
      window.history.replaceState(null, "", `#${h}`);
    } catch {
      // ignore (sandboxed iframes)
    }
  };

  // Open the tab named in the URL (#findings, or #finding-<id> for one finding).
  useEffect(() => {
    const read = () => {
      let h = window.location.hash.slice(1);
      try {
        h = decodeURIComponent(h);
      } catch {
        // a malformed escape (#%E0): use it raw; it just won't match anything
      }
      if (h.startsWith("finding-")) {
        const id = h.slice("finding-".length);
        setTabState(depIds.has(id) ? "dependencies" : "findings");
        focusTarget.current = id;
        setFocusSeq((n) => n + 1);
      } else if ((TAB_IDS as string[]).includes(h)) setTabState(h as TabId);
    };
    read();
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, [depIds]);

  const setTab = useCallback((id: TabId) => {
    setTabState(id);
    writeHash(id);
  }, []);

  const openFinding = useCallback(
    (id: string) => {
      setTabState(depIds.has(id) ? "dependencies" : "findings");
      focusTarget.current = id;
      setFocusSeq((n) => n + 1);
      writeHash(`finding-${id}`);
    },
    [depIds],
  );

  // Once the finding's tab is showing (panels are always mounted; the Findings one was just
  // remounted without filters): open it, scroll to it, and move keyboard focus onto it.
  useEffect(() => {
    const id = focusTarget.current;
    focusTarget.current = null;
    if (!id) return;
    const el = document.getElementById(`finding-${id}`);
    if (el instanceof HTMLDetailsElement) {
      el.open = true;
      el.scrollIntoView({ behavior: "smooth", block: "start" });
      el.querySelector("summary")?.focus({ preventScroll: true });
    }
  }, [focusSeq]);

  const current = tabs.some((t) => t.id === tab) ? tab : "overview";
  const content = (id: TabId): ReactNode => {
    switch (id) {
      case "overview":
        return (
          <Overview
            report={report}
            findings={appFindings}
            attempts={attempts}
            onOpenFinding={openFinding}
            onTab={(t) => {
              setTab(t);
              requestAnimationFrame(() => document.getElementById(`tab-${t}`)?.focus());
            }}
          />
        );
      case "findings":
        return <FindingsPanel key={focusSeq} findings={appFindings} auditId={report.auditId} />;
      case "sandbox":
        return <Containment entries={report.containment} controls={report.controls} />;
      case "browser":
        return report.pages?.length ? (
          <div className="flex flex-col gap-6">
            <Replay auditId={report.auditId} pages={report.pages} />
            <Pages pages={report.pages} auditId={report.auditId} />
          </div>
        ) : null;
      case "dependencies":
        return <Dependencies findings={depFindings} auditId={report.auditId} />;
      case "activity":
        return activity ?? null;
    }
  };

  return (
    <section aria-labelledby="report-title" className="flex flex-col gap-6">
      <div className="flex flex-col gap-4 rounded-xl border border-zinc-200 p-5 sm:flex-row sm:items-center dark:border-zinc-800">
        <Score score={report.score} />
        <div className="flex flex-1 flex-col gap-2">
          <h2 id="report-title" className="text-lg font-semibold">
            {report.status === "failed" ? "Partial results" : report.mode === "runtime" ? "Runtime audit" : "Static-only audit"}
          </h2>
          {report.status === "failed" ? (
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              The audit stopped early. What was found before it stopped, and everything the sandbox tried, is below.
            </p>
          ) : report.mode === "static_only" && report.staticOnlyReason ? (
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              The app wasn&apos;t run: {report.staticOnlyReason}. Findings come from the code alone.
            </p>
          ) : (
            <p className="text-sm text-zinc-600 dark:text-zinc-400">
              The app was installed, built and run in the sandbox, then probed over the network.
            </p>
          )}
          <div className="flex flex-wrap gap-1.5">
            {counts.length ? (
              counts.map(([s, n]) => (
                <span key={s} className={`rounded px-2 py-0.5 text-xs font-medium ${SEV_STYLE[s]}`}>
                  {n} {s}
                </span>
              ))
            ) : (
              <span className="text-sm text-emerald-700 dark:text-emerald-400">No findings.</span>
            )}
            {depFindings.length ? (
              <span className="self-center text-xs text-zinc-500">
                incl. {depFindings.length} dependency advisor{depFindings.length === 1 ? "y" : "ies"}
              </span>
            ) : null}
          </div>
        </div>
      </div>

      {hostile.length ? (
        <div role="alert" className="flex flex-col gap-2 rounded-xl border-2 border-red-600 bg-red-50 p-4 dark:bg-red-950/40">
          <h3 className="font-semibold text-red-800 dark:text-red-300">Malicious install-time behaviour</h3>
          <p className="text-sm text-red-900 dark:text-red-200">
            This project, or a package it installs, does something hostile when it is installed. Don&apos;t run{" "}
            <code className="font-mono">npm install</code> on it outside a sandbox
            {hostile.some((f) => f.severity === "critical") ? ", and the score is capped at 40 whatever else the audit found" : ""}.
          </p>
          <ul className="list-disc pl-5 text-sm text-red-900 dark:text-red-200">
            {hostile.map((f) => (
              <li key={f.id}>{f.title}</li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="flex flex-col gap-5">
        <TabBar tabs={tabs} current={current} onSelect={setTab} />
        {/* Every panel stays mounted (hidden when inactive): Ctrl+F, printing and screen readers
            reach the whole report, filters survive a tab switch, and the console plays once. */}
        {tabs.map((t) => (
          <div
            key={t.id}
            role="tabpanel"
            id={`panel-${t.id}`}
            aria-labelledby={`tab-${t.id}`}
            tabIndex={0}
            hidden={t.id !== current}
            className="outline-none print:!block"
          >
            {content(t.id)}
          </div>
        ))}
      </div>
    </section>
  );
}

function TabBar({
  tabs,
  current,
  onSelect,
}: {
  tabs: { id: TabId; label: string; count?: number }[];
  current: TabId;
  onSelect: (id: TabId) => void;
}) {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const go = (i: number) => {
    const next = tabs[(i + tabs.length) % tabs.length]!;
    onSelect(next.id);
    refs.current[next.id]?.focus();
  };
  return (
    <div
      role="tablist"
      aria-label="Report sections"
      className="-mx-4 flex gap-1 overflow-x-auto border-b border-zinc-200 px-4 sm:mx-0 sm:px-0 dark:border-zinc-800"
      onKeyDown={(e) => {
        const i = tabs.findIndex((t) => t.id === current);
        if (e.key === "ArrowRight") go(i + 1);
        else if (e.key === "ArrowLeft") go(i - 1);
        else if (e.key === "Home") go(0);
        else if (e.key === "End") go(tabs.length - 1);
        else return;
        e.preventDefault();
      }}
    >
      {tabs.map((t) => {
        const on = t.id === current;
        return (
          <button
            key={t.id}
            ref={(el) => {
              refs.current[t.id] = el;
            }}
            id={`tab-${t.id}`}
            role="tab"
            type="button"
            aria-selected={on}
            aria-controls={`panel-${t.id}`}
            tabIndex={on ? 0 : -1}
            onClick={() => onSelect(t.id)}
            className={`-mb-px flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-sm whitespace-nowrap ${
              on
                ? "border-zinc-900 font-medium text-zinc-900 dark:border-zinc-100 dark:text-zinc-100"
                : "border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200"
            }`}
          >
            {t.label}
            {t.count !== undefined ? (
              <span className="rounded-full bg-zinc-100 px-1.5 text-xs text-zinc-600 tabular-nums dark:bg-zinc-800 dark:text-zinc-300">
                {t.count}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

function Overview({
  report,
  findings,
  attempts,
  onOpenFinding,
  onTab,
}: {
  report: Report;
  findings: Finding[];
  attempts: number;
  onOpenFinding: (id: string) => void;
  onTab: (id: TabId) => void;
}) {
  const top = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const proven = findings.filter((f) => proofOf(f) === "runtime").length;
  const stats: { label: string; value: number; tab: TabId }[] = [
    { label: "Proven at runtime", value: proven, tab: "findings" },
    { label: "Other findings", value: findings.length - proven, tab: "findings" },
    { label: "Attempts stopped by the sandbox", value: attempts, tab: "sandbox" },
    ...(report.pages?.length ? [{ label: "Pages visited logged out", value: report.pages.length, tab: "browser" as TabId }] : []),
  ];
  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
        {stats.map((s) => (
          <button
            key={s.label}
            type="button"
            onClick={() => onTab(s.tab)}
            className="flex flex-col items-start rounded-lg border border-zinc-200 p-3 text-left hover:border-zinc-400 dark:border-zinc-800 dark:hover:border-zinc-600"
          >
            <span className="text-2xl font-semibold tabular-nums">{s.value}</span>
            <span className="text-xs text-zinc-500">{s.label}</span>
          </button>
        ))}
      </div>

      {top.length ? (
        <div className="flex flex-col gap-2">
          <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">Fix these first</h3>
          <ul className="flex flex-col divide-y divide-zinc-200 rounded-lg border border-zinc-200 dark:divide-zinc-800 dark:border-zinc-800">
            {top.map((f) => (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => onOpenFinding(f.id)}
                  className="flex w-full flex-wrap items-center gap-2 px-3 py-2 text-left text-sm hover:bg-zinc-50 dark:hover:bg-zinc-900"
                >
                  <span className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEV_STYLE[f.severity]}`}>{f.severity}</span>
                  <span className="min-w-0 flex-1 font-medium break-words">{f.title}</span>
                  <span className={`text-xs ${proofOf(f) === "runtime" ? "text-emerald-700 dark:text-emerald-400" : "text-zinc-500"}`}>
                    {PROOF_LABEL[proofOf(f)]}
                  </span>
                  <span aria-hidden className="text-zinc-400">
                    →
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="text-sm text-emerald-700 dark:text-emerald-400">Nothing critical or high was found in the app itself.</p>
      )}

      <AttackConsole report={report} />

      {report.lighthouse ? (
        <div className="flex flex-col gap-2">
          <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">Lighthouse</h3>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {Object.entries(report.lighthouse.scores).map(([k, v]) => (
              <div key={k} className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
                <div className="text-2xl font-semibold tabular-nums">{Math.round(v)}</div>
                <div className="text-xs text-zinc-500">{LH_LABEL[k] ?? k}</div>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

type ProofFilter = "all" | Proof;

function FindingsPanel({ findings, auditId }: { findings: Finding[]; auditId: string }) {
  const [sevs, setSevs] = useState<Set<Severity>>(new Set());
  const [proof, setProof] = useState<ProofFilter>("all");
  const [cat, setCat] = useState<Finding["category"] | "all">("all");
  const [q, setQ] = useState("");
  const [expandAll, setExpandAll] = useState<{ open: boolean; n: number }>({ open: false, n: 0 });

  const sevCounts = SEV_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n);
  const proofCounts = (["runtime", "code", "suspicion"] as Proof[]).map((p) => [p, findings.filter((f) => proofOf(f) === p).length] as const);
  const cats = [...new Set(findings.map((f) => f.category))];
  const needle = q.trim().toLowerCase();
  const shown = findings.filter(
    (f) =>
      (!sevs.size || sevs.has(f.severity)) &&
      (proof === "all" || proofOf(f) === proof) &&
      (cat === "all" || f.category === cat) &&
      (!needle ||
        `${f.title}\n${f.description}\n${f.evidence.map((e) => (e.kind === "code" ? e.file : e.kind === "http" ? e.url : "")).join(" ")}`
          .toLowerCase()
          .includes(needle)),
  );
  const filtered = sevs.size > 0 || proof !== "all" || cat !== "all" || needle !== "";
  const clear = () => {
    setSevs(new Set());
    setProof("all");
    setCat("all");
    setQ("");
  };


  if (!findings.length) return <p className="text-sm text-emerald-700 dark:text-emerald-400">No findings in the app itself.</p>;

  const chip = (on: boolean) =>
    `rounded-full border px-2.5 py-1 text-xs ${
      on
        ? "border-zinc-900 bg-zinc-900 text-white dark:border-zinc-100 dark:bg-zinc-100 dark:text-zinc-900"
        : "border-zinc-300 text-zinc-700 hover:border-zinc-500 dark:border-zinc-700 dark:text-zinc-300"
    }`;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-3 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by severity">
          <span className="w-16 text-xs text-zinc-500">Severity</span>
          {sevCounts.map(([s, n]) => {
            const on = sevs.has(s);
            return (
              <button
                key={s}
                type="button"
                aria-pressed={on}
                onClick={() => {
                  const next = new Set(sevs);
                  if (on) next.delete(s);
                  else next.add(s);
                  setSevs(next);
                }}
                className={chip(on)}
              >
                {s} <span className="tabular-nums opacity-70">{n}</span>
              </button>
            );
          })}
        </div>
        <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by proof">
          <span className="w-16 text-xs text-zinc-500">Proof</span>
          <button type="button" aria-pressed={proof === "all"} onClick={() => setProof("all")} className={chip(proof === "all")}>
            All
          </button>
          {proofCounts.map(([p, n]) =>
            n ? (
              <button key={p} type="button" aria-pressed={proof === p} onClick={() => setProof(proof === p ? "all" : p)} className={chip(proof === p)}>
                {PROOF_LABEL[p]} <span className="tabular-nums opacity-70">{n}</span>
              </button>
            ) : null,
          )}
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <label className="flex items-center gap-2 text-xs text-zinc-500">
            <span className="w-16">Category</span>
            <select
              value={cat}
              onChange={(e) => setCat(e.target.value as Finding["category"] | "all")}
              className="h-8 rounded-md border border-zinc-300 bg-white px-2 text-sm text-zinc-800 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-200"
            >
              <option value="all">All categories</option>
              {cats.map((c) => (
                <option key={c} value={c}>
                  {CATEGORY[c]}
                </option>
              ))}
            </select>
          </label>
          <input
            type="search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search title, description, file or route"
            aria-label="Search findings"
            className="h-8 min-w-0 flex-1 rounded-md border border-zinc-300 bg-white px-2 text-sm dark:border-zinc-700 dark:bg-zinc-950"
          />
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-zinc-500">
        <span>
          <span aria-live="polite">
            {shown.length === findings.length
              ? `${findings.length} finding${findings.length === 1 ? "" : "s"}`
              : `${shown.length} of ${findings.length} findings`}
          </span>
          {filtered ? (
            <>
              {" · "}
              <button type="button" onClick={clear} className="underline underline-offset-2">
                Clear filters
              </button>
            </>
          ) : null}
        </span>
        <span className="flex gap-3">
          <button type="button" onClick={() => setExpandAll((s) => ({ open: true, n: s.n + 1 }))} className="underline underline-offset-2">
            Expand all
          </button>
          <button type="button" onClick={() => setExpandAll((s) => ({ open: false, n: s.n + 1 }))} className="underline underline-offset-2">
            Collapse all
          </button>
        </span>
      </div>

      <div className="flex flex-col gap-2">
        {shown.map((f) => (
          <FindingCard key={`${f.id}-${expandAll.n}`} f={f} auditId={auditId} defaultOpen={expandAll.open} />
        ))}
        {!shown.length ? <p className="text-sm text-zinc-600 dark:text-zinc-400">No findings match these filters.</p> : null}
      </div>
    </div>
  );
}

const LH_LABEL: Record<string, string> = {
  performance: "Performance",
  accessibility: "Accessibility",
  bestPractices: "Best practices",
  seo: "SEO",
};

function Score({ score }: { score: number }) {
  const s = Math.round(score);
  const color = s >= 80 ? "text-emerald-600" : s >= 50 ? "text-amber-600" : "text-red-600";
  return (
    <div className="flex flex-col items-center justify-center px-4">
      <span className={`text-5xl font-bold tabular-nums ${color}`}>
        {s}
        <span className="sr-only"> out of 100</span>
      </span>
      <span aria-hidden className="text-xs text-zinc-500">
        / 100
      </span>
    </div>
  );
}

function Dependencies({ findings, auditId }: { findings: Finding[]; auditId: string }) {
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-zinc-600 dark:text-zinc-400">
        {findings.length} package{findings.length === 1 ? "" : "s"} with known vulnerabilities, from OSV.dev advisories for the installed
        versions. They count at half weight, and at most 30 points together.
      </p>
      <div className="flex flex-col gap-2">
        {findings.map((f) => (
          <FindingCard key={f.id} f={f} auditId={auditId} />
        ))}
      </div>
    </div>
  );
}

function FindingCard({ f, auditId, defaultOpen = false }: { f: Finding; auditId: string; defaultOpen?: boolean }) {
  const proof = proofOf(f);
  const runtime = proof === "runtime";
  return (
    <details id={`finding-${f.id}`} open={defaultOpen} className="group scroll-mt-4 rounded-lg border border-zinc-200 dark:border-zinc-800">
      <summary className="flex cursor-pointer list-none flex-wrap items-center gap-x-2 gap-y-1 p-3 [&::-webkit-details-marker]:hidden">
        <span aria-hidden className="inline-block w-3 text-xs text-zinc-400 transition-transform group-open:rotate-90">
          ▶
        </span>
        <span className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEV_STYLE[f.severity]}`}>{f.severity}</span>
        <h4 className="min-w-0 flex-1 font-medium break-words">{f.title}</h4>
        <span className="flex flex-wrap gap-2 text-xs text-zinc-500">
          <span>{CATEGORY[f.category]}</span>
          <span aria-hidden>·</span>
          <span className={f.confirmed ? "text-emerald-700 dark:text-emerald-400" : ""}>{PROOF_LABEL[proof]}</span>
          {f.corroboratedBy?.length ? (
            <>
              <span aria-hidden>·</span>
              <span className="text-violet-700 dark:text-violet-400">
                {runtime ? "Suspected by code review, then proven" : "Also flagged by code review"}
              </span>
            </>
          ) : null}
        </span>
      </summary>
      <div className="flex flex-col gap-3 border-t border-zinc-200 p-4 dark:border-zinc-800">
        {f.corroboratedBy?.length ? (
          <p className="rounded-md bg-violet-50 px-3 py-2 text-xs text-violet-900 dark:bg-violet-950/40 dark:text-violet-200">
            <span className="font-medium">The LLM code review reported this independently</span>
            {runtime ? ", before the sandbox proved it" : ""}:{" "}
            {f.corroboratedBy.map((c) => `“${c.title}”${c.file ? ` (${c.file}${c.line ? `:${c.line}` : ""})` : ""}`).join(", ")}.
          </p>
        ) : null}
        <p className="text-sm leading-6 text-zinc-700 dark:text-zinc-300">{f.description}</p>
        <div className="flex flex-col gap-2">
          {f.evidence.map((e, i) => (
            <EvidenceBlock key={i} e={e} auditId={auditId} />
          ))}
        </div>
        {f.fix ? (
          <p className="text-sm text-zinc-700 dark:text-zinc-300">
            <span className="font-medium">Fix: </span>
            {f.fix}
          </p>
        ) : null}
      </div>
    </details>
  );
}

function EvidenceBlock({ e, auditId }: { e: Evidence; auditId: string }) {
  const box = "rounded-md bg-zinc-50 p-3 font-mono text-xs leading-5 dark:bg-zinc-900";
  switch (e.kind) {
    case "code":
      return (
        <div className={box}>
          <div className="mb-1 text-zinc-500">
            {e.file}
            {e.line ? `:${e.line}` : ""}
          </div>
          <pre className="whitespace-pre-wrap break-all">{e.snippet}</pre>
        </div>
      );
    case "http":
      return (
        <div className={box}>
          <div className="mb-1">
            <span className="text-zinc-500">{e.method}</span> {e.url} <span className="text-zinc-500">→</span>{" "}
            <span className={e.status < 400 ? "text-red-700 dark:text-red-400" : ""}>{e.status}</span>
          </div>
          {e.bodyExcerpt ? <pre className="whitespace-pre-wrap break-all text-zinc-600 dark:text-zinc-400">{e.bodyExcerpt}</pre> : null}
        </div>
      );
    case "bundle":
      return (
        <div className={box}>
          <span className="text-zinc-500">client bundle</span> {e.asset}: <span className="break-all">{e.match}</span>
        </div>
      );
    case "network":
      return (
        <div className={box}>
          <div className="mb-1 text-zinc-500">
            {e.control === "firewall" ? "firewall drop" : "proxy blocked"}
            {e.stage ? ` · ${e.stage}` : ""} · <LocalTime iso={e.at} />
          </div>
          <span className="break-all">{e.target}</span>
          {e.detail ? <div className="mt-1 text-zinc-600 dark:text-zinc-400">{e.detail}</div> : null}
        </div>
      );
    case "screenshot": {
      const src = artifactUrl(auditId, e.path);
      return (
        <div className={box}>
          {src ? (
            <a href={src} target="_blank" rel="noopener noreferrer" className="block">
              {/* eslint-disable-next-line @next/next/no-img-element -- evidence served by our API, not an optimizable asset */}
              <img src={src} alt="Screenshot of the page, logged out" loading="lazy" className="w-full max-w-xl rounded border border-zinc-200 dark:border-zinc-800" />
            </a>
          ) : (
            <span>
              <span className="text-zinc-500">screenshot</span> {e.path}
            </span>
          )}
          {e.verdict ? <div className="mt-2 font-sans text-zinc-700 dark:text-zinc-300">{e.verdict}</div> : null}
        </div>
      );
    }
    default: {
      // Compile-time exhaustiveness; at runtime an unknown kind (a newer report) renders nothing.
      const unhandled: never = e;
      void unhandled;
      return null;
    }
  }
}

/** What the browser saw, logged out: one card per page it visited. */
function Pages({ pages, auditId }: { pages: PageVisit[]; auditId: string }) {
  return (
    <div className="flex flex-col gap-3">
      <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">Pages visited (logged out)</h3>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {pages.map((p) => {
          const src = p.screenshot ? artifactUrl(auditId, p.screenshot) : null;
          // Same rule as the worker's stayed(): the query and a trailing slash don't count.
          const landed = p.finalPath?.split("?")[0];
          const moved = p.finalPath === null || (landed !== p.path && landed !== `${p.path}/`);
          return (
            <figure key={p.path} className="flex min-w-0 flex-col gap-2 rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
              {src ? (
                <a href={src} target="_blank" rel="noopener noreferrer">
                  {/* eslint-disable-next-line @next/next/no-img-element -- evidence served by our API */}
                  <img src={src} alt={`Screenshot of ${p.path}`} loading="lazy" className="aspect-[8/5] w-full rounded border border-zinc-200 object-cover object-top dark:border-zinc-800" />
                </a>
              ) : null}
              <figcaption className="flex min-w-0 flex-col gap-0.5 text-xs">
                <div className="flex items-center gap-2 font-mono">
                  <span className="truncate">{p.path}</span>
                  <span className={p.status >= 200 && p.status < 300 ? "text-zinc-700 dark:text-zinc-300" : "text-zinc-500"}>
                    {p.status || "no response"}
                  </span>
                </div>
                {moved ? <div className="truncate font-mono text-zinc-500">→ {p.finalPath ?? "left the app"}</div> : null}
                {p.title ? <div className="truncate text-zinc-600 dark:text-zinc-400">{p.title}</div> : null}
                {p.verdict ? <div className="text-zinc-700 dark:text-zinc-300">{p.verdict}</div> : null}
              </figcaption>
            </figure>
          );
        })}
      </div>
    </div>
  );
}

function Containment({ entries, controls }: { entries: ContainmentEntry[]; controls?: SandboxControls }) {
  const flagged: ContainmentEntry[] = [];
  const allowed: Extract<ContainmentEntry, { source: "proxy" }>[] = [];
  let exfil = 0;
  let blocked = 0;
  let fw = 0;
  let limitsHit = 0;
  for (const e of entries) {
    if (e.source === "proxy" && e.verdict === "allowed") {
      allowed.push(e);
      continue;
    }
    flagged.push(e);
    if (e.source === "proxy") {
      if (e.verdict === "exfil") exfil++;
      else blocked++;
    }
    else if (e.source === "firewall") fw++;
    else limitsHit++;
  }
  const allowedRequests = allowed.reduce((n, e) => n + (e.repeat ?? 1), 0);
  // Past 20 identical requests the proxy logs only every 100th, so big counts are lower bounds.
  const approx = allowed.some((e) => (e.repeat ?? 1) > 20);

  return (
    <div className="flex flex-col gap-3">
      <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">Containment</h3>
      {controls ? <ControlsReceipt c={controls} /> : null}
      {entries.length === 0 ? (
        <p className="text-sm text-zinc-600 dark:text-zinc-400">The sandbox made no network requests and hit no limits.</p>
      ) : (
        <>
          <div className="flex flex-wrap gap-1.5 text-xs">
            {exfil ? <Chip cls="bg-red-600 text-white">{exfil} exfiltration attempt{exfil === 1 ? "" : "s"} blocked</Chip> : null}
            {blocked ? <Chip cls="bg-orange-100 text-orange-900 dark:bg-orange-950 dark:text-orange-200">{blocked} request{blocked === 1 ? "" : "s"} blocked by the proxy</Chip> : null}
            {fw ? <Chip cls="bg-orange-100 text-orange-900 dark:bg-orange-950 dark:text-orange-200">{fw} packet{fw === 1 ? "" : "s"} dropped by the firewall</Chip> : null}
            {limitsHit ? <Chip cls="bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200">{limitsHit} limit{limitsHit === 1 ? "" : "s"} hit</Chip> : null}
            {allowedRequests ? (
              <Chip cls="bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                {approx ? "at least " : ""}
                {allowedRequests} allowed request{allowedRequests === 1 ? "" : "s"} to {new Set(allowed.map((e) => e.host)).size} host(s)
              </Chip>
            ) : null}
          </div>

          {flagged.length ? (
            <div className="overflow-x-auto rounded-lg border border-zinc-200 dark:border-zinc-800">
              <table className="w-full text-left text-xs">
                <thead className="bg-zinc-50 text-zinc-500 dark:bg-zinc-900">
                  <tr>
                    <th className="px-3 py-2 font-medium">Time</th>
                    <th className="px-3 py-2 font-medium">Stage</th>
                    <th className="px-3 py-2 font-medium">What the code tried</th>
                    <th className="px-3 py-2 font-medium">Stopped by</th>
                    <th className="px-3 py-2 font-medium">Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {flagged.map((e, i) => {
                    const a = describeAttempt(e);
                    if (!a) return null;
                    return (
                      <tr key={i} className="border-t border-zinc-200 align-top dark:border-zinc-800">
                        <td className="px-3 py-1.5 whitespace-nowrap text-zinc-500 font-mono"><LocalTime iso={e.at} /></td>
                        <td className="px-3 py-1.5 font-mono">{e.stage ?? "-"}</td>
                        <td className={`px-3 py-1.5 ${a.tone === "red" ? "font-semibold text-red-700 dark:text-red-400" : ""}`}>{a.attempt}</td>
                        <td className="px-3 py-1.5 whitespace-nowrap text-emerald-700 dark:text-emerald-400">✓ {a.control}</td>
                        <td className="px-3 py-1.5 font-mono break-all text-zinc-600 dark:text-zinc-400">{a.evidence}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-sm text-zinc-600 dark:text-zinc-400">Nothing was blocked: every request went to an allowed host.</p>
          )}

          {allowed.length ? (
            <details className="text-xs">
              <summary className="cursor-pointer text-zinc-600 dark:text-zinc-400">Allowed traffic by stage and host</summary>
              <ul className="mt-2 flex flex-col gap-1 font-mono">
                {allowed.map((e, i) => (
                  <li key={i}>
                    <span className="text-zinc-500">{e.stage ?? "-"}</span> {e.method ?? ""} {e.host}
                    {e.keyVar ? <span className="text-emerald-700 dark:text-emerald-400"> (test key {e.keyVar} swapped in)</span> : null}
                    <span className="text-zinc-500">
                      {" "}
                      ×{e.repeat ?? 1}
                      {(e.repeat ?? 1) > 20 ? "+" : ""}
                    </span>
                  </li>
                ))}
              </ul>
            </details>
          ) : null}
        </>
      )}
    </div>
  );
}

function Chip({ cls, children }: { cls: string; children: React.ReactNode }) {
  return <span className={`rounded px-2 py-0.5 font-medium ${cls}`}>{children}</span>;
}

function ControlsReceipt({ c }: { c: SandboxControls }) {
  const gb = (b: number) => `${(b / 1024 ** 3).toFixed(b % 1024 ** 3 ? 1 : 0)} GB`;
  const rootUser = /^(root|0)(:|$)/.test(c.user);
  const rows: [boolean, string, string][] = [
    [c.runtime === "runsc", "gVisor user-space kernel", `runtime ${c.runtime}`],
    [!rootUser, "Non-root user", `user ${c.user}`],
    [!c.privileged && c.capDrop.includes("ALL") && c.capAdd.length === 0, "No Linux capabilities", c.privileged ? "privileged" : `drop ${c.capDrop.join(",") || "none"}${c.capAdd.length ? `, add ${c.capAdd.join(",")}` : ""}`],
    [c.noNewPrivileges, "No privilege escalation", c.noNewPrivileges ? "no-new-privileges" : "not set"],
    [c.pidsLimit !== null, "Process cap", c.pidsLimit !== null ? `${c.pidsLimit} pids` : "none"],
    [c.memoryBytes > 0, "Memory cap", c.memoryBytes ? gb(c.memoryBytes) : "none"],
    [c.cpus > 0, "CPU cap", c.cpus ? `${c.cpus} CPUs` : "none"],
    [c.egressProxy, "All web traffic via the egress proxy", `network ${c.network}`],
    [!c.mounts.some((m) => /docker\.sock/.test(m.destination)), "No Docker socket mounted", c.mounts.map((m) => `${m.destination} (${m.rw ? "rw" : "ro"})`).join(", ") || "no mounts"],
  ];
  const planted = `${c.planted.canaries} canary secret${c.planted.canaries === 1 ? "" : "s"}${c.planted.placeholders ? ` and ${c.planted.placeholders} test-key placeholder${c.planted.placeholders === 1 ? "" : "s"} (swapped for the real key by the proxy, outside the sandbox)` : ""}`;
  return (
    <div className="rounded-lg border border-zinc-200 p-3 dark:border-zinc-800">
      <p className="mb-2 text-xs text-zinc-500">
        Isolation the app container actually ran under, read back from the sandbox host&apos;s Docker daemon. Outside the container, VM 2&apos;s firewall drops every packet except those to the proxy on VM 1.
      </p>
      <ul className="grid gap-x-4 gap-y-1 text-xs sm:grid-cols-2">
        {rows.map(([ok, label, value]) => (
          <li key={label} className="flex gap-2">
            <span aria-hidden className={ok ? "text-emerald-600" : "text-red-600"}>{ok ? "✓" : "✗"}</span>
            <span>
              <span className="font-medium">{label}</span> <span className="font-mono text-zinc-500 break-all">{value}</span>
              {ok ? null : <span className="sr-only"> (not applied)</span>}
            </span>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-xs text-zinc-500">
        Env: {planted}. By design, no real secret is ever put in a sandbox.
      </p>
    </div>
  );
}
