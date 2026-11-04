import type { ContainmentEntry, Evidence, Finding, Report, Severity } from "@vibeaudit/shared";
import { LocalTime } from "@/components/local-time";

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
};

/** The scorecard. Everything in it can contain repo- or sandbox-derived text: plain text only. */
export function ReportView({ report }: { report: Report }) {
  const findings = [...report.findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) || Number(b.confirmed) - Number(a.confirmed),
  );
  const counts = SEV_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n);

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
          </div>
        </div>
      </div>

      {findings.length ? (
        <div className="flex flex-col gap-3">
          <h3 className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">Findings</h3>
          {findings.map((f) => (
            <FindingCard key={f.id} f={f} />
          ))}
        </div>
      ) : null}

      <Containment entries={report.containment} />

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
    </section>
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
    <div className="flex flex-col items-center justify-center px-4" aria-label={`Score ${s} out of 100`}>
      <span className={`text-5xl font-bold tabular-nums ${color}`}>{s}</span>
      <span className="text-xs text-zinc-500">/ 100</span>
    </div>
  );
}

function FindingCard({ f }: { f: Finding }) {
  return (
    <article className="flex flex-col gap-3 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
      <header className="flex flex-wrap items-center gap-2">
        <span className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEV_STYLE[f.severity]}`}>{f.severity}</span>
        <h4 className="font-medium">{f.title}</h4>
      </header>
      <div className="flex flex-wrap gap-2 text-xs text-zinc-500">
        <span>{CATEGORY[f.category]}</span>
        <span aria-hidden>·</span>
        <span className={f.confirmed ? "text-emerald-700 dark:text-emerald-400" : ""}>
          {f.confirmed ? "Proven at runtime" : "Static suspicion"}
        </span>
      </div>
      <p className="text-sm leading-6 text-zinc-700 dark:text-zinc-300">{f.description}</p>
      <div className="flex flex-col gap-2">
        {f.evidence.map((e, i) => (
          <EvidenceBlock key={i} e={e} />
        ))}
      </div>
      {f.fix ? (
        <p className="text-sm text-zinc-700 dark:text-zinc-300">
          <span className="font-medium">Fix: </span>
          {f.fix}
        </p>
      ) : null}
    </article>
  );
}

function EvidenceBlock({ e }: { e: Evidence }) {
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
    case "screenshot":
      return (
        <div className={box}>
          <span className="text-zinc-500">screenshot</span> {e.path}
          {e.verdict ? <div className="mt-1 font-sans text-zinc-700 dark:text-zinc-300">{e.verdict}</div> : null}
        </div>
      );
  }
}

function Containment({ entries }: { entries: ContainmentEntry[] }) {
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
                    <th className="px-3 py-2 font-medium">Control</th>
                    <th className="px-3 py-2 font-medium">Target</th>
                    <th className="px-3 py-2 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {flagged.map((e, i) => (
                    <tr key={i} className="border-t border-zinc-200 align-top dark:border-zinc-800">
                      <td className="px-3 py-1.5 whitespace-nowrap text-zinc-500"><LocalTime iso={e.at} /></td>
                      <td className="px-3 py-1.5">{e.stage ?? "-"}</td>
                      <td className={`px-3 py-1.5 whitespace-nowrap ${e.source === "proxy" && e.verdict === "exfil" ? "font-semibold text-red-700 dark:text-red-400" : ""}`}>
                        {eventLabel(e)}
                      </td>
                      <td className="px-3 py-1.5 break-all">{target(e)}</td>
                      <td className="px-3 py-1.5 break-all">{detail(e)}</td>
                    </tr>
                  ))}
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

function eventLabel(e: ContainmentEntry): string {
  if (e.source === "proxy") return e.verdict === "exfil" ? "exfil blocked" : `proxy ${e.verdict}`;
  if (e.source === "firewall") return `firewall drop (${e.direction})`;
  return `limit: ${e.limit}`;
}
function target(e: ContainmentEntry): string {
  if (e.source === "proxy") return `${e.method ?? ""} ${e.host ?? ""}${e.path ?? ""}`.trim();
  if (e.source === "firewall") return `${e.proto} ${e.dst}${e.dport ? `:${e.dport}` : ""}`;
  return "";
}
function detail(e: ContainmentEntry): string {
  if (e.source === "proxy") return [e.reason, e.keyVar ? `key ${e.keyVar}` : null, e.repeat ? `×${e.repeat}` : null].filter(Boolean).join(" · ");
  if (e.source === "limit") return e.detail;
  return "";
}
