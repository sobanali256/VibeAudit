import Link from "next/link";
import { connection } from "next/server";
import { Suspense } from "react";
import { loadAuditView } from "@/lib/audits";
import { DEMO, DEMO_MESSAGE } from "@/lib/demo";
import { DEMO_REPOS, FEATURED } from "./featured";
import { RepoUrlForm } from "./repo-url-form";

const STEPS = [
  ["Plan", "Reads package.json inside the sandbox and works out how to install, build and start the app."],
  ["You approve", "Shows the exact commands, the fake env it will plant and the repo's install hooks. Nothing runs until you say so."],
  ["Run and attack", "Installs, builds and starts the app under gVisor, then probes it like a stranger would: no login, forged headers, other users' ids."],
  ["Prove it", "Every finding carries its evidence: the code line, the HTTP response or a screenshot a vision model checked."],
] as const;

const CONTROLS = [
  ["Two machines", "The VM that runs repo code holds no secrets. Keys, the database and the LLM live on the other one, which never unpacks a repo."],
  ["gVisor sandbox", "Every step runs in a fresh container with a user-space kernel, no capabilities, a non-root user and CPU, memory and process caps."],
  ["One way out", "A firewall drops every packet except those to an egress proxy, which allows only the hosts each stage needs."],
  ["Canaries, not keys", "The app gets fake secrets. If one is sent out in plain, URL-encoded or base64 form, the proxy blocks it, even on an allowed host."],
  ["Destroyed after", "Containers, network and workspace are removed after every audit, pass or fail. A janitor sweeps anything left."],
] as const;

export default function Home() {
  return (
    <main className="mx-auto flex w-full max-w-4xl flex-1 flex-col gap-14 px-4 py-14 sm:py-20">
      <section className="flex flex-col gap-6">
        <div className="flex flex-col gap-3">
          <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">Don&apos;t read the vibe-coded app. Run it.</h1>
          <p className="max-w-2xl text-lg leading-8 text-zinc-600 dark:text-zinc-400">
            VibeAudit installs, builds and starts an AI-generated Node app (Next.js, Vite or Express) inside a locked-down
            sandbox, attacks it, and hands back a scorecard where every finding comes with proof. Hostile code is
            welcome: it never sees a real secret, and everything it tries is stopped and logged.
          </p>
        </div>
        {DEMO ? (
          <div role="status" className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-950 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-100">
            {DEMO_MESSAGE}{" "}
            <a href="https://github.com/sobanali256/VibeAudit" className="font-medium underline underline-offset-2">
              Watch the demo video or deploy your own
            </a>
            .
          </div>
        ) : (
          <>
            <RepoUrlForm demos={DEMO_REPOS} />
            <p className="text-xs text-zinc-500">
              Public repos only. An audit takes 3 to 6 minutes and one runs at a time, so you may queue briefly.
            </p>
          </>
        )}
      </section>

      <section aria-labelledby="featured-title" className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <h2 id="featured-title" className="text-lg font-semibold">Finished reports</h2>
          <p className="text-sm text-zinc-600 dark:text-zinc-400">Full results from the live sandbox, no waiting.</p>
        </div>
        <Suspense fallback={<FeaturedSkeleton />}>
          <FeaturedReports />
        </Suspense>
      </section>

      <section aria-labelledby="how-title" className="flex flex-col gap-4">
        <h2 id="how-title" className="text-lg font-semibold">How an audit works</h2>
        <ol className="grid gap-3 sm:grid-cols-2">
          {STEPS.map(([title, body], i) => (
            <li key={title} className="flex gap-3 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-zinc-900 text-xs font-semibold text-white dark:bg-zinc-100 dark:text-zinc-900">
                {i + 1}
              </span>
              <div className="flex flex-col gap-1">
                <h3 className="text-sm font-semibold">{title}</h3>
                <p className="text-sm text-zinc-600 dark:text-zinc-400">{body}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <section aria-labelledby="contain-title" className="flex flex-col gap-4">
        <div className="flex flex-col gap-1">
          <h2 id="contain-title" className="text-lg font-semibold">Blast radius: zero</h2>
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            Each report ends with a containment log: everything the code tried and the control that stopped it.
          </p>
        </div>
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {CONTROLS.map(([title, body]) => (
            <li key={title} className="flex flex-col gap-1 rounded-lg border border-zinc-200 p-4 dark:border-zinc-800">
              <h3 className="text-sm font-semibold">
                <span aria-hidden className="text-emerald-600">✓</span> {title}
              </h3>
              <p className="text-sm text-zinc-600 dark:text-zinc-400">{body}</p>
            </li>
          ))}
        </ul>
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          Built on Vultr Cloud Compute (two VMs on a private VPC) and Vultr Serverless Inference for code review and
          screenshot checks.{" "}
          <a href="https://github.com/sobanali256/VibeAudit" className="underline underline-offset-2">
            Source and architecture on GitHub
          </a>
          .
        </p>
      </section>
    </main>
  );
}

async function FeaturedReports() {
  await connection();
  const views = await Promise.all(FEATURED.map((f) => loadAuditView(f.id, () => false).catch(() => null)));
  const cards = FEATURED.flatMap((f, i) => {
    const v = views[i];
    return v?.status === "completed" && v.report ? [{ f, r: v.report }] : [];
  });
  if (!cards.length) return <p className="text-sm text-zinc-600 dark:text-zinc-400">No finished reports to show yet.</p>;
  return (
    <ul className="grid gap-3 sm:grid-cols-2">
      {cards.map(({ f, r }) => {
        const s = Math.round(r.score);
        const color = s >= 80 ? "text-emerald-600" : s >= 50 ? "text-amber-600" : "text-red-600";
        const critical = r.findings.filter((x) => x.severity === "critical").length;
        const proven = r.findings.filter((x) => x.confirmed).length;
        const stopped = r.containment.filter((e) => !(e.source === "proxy" && e.verdict === "allowed")).length;
        return (
          <li key={f.id}>
            <Link
              href={`/audit/${f.id}`}
              className="flex h-full gap-4 rounded-lg border border-zinc-200 p-4 hover:border-zinc-900 dark:border-zinc-800 dark:hover:border-zinc-100"
            >
              <div className="flex flex-col items-center">
                <span className={`text-3xl font-bold tabular-nums ${color}`}>
                  {s}
                  <span className="sr-only"> out of 100</span>
                </span>
                <span aria-hidden className="text-xs text-zinc-500">/ 100</span>
              </div>
              <div className="flex min-w-0 flex-col gap-1">
                <span className="truncate font-mono text-sm font-medium">{f.repo}</span>
                <span className="text-sm text-zinc-600 dark:text-zinc-400">{f.blurb}</span>
                <span className="text-xs text-zinc-500">
                  {r.findings.length} finding{r.findings.length === 1 ? "" : "s"}
                  {critical ? ` · ${critical} critical` : ""}
                  {proven ? ` · ${proven} proven at runtime` : ""}
                  {stopped ? ` · ${stopped} attempt${stopped === 1 ? "" : "s"} contained` : ""}
                </span>
              </div>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}

function FeaturedSkeleton() {
  return (
    <div className="grid animate-pulse gap-3 sm:grid-cols-2" aria-busy="true">
      {FEATURED.map((f) => (
        <div key={f.id} className="h-28 rounded-lg bg-zinc-200 dark:bg-zinc-800" />
      ))}
    </div>
  );
}
