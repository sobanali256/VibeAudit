"use client";

import type { ApprovalRequest } from "@vibeaudit/shared";
import { useEffect, useState } from "react";

type Decision = "approve" | "static_only" | "cancel";

/**
 * The human-approval step: show exactly what will run, then let the owner run it, fall back
 * to a static-only audit, or cancel. Commands and script bodies come from the repo
 * (untrusted) and are rendered as plain text.
 */
export function ApprovalPanel({ auditId, request }: { auditId: string; request: ApprovalRequest }) {
  const { plan, env, installScripts } = request;
  const keyVars = env.filter((e) => e.provide === "placeholder").map((e) => e.name);
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [ignoreScripts, setIgnoreScripts] = useState(installScripts.length > 0);
  const [busy, setBusy] = useState<Decision | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState<Decision | null>(null);
  const remaining = useCountdown(request.expiresAt);

  async function submit(decision: Decision) {
    setBusy(decision);
    setError(null);
    try {
      const res = await fetch(`/api/audits/${auditId}/approval`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          requestId: request.requestId,
          decision,
          ...(decision === "approve" ? { ignoreScripts, testKeys: keys } : {}),
        }),
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { error?: string } | null;
        setError(body?.error ?? `Request failed (${res.status})`);
        return;
      }
      setKeys({}); // don't keep keys in memory longer than needed; the stream moves us on
      setSent(decision);
    } catch {
      setError("Network error. Try again.");
    } finally {
      setBusy(null);
    }
  }

  const expired = remaining <= 0;
  const locked = !!busy || !!sent || expired;
  return (
    <section
      aria-labelledby="approval-title"
      className="flex flex-col gap-5 rounded-xl border border-amber-300 bg-amber-50/60 p-5 dark:border-amber-900 dark:bg-amber-950/20"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="approval-title" className="text-lg font-semibold">
          Approve the run plan
        </h2>
        <span className={`text-sm tabular-nums ${remaining < 120 ? "text-red-700 dark:text-red-400" : "text-zinc-600 dark:text-zinc-400"}`}>
          {expired ? "expired" : `expires in ${fmt(remaining)}`}
        </span>
      </div>
      <p className="text-sm text-zinc-700 dark:text-zinc-300">
        Nothing from this repo has run yet. If you approve, these commands run inside a gVisor sandbox with no secrets
        and egress limited to package registries (and the API hosts of any test keys you add below).
      </p>

      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-sm">
        <dt className="text-zinc-500">Framework</dt>
        <dd>
          {plan.framework} · {plan.packageManager}
          {plan.port ? ` · port ${plan.port}` : ""}
        </dd>
        <Cmd label="Install" cmd={plan.installCommand + (ignoreScripts ? " --ignore-scripts" : "")} />
        <Cmd label="Build" cmd={plan.buildCommand} />
        <Cmd label="Start" cmd={plan.startCommand} />
      </dl>

      {installScripts.length ? (
        <div className="flex flex-col gap-2">
          <h3 className="text-sm font-semibold">Install scripts found</h3>
          <ul className="flex flex-col gap-1">
            {installScripts.map((s, i) => (
              <li key={i} className="rounded bg-white/70 px-2 py-1 font-mono text-xs break-all dark:bg-zinc-900">
                <span className="text-zinc-500">{s.pkg}</span> {s.script}
              </li>
            ))}
          </ul>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={ignoreScripts} onChange={(e) => setIgnoreScripts(e.target.checked)} />
            Install with scripts disabled (<span className="font-mono">--ignore-scripts</span>)
          </label>
        </div>
      ) : null}

      {env.length ? (
        <div className="flex flex-col gap-2">
          <h3 className="text-sm font-semibold">Environment the app reads</h3>
          <ul className="flex flex-col gap-1.5 text-sm">
            {env.map((e) => (
              <li key={e.name} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span className="font-mono text-xs">{e.name}</span>
                <span className="text-xs text-zinc-500">{ENV_LABEL[e.provide]}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {keyVars.length ? (
        <fieldset className="flex flex-col gap-3">
          <legend className="text-sm font-semibold">Test keys (optional)</legend>
          <p className="text-xs text-zinc-600 dark:text-zinc-400">
            Use a low-limit test key. The app only ever sees a placeholder; the proxy swaps the real key in on requests to
            that provider&apos;s API host. Keys are deleted when the audit ends.
          </p>
          {keyVars.map((name) => (
            <label key={name} className="flex flex-col gap-1 text-sm">
              <span className="font-mono text-xs">{name}</span>
              <input
                type="password"
                // A test key isn't a login: keep browsers and password managers from saving it.
                autoComplete="new-password"
                data-1p-ignore
                data-lpignore="true"
                data-bwignore
                data-form-type="other"
                spellCheck={false}
                value={keys[name] ?? ""}
                onChange={(e) => setKeys((k) => ({ ...k, [name]: e.target.value }))}
                placeholder="leave blank to skip"
                className="h-9 rounded-md border border-zinc-300 bg-white px-2 font-mono text-xs outline-none focus:border-zinc-900 dark:border-zinc-700 dark:bg-zinc-950 dark:focus:border-zinc-100"
              />
            </label>
          ))}
        </fieldset>
      ) : null}

      {error ? (
        <p role="alert" className="text-sm text-red-700 dark:text-red-400">
          {error}
        </p>
      ) : null}

      {sent ? (
        <p role="status" className="text-sm text-zinc-700 dark:text-zinc-300">
          Decision recorded. {sent === "cancel" ? "Cancelling…" : "Handing over to the sandbox…"}
        </p>
      ) : null}

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={locked}
          onClick={() => submit("approve")}
          className="h-10 rounded-md bg-zinc-900 px-4 text-sm font-medium text-white disabled:opacity-40 dark:bg-zinc-100 dark:text-zinc-900"
        >
          {busy === "approve" ? "Starting…" : "Approve and run"}
        </button>
        <button
          type="button"
          disabled={locked}
          onClick={() => submit("static_only")}
          className="h-10 rounded-md border border-zinc-300 px-4 text-sm font-medium disabled:opacity-40 dark:border-zinc-700"
        >
          Static audit only
        </button>
        <button
          type="button"
          disabled={locked}
          onClick={() => submit("cancel")}
          className="h-10 rounded-md px-4 text-sm font-medium text-zinc-600 hover:text-red-700 disabled:opacity-40 dark:text-zinc-400"
        >
          Cancel
        </button>
      </div>
    </section>
  );
}

const ENV_LABEL = {
  canary: "gets a canary value (any leak during install is flagged)",
  placeholder: "test key slot",
  empty: "left empty",
} as const;

function Cmd({ label, cmd }: { label: string; cmd: string | null }) {
  return (
    <>
      <dt className="text-zinc-500">{label}</dt>
      <dd className="font-mono text-xs leading-5 break-all">{cmd ?? <span className="text-zinc-400">none</span>}</dd>
    </>
  );
}

function useCountdown(iso: string): number {
  const target = Date.parse(iso);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return Math.max(0, Math.floor((target - now) / 1000));
}

function fmt(s: number): string {
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}
