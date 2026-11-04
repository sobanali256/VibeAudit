"use client";

import { parseGitHubUrl } from "@vibeaudit/shared/github";
import { useRouter } from "next/navigation";
import { useState } from "react";

// Client-side check is for UX only; POST /api/audits re-runs parseGitHubUrl on the server.
export function RepoUrlForm() {
  const router = useRouter();
  const [value, setValue] = useState("");
  const [touched, setTouched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const parsed = value.trim() ? parseGitHubUrl(value) : null;
  const showInvalid = touched && value.trim() !== "" && !parsed;

  async function submit() {
    if (!parsed || busy) return;
    setBusy(true);
    setError(null);
    try {
      const res = await fetch("/api/audits", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: value.trim() }),
      });
      const body = (await res.json().catch(() => null)) as { id?: string; error?: string } | null;
      if (!res.ok || !body?.id) {
        setError(body?.error ?? `Couldn't start the audit (${res.status}).`);
        setBusy(false);
        return;
      }
      router.push(`/audit/${body.id}`);
    } catch {
      setError("Network error. Try again.");
      setBusy(false);
    }
  }

  return (
    <form
      className="flex flex-col gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        setTouched(true);
        void submit();
      }}
    >
      <label htmlFor="repo-url" className="text-sm font-medium">
        Public GitHub repository URL
      </label>
      <div className="flex flex-col gap-2 sm:flex-row">
        <input
          id="repo-url"
          name="url"
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          placeholder="https://github.com/owner/repo"
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setError(null);
          }}
          onBlur={() => setTouched(true)}
          aria-invalid={showInvalid}
          aria-describedby="repo-url-hint"
          className="h-11 flex-1 rounded-md border border-zinc-300 bg-white px-3 font-mono text-sm outline-none focus:border-zinc-900 dark:border-zinc-700 dark:bg-zinc-950 dark:focus:border-zinc-100"
        />
        <button
          type="submit"
          disabled={!parsed || busy}
          className="h-11 rounded-md bg-zinc-900 px-5 text-sm font-medium text-white disabled:opacity-40 dark:bg-zinc-100 dark:text-zinc-900"
        >
          {busy ? "Starting…" : "Audit"}
        </button>
      </div>
      <p id="repo-url-hint" className="min-h-5 text-sm text-zinc-600 dark:text-zinc-400" aria-live="polite">
        {error ? (
          <span className="text-red-700 dark:text-red-400">{error}</span>
        ) : showInvalid ? (
          <span className="text-red-700 dark:text-red-400">That isn&apos;t a github.com repository URL.</span>
        ) : parsed ? (
          <>
            Will audit <span className="font-mono">{parsed.owner}/{parsed.repo}</span>
            {parsed.ref ? (
              <>
                {" "}at <span className="font-mono">{parsed.ref}</span>
              </>
            ) : null}
          </>
        ) : null}
      </p>
    </form>
  );
}
