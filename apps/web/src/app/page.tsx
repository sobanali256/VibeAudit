import { RepoUrlForm } from "./repo-url-form";

export default function Home() {
  return (
    <main className="mx-auto flex w-full max-w-2xl flex-1 flex-col justify-center gap-8 px-4 py-24">
      <div className="flex flex-col gap-3">
        <h1 className="text-3xl font-semibold tracking-tight">VibeAudit</h1>
        <p className="text-lg leading-8 text-zinc-600 dark:text-zinc-400">
          Audit an AI-generated Node web app by actually running it in a locked-down sandbox. Every
          finding comes with evidence: a code line, a screenshot or an HTTP response.
        </p>
      </div>
      <RepoUrlForm />
    </main>
  );
}
