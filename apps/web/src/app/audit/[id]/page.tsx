import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { AuditLive } from "@/components/audit/audit-live";
import { loadAuditView } from "@/lib/audits";

export const metadata: Metadata = { title: "Audit · VibeAudit", robots: { index: false } };

export default function AuditPage({ params }: PageProps<"/audit/[id]">) {
  return (
    <main className="mx-auto w-full max-w-4xl flex-1 px-4 py-10">
      <Suspense fallback={<AuditSkeleton />}>
        <AuditLoader params={params} />
      </Suspense>
    </main>
  );
}

async function AuditLoader({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // SSR has no owner cookie (it's scoped to the API path); the live stream reports ownership.
  const view = await loadAuditView(id, () => false);
  if (!view) notFound();
  return <AuditLive initial={view} />;
}

function AuditSkeleton() {
  return (
    <div className="flex animate-pulse flex-col gap-6" aria-busy="true" aria-label="Loading audit">
      <div className="h-8 w-2/3 rounded bg-zinc-200 dark:bg-zinc-800" />
      <div className="h-14 rounded bg-zinc-200 dark:bg-zinc-800" />
      <div className="h-64 rounded bg-zinc-200 dark:bg-zinc-800" />
    </div>
  );
}
