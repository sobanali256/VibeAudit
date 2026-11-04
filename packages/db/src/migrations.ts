import type { Sql } from "postgres";

/**
 * Append-only list of migrations. Never edit a shipped entry; add a new one.
 * Embedded as strings (not .sql files) so they bundle cleanly into Next and tsx.
 */
export const MIGRATIONS: { id: number; name: string; sql: string }[] = [
  {
    id: 1,
    name: "audits, events, secrets",
    sql: /* sql */ `
      CREATE TABLE audits (
        id                 text PRIMARY KEY,
        source             jsonb NOT NULL,
        status             text NOT NULL DEFAULT 'queued',
        stage              text,
        created_at         timestamptz NOT NULL DEFAULT now(),
        updated_at         timestamptz NOT NULL DEFAULT now(),
        started_at         timestamptz,
        finished_at        timestamptz,
        -- Lease: the worker that claimed the audit refreshes this; stale = crashed worker.
        heartbeat_at       timestamptz,
        error              text,
        approval_request   jsonb,
        approval_expires_at timestamptz,
        approval_decision  jsonb,
        report             jsonb,
        CONSTRAINT audits_status_chk CHECK (status IN
          ('queued','running','awaiting_approval','completed','static_only','failed','cancelled'))
      );
      CREATE INDEX audits_queue_idx ON audits (created_at) WHERE status = 'queued';

      -- Progress stream for SSE. Payloads may contain sandbox-derived text: escape on render.
      CREATE TABLE audit_events (
        id        bigserial PRIMARY KEY,
        audit_id  text NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
        at        timestamptz NOT NULL DEFAULT now(),
        kind      text NOT NULL,
        payload   jsonb NOT NULL DEFAULT '{}'::jsonb
      );
      CREATE INDEX audit_events_audit_idx ON audit_events (audit_id, id);

      -- Real test keys. Separate table so they never ride along with audit rows/API output.
      -- Deleted as soon as the audit leaves the run-time stages (and by the janitor).
      CREATE TABLE audit_secrets (
        audit_id    text PRIMARY KEY REFERENCES audits(id) ON DELETE CASCADE,
        test_keys   jsonb NOT NULL,
        created_at  timestamptz NOT NULL DEFAULT now()
      );
    `,
  },
];

const LOCK_KEY = 0x76696265; // "vibe": serialize concurrent migrators (web + worker boot)

export async function migrate(sql: Sql): Promise<number[]> {
  return sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(${LOCK_KEY})`;
    await tx`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        id integer PRIMARY KEY,
        name text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )`;
    const done = new Set((await tx<{ id: number }[]>`SELECT id FROM schema_migrations`).map((r) => r.id));
    const applied: number[] = [];
    for (const m of MIGRATIONS) {
      if (done.has(m.id)) continue;
      await tx.unsafe(m.sql);
      await tx`INSERT INTO schema_migrations (id, name) VALUES (${m.id}, ${m.name})`;
      applied.push(m.id);
    }
    return applied;
  });
}
