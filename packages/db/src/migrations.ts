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
  {
    id: 2,
    name: "audit owner token hash",
    sql: /* sql */ `
      -- sha256 of the per-audit owner token (held in the creator's cookie). Only the owner
      -- may answer the approval step; anyone with the link can watch and read the report.
      ALTER TABLE audits ADD COLUMN owner_hash text;
    `,
  },
  {
    id: 3,
    name: "audit artifacts (screenshots)",
    sql: /* sql */ `
      -- Evidence files the worker captured (browser screenshots). The bytes come from the
      -- sandbox: untrusted. The worker only stores JPEGs it has checked; the web serves them
      -- as image/jpeg with nosniff and a locked-down CSP. Readable by anyone with the audit
      -- link, like the report that references them.
      CREATE TABLE audit_artifacts (
        audit_id   text NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
        name       text NOT NULL,
        mime       text NOT NULL,
        data       bytea NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (audit_id, name),
        CONSTRAINT audit_artifacts_name_chk CHECK (name ~ '^[a-z0-9-]{1,40}[.]jpg$'),
        CONSTRAINT audit_artifacts_mime_chk CHECK (mime = 'image/jpeg'),
        CONSTRAINT audit_artifacts_size_chk CHECK (octet_length(data) <= 1048576)
      );
    `,
  },
];

/** Role the internet-facing web app connects as (created by infra/cp/setup-app.sh). */
export const WEB_ROLE = "vibeaudit_web";

/**
 * Least privilege for the web: read audits/events, create audits, answer approvals.
 * It can write test keys but never read them back (only the audit_id column, which the
 * DELETE in decideApproval needs), and it has no DDL (migrations run from the worker).
 * Re-applied on every migrate() so grants track new tables/columns. Skipped when the role
 * doesn't exist (dev, tests).
 */
const WEB_GRANTS = /* sql */ `
  DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${WEB_ROLE}') THEN
      REVOKE ALL ON audits, audit_events, audit_secrets, audit_artifacts, schema_migrations FROM ${WEB_ROLE};
      GRANT SELECT, INSERT (id, source, owner_hash),
            UPDATE (status, approval_decision, finished_at, updated_at, heartbeat_at)
        ON audits TO ${WEB_ROLE};
      GRANT SELECT ON audit_events TO ${WEB_ROLE};
      GRANT SELECT ON audit_artifacts TO ${WEB_ROLE};
      GRANT SELECT (audit_id), INSERT (audit_id, test_keys), DELETE ON audit_secrets TO ${WEB_ROLE};
    END IF;
  END $$;
`;

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
    await tx.unsafe(WEB_GRANTS);
    return applied;
  });
}
