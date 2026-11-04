import "server-only";
import { CHANNEL_EVENTS, createDb, type Sql } from "@vibeaudit/db";

// One pool and one LISTEN connection per web process. Cached on globalThis so dev-mode
// hot reloads don't leak a pool per edit.
type Listener = () => void;
interface DbState {
  sql: Sql;
  subs: Map<string, Set<Listener>>;
  /** Bumped on every NOTIFY for an audit, so readers can tell a fresh read from a stale one. */
  gen: Map<string, number>;
  listening: Promise<void> | null;
}
const g = globalThis as typeof globalThis & { __vibeauditDb?: DbState };

function state(): DbState {
  if (!g.__vibeauditDb) {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL is not set");
    g.__vibeauditDb = { sql: createDb(url, { max: 8 }), subs: new Map(), gen: new Map(), listening: null };
  }
  return g.__vibeauditDb;
}

export function db(): Sql {
  return state().sql;
}

/**
 * Subscribe to "something changed for this audit" (new event, status change). Every SSE
 * stream in this process shares a single LISTEN connection; NOTIFY payloads are just audit
 * ids, so subscribers re-read what they need. Returns an unsubscribe function.
 */
export async function subscribe(auditId: string, fn: Listener): Promise<() => void> {
  const s = state();
  if (!s.listening) {
    s.listening = s.sql
      .listen(CHANNEL_EVENTS, (id) => {
        const set = s.subs.get(id);
        if (!set) return;
        s.gen.set(id, (s.gen.get(id) ?? 0) + 1);
        for (const f of set) f();
      })
      .then(() => undefined)
      .catch((err) => {
        s.listening = null; // retry on the next subscribe; streams also poll as a backstop
        throw err;
      });
  }
  let set = s.subs.get(auditId);
  if (!set) s.subs.set(auditId, (set = new Set()));
  set.add(fn);
  try {
    await s.listening;
  } catch {
    // Not fatal: the stream's periodic re-check still delivers updates, just later.
  }
  return () => {
    const cur = s.subs.get(auditId);
    if (!cur) return;
    cur.delete(fn);
    // Keep gen: resetting it could make an old cached read look current again.
    if (cur.size === 0) s.subs.delete(auditId);
  };
}

/** Current notify generation for an audit (see DbState.gen). */
export function generation(auditId: string): number {
  return state().gen.get(auditId) ?? 0;
}
