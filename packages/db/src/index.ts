import postgres, { type Sql } from "postgres";

export * from "./audits";
export { MIGRATIONS, migrate } from "./migrations";
export type { Sql };

export function createDb(url: string, opts: { max?: number } = {}): Sql {
  return postgres(url, {
    max: opts.max ?? 5,
    idle_timeout: 30,
    connect_timeout: 10,
    // bigint/bigserial as strings (event ids); jsonb parsed automatically.
    onnotice: () => {},
  });
}
