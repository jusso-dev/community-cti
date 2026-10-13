import { PGlite } from "@electric-sql/pglite";
import { migrate } from "./migrate.js";
import type { Db } from "./types.js";

export interface TestDb extends Db {
  admin<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }>;
  close(): Promise<void>;
}

export function wrapPglite(pg: PGlite): Db {
  const adapter = (queryable: { query: PGlite["query"]; exec: PGlite["exec"] }): Db => ({
    async query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: T[] }> {
      const result = await queryable.query(sql, params as never[]);
      return { rows: result.rows as T[] };
    },
    async exec(sql) {
      await queryable.exec(sql);
    },
    async withTransaction(fn) {
      return pg.transaction(async (tx) => fn(adapter(tx)));
    },
  });
  return adapter(pg);
}

export async function createTestDb(): Promise<TestDb> {
  const pg = new PGlite();
  const db = wrapPglite(pg);
  await migrate(db);
  return {
    ...db,
    admin: (sql, params) => db.query(sql, params),
    close: () => pg.close(),
  };
}
