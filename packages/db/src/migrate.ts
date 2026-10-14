import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export interface Queryable {
  query(sql: string, params?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>;
}

export function migrationsDir(): string {
  return fileURLToPath(new URL("../../../db/migrations", import.meta.url));
}

export async function migrate(db: Queryable, dir = migrationsDir()): Promise<{ applied: string[] }> {
  await db.query(`create table if not exists schema_migrations (
    version text primary key,
    applied_at timestamptz not null default now()
  )`);
  const existing = await db.query("select version from schema_migrations");
  const have = new Set(existing.rows.map((row) => String(row.version)));
  const files = readdirSync(dir).filter((name) => name.endsWith(".sql")).sort();
  const applied: string[] = [];
  for (const file of files) {
    if (have.has(file)) continue;
    const sql = readFileSync(join(dir, file), "utf8");
    await db.query(sql);
    await db.query("insert into schema_migrations (version) values ($1)", [file]);
    have.add(file);
    applied.push(file);
  }
  return { applied };
}
