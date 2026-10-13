import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import type { Db } from "./types.js";

const BOOTSTRAP = `
create table if not exists schema_migrations (
  version text primary key,
  applied_at timestamptz not null default now()
)`;

export function migrationsDir(): string {
  return fileURLToPath(new URL("../../../db/migrations", import.meta.url));
}

export async function migrate(db: Db, dir = migrationsDir()): Promise<string[]> {
  await db.exec(BOOTSTRAP);
  const files = readdirSync(dir).filter((name) => name.endsWith(".sql")).sort();
  const applied = new Set(
    (await db.query<{ version: string }>("select version from schema_migrations")).rows.map((row) => row.version),
  );
  const ran: string[] = [];
  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = readFileSync(join(dir, file), "utf8");
    await db.exec(sql);
    await db.query("insert into schema_migrations (version) values ($1)", [file]);
    ran.push(file);
  }
  return ran;
}

export function wrapPg(pool: pg.Pool): Db {
  return {
    async query(sql, params) {
      const result = await pool.query(sql, params as never[]);
      return { rows: result.rows };
    },
    async exec(sql) {
      await pool.query(sql);
    },
    async withTransaction(fn) {
      const client = await pool.connect();
      const tx: Db = {
        async query(sql, params) {
          const result = await client.query(sql, params as never[]);
          return { rows: result.rows };
        },
        async exec(sql) {
          await client.query(sql);
        },
        withTransaction: (inner) => inner(tx),
      };
      try {
        await client.query("begin");
        const value = await fn(tx);
        await client.query("commit");
        return value;
      } catch (error) {
        await client.query("rollback");
        throw error;
      } finally {
        client.release();
      }
    },
  };
}

const isCli = process.argv[1]?.endsWith("migrate.js") || process.argv[1]?.endsWith("migrate.ts");
if (isCli) {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error("DATABASE_URL is required");
    process.exit(1);
  }
  const pool = new pg.Pool({ connectionString: url });
  migrate(wrapPg(pool))
    .then((ran) => {
      console.log(ran.length === 0 ? "migrations already applied" : `applied ${ran.join(", ")}`);
      return pool.end();
    })
    .catch(async (error: unknown) => {
      console.error(error);
      await pool.end();
      process.exit(1);
    });
}
