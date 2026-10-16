import pg from "pg";
import { migrate } from "./migrate.js";

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is not set");
  process.exit(1);
}
const pool = new pg.Pool({ connectionString: url });
try {
  const result = await migrate(pool);
  console.log(result.applied.length === 0 ? "migrations already applied" : `applied ${result.applied.join(", ")}`);
  // Migration 0001 creates cti_app with a development password. Deployments replace it.
  const appPassword = process.env.CTI_APP_PASSWORD;
  if (appPassword) {
    const quoted = (await pool.query("select quote_literal($1::text) as value", [appPassword])).rows[0]!.value as string;
    await pool.query(`alter role cti_app password ${quoted}`);
    console.log("cti_app password set from CTI_APP_PASSWORD");
  }
} finally {
  await pool.end();
}
