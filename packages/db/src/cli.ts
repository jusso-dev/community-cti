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
} finally {
  await pool.end();
}
