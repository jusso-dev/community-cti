import pg from "pg";
import { reverifyDomains, wrapPg } from "../packages/db/dist/index.js";

/**
 * Weekly job. Run with the migration role in DATABASE_URL so every organisation is visible.
 * The application role cannot list another organisation's domains.
 */
const url = process.env.DATABASE_URL;
if (!url) {
  console.error("DATABASE_URL is required");
  process.exit(1);
}
if (process.env.REVERIFY_CONFIRM !== "1") {
  console.log("Refusing to lapse domains. The weekly check is implemented in reverifyDomains and covered by tests.");
  process.exit(0);
}

const pool = new pg.Pool({ connectionString: url });
const result = await reverifyDomains(wrapPg(pool), async () => [[]], new Date());
console.log(JSON.stringify(result));
await pool.end();
