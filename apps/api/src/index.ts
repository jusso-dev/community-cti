import { resolveTxt } from "node:dns/promises";
import pg from "pg";
import { mailerFromEnv } from "@community-cti/notify";
import { createApp, defaultDeps, type AppDeps } from "./app.js";
import { PgStore } from "./pg-store.js";

export { createApp, defaultDeps, ROUTES, type AppConfig, type AppDeps } from "./app.js";
export { MemoryStore, type Repo } from "./store.js";
export { PgStore } from "./pg-store.js";
export { onboardingCopy } from "./copy.js";

const DEV_FIELD_KEY = "0".repeat(64);

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

/** Builds production dependencies from the environment. Secrets never leave this function. */
export function depsFromEnv(env = process.env): AppDeps {
  const production = env.CTI_ENV === "production";
  const fieldKeyHex = env.FIELD_ENCRYPTION_KEY ?? (production ? "" : DEV_FIELD_KEY);
  if (!/^[0-9a-f]{64}$/i.test(fieldKeyHex)) throw new Error("FIELD_ENCRYPTION_KEY must be 64 hex characters");
  if (production && fieldKeyHex === DEV_FIELD_KEY) throw new Error("FIELD_ENCRYPTION_KEY is the development key");
  const pool = new pg.Pool({ connectionString: required("DATABASE_URL_APP"), max: Number(env.DB_POOL_MAX ?? 10) });
  pool.on("error", (error) => console.error(JSON.stringify({ level: "error", msg: "postgres pool error", error: error.message })));
  const { mailer, kind } = mailerFromEnv(env);
  console.log(JSON.stringify({ level: kind === "sink" ? "warn" : "info", msg: kind === "sink" ? "no mail transport configured; emails are kept in memory only" : `mail via ${kind}` }));
  return {
    store: new PgStore(pool),
    mailer,
    now: () => new Date(),
    resolveTxt,
    config: {
      portalBaseUrl: (env.PORTAL_BASE_URL ?? "http://localhost:3000").replace(/\/$/, ""),
      fieldKey: Buffer.from(fieldKeyHex, "hex"),
      secureCookies: env.PORTAL_BASE_URL?.startsWith("https://") ?? false,
      evidenceBaseUrl: env.EVIDENCE_BASE_URL ?? null,
      magicLinkLimit: Number(env.MAGIC_LINK_LIMIT ?? 5),
    },
  };
}

if (process.env.START_SERVER === "1") {
  const deps = process.env.DATABASE_URL_APP ? depsFromEnv() : defaultDeps();
  if (!process.env.DATABASE_URL_APP) console.warn(JSON.stringify({ level: "warn", msg: "DATABASE_URL_APP is not set; using in-memory store" }));
  const server = createApp(deps);
  const port = Number(process.env.PORT ?? 8080);
  server.listen(port, () => console.log(JSON.stringify({ level: "info", msg: "api listening", port })));
  const stop = () => server.close(() => process.exit(0));
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
