import * as dns from "node:dns/promises";
import { setDefaultAutoSelectFamilyAttemptTimeout } from "node:net";
import pg from "pg";
import { PostgresIntelStore } from "@community-cti/db";
import { mailerFromEnv, type Mailer } from "@community-cti/notify";
import { loadConfig } from "./config.js";
import type { WorkerContext } from "./context.js";
import { fileRawStore } from "./db.js";
import { effectiveSources, ignoredTestApprovals, loadSourcesDoc, syncSources } from "./governance.js";
import { jsonLogger, redact, type Logger } from "./log.js";
import { buildJobs, runAll, selectJobs, startHealthServer, startScheduler, type JobStatus } from "./scheduler.js";

export { loadConfig, type WorkerConfig } from "./config.js";
export { buildJobs, cadenceMs, isDue, runAll, runJob, selectJobs, type Job } from "./scheduler.js";

/** The worker reads every tenant, so its role must bypass row-level security (table owner with BYPASSRLS, or superuser). */
async function assertReady(pool: pg.Pool): Promise<void> {
  const role = await pool.query("select rolsuper or rolbypassrls as privileged from pg_roles where rolname = current_user");
  if (!role.rows[0]?.privileged) throw new Error("DATABASE_URL must connect as the table owner with BYPASSRLS; the worker reads across tenants");
  const table = await pool.query("select to_regclass('public.collector_runs') as name, to_regclass('public.alert_deliveries') as alerts");
  if (!table.rows[0]?.name || !table.rows[0]?.alerts) throw new Error("worker tables are missing; run pnpm db:migrate");
}

function mailerFrom(env: Record<string, string | undefined>, log: Logger): Mailer {
  const { mailer, kind } = mailerFromEnv(env);
  if (kind === "sink") log({ level: "warn", msg: "no mail transport configured (PAPERBOY_URL/PAPERBOY_API_KEY or SMTP_URL); alerts go to an in-memory sink" });
  else log({ level: "info", msg: `mail via ${kind}` });
  return mailer;
}

export async function main(env: Record<string, string | undefined> = process.env, log: Logger = jsonLogger): Promise<number> {
  // Node gives each address 250 ms before trying the next. Far-away IPv4 hosts with dead IPv6 then never connect.
  setDefaultAutoSelectFamilyAttemptTimeout(2_500);
  const config = loadConfig(env);
  const jobs = selectJobs(buildJobs(), config.workerJobs);
  const rows = loadSourcesDoc();
  const sources = effectiveSources(rows, config.testApprovedSources, config.env);
  if (config.testApprovedSources.length > 0) {
    const lifted = config.testApprovedSources.filter((id) => sources.get(id)?.status === "approved" && rows.find((row) => row.id === id)?.status !== "approved");
    log({
      level: "warn",
      msg: "TEST_APPROVED_SOURCES is set: these candidate sources run as approved before their licence review. Never use this in production.",
      sources: lifted,
      ignored: ignoredTestApprovals(rows, config.testApprovedSources),
    });
  }
  const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 8, connectionTimeoutMillis: 10_000, statement_timeout: 120_000 });
  pool.on("error", (error) => log({ level: "error", msg: "idle database connection failed", error: redact(error) }));
  try {
    await assertReady(pool);
    await syncSources(pool, rows);
    const ctx: WorkerContext = {
      pool,
      config,
      sources,
      fetchImpl: (url, init) => fetch(url, init),
      dns,
      sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
      now: () => new Date(),
      mailer: mailerFrom(env, log),
      log,
      putRaw: fileRawStore(config.rawDir),
      intel: new PostgresIntelStore(pool),
    };
    const status = new Map<string, JobStatus>();
    if (config.runOnce) {
      const ok = await runAll(ctx, jobs, status);
      log({ level: ok ? "info" : "error", msg: "run once finished", ok, failed: [...status].filter(([, item]) => !item.ok).map(([name]) => name) });
      return ok ? 0 : 1;
    }
    const server = startHealthServer(config.healthPort, status, new Date());
    const scheduler = startScheduler(ctx, jobs, status);
    log({ level: "info", msg: "worker started", healthPort: config.healthPort, jobs: jobs.map((job) => job.name) });
    await new Promise<void>((resolve) => {
      process.once("SIGTERM", resolve);
      process.once("SIGINT", resolve);
    });
    log({ level: "info", msg: "shutting down" });
    server.close();
    await Promise.race([scheduler.stop(), new Promise((resolve) => setTimeout(resolve, 25_000))]);
    return 0;
  } finally {
    await pool.end().catch(() => undefined);
  }
}

if (process.env.START_WORKER === "1" || process.env.RUN_ONCE === "1") {
  main().then(
    (code) => process.exit(code),
    (error) => {
      jsonLogger({ level: "error", msg: "worker failed to start", error: redact(error) });
      process.exit(1);
    },
  );
}
