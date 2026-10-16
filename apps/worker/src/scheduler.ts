import { createServer, type Server } from "node:http";
import { SOURCE_CRONS } from "@community-cti/collectors";
import { runAdvisories } from "./advisories.js";
import { runAlerts, runDigest } from "./alerts.js";
import { FEEDS, runFeed } from "./collect.js";
import { emptyCounts, type JobCounts, type WorkerContext } from "./context.js";
import { markAttempt, markResult, readState, type RunState } from "./db.js";
import { loadSourcesDoc, syncSources } from "./governance.js";
import { runLookalikes } from "./lookalike.js";
import { redact } from "./log.js";
import { runAuRansomware, runRansomwareMatch } from "./ransomware.js";
import { runPermutations } from "./permutations.js";
import { runRetention } from "./retention.js";
import { runReverify } from "./reverify.js";

export interface Job {
  name: string;
  everyMs: number;
  run(ctx: WorkerContext): Promise<JobCounts>;
}

export interface JobStatus {
  lastRunAt: string;
  ok: boolean;
  durationMs: number;
  counts: JobCounts;
  error?: string;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
/** A failed job waits this long (or its cadence, if shorter) before it is tried again. */
const RETRY_AFTER_MS = 15 * MINUTE;

/** Read the cadence out of a five-field cron: hourly, daily or weekly is all the worker needs. */
export function cadenceMs(cron: string | undefined, fallback = DAY): number {
  if (!cron) return fallback;
  const [minute, hour, , , weekday] = cron.trim().split(/\s+/);
  if (minute === "*") return MINUTE;
  if (hour === "*") return HOUR;
  if (weekday && weekday !== "*") return 7 * DAY;
  return DAY;
}

export function isDue(job: Job, state: RunState, now: Date): boolean {
  if (state.lastSuccessAt && now.getTime() - state.lastSuccessAt.getTime() < job.everyMs) return false;
  const retryAfter = Math.min(job.everyMs, RETRY_AFTER_MS);
  if (state.lastAttemptAt && (!state.lastSuccessAt || state.lastAttemptAt > state.lastSuccessAt) && now.getTime() - state.lastAttemptAt.getTime() < retryAfter) {
    return false;
  }
  return true;
}

/** Jobs in run order: governance, AU feeds, bulk collection, upkeep, matching, then alerts. */
export function buildJobs(): Job[] {
  return [
    {
      name: "sources-sync",
      everyMs: DAY,
      async run(ctx) {
        const counts = emptyCounts();
        counts.inserted = await syncSources(ctx.pool, loadSourcesDoc());
        return counts;
      },
    },
    // Small AU feeds first so a slow bulk feed never holds them up.
    { name: "advisories", everyMs: HOUR, run: (ctx) => runAdvisories(ctx) },
    { name: "collect:ransomwatch", everyMs: cadenceMs(SOURCE_CRONS.ransomwatch), run: (ctx) => runAuRansomware(ctx) },
    ...FEEDS.map((def) => ({
      name: `collect:${def.id}`,
      everyMs: def.everyMs ?? cadenceMs(SOURCE_CRONS[def.id], HOUR),
      run: (ctx: WorkerContext) => runFeed(ctx, def),
    })),
    { name: "reverify-domains", everyMs: DAY, run: (ctx) => runReverify(ctx) },
    { name: "lookalike", everyMs: HOUR, run: (ctx) => runLookalikes(ctx) },
    { name: "lookalike-permutations", everyMs: DAY, run: (ctx) => runPermutations(ctx) },
    { name: "ransomware-match", everyMs: HOUR, run: (ctx) => runRansomwareMatch(ctx) },
    { name: "alerts", everyMs: 5 * MINUTE, run: (ctx) => runAlerts(ctx) },
    { name: "digest", everyMs: DAY, run: (ctx) => runDigest(ctx) },
    { name: "retention", everyMs: DAY, run: (ctx) => runRetention(ctx) },
  ];
}

/** Keep only the named jobs, in run order. Unknown names are an error so a typo never silently runs nothing. */
export function selectJobs(jobs: Job[], names: string[]): Job[] {
  if (names.length === 0) return jobs;
  const known = new Set(jobs.map((job) => job.name));
  const unknown = names.filter((name) => !known.has(name));
  if (unknown.length > 0) throw new Error(`WORKER_JOBS has unknown job names: ${unknown.join(", ")}. Known: ${[...known].join(", ")}`);
  return jobs.filter((job) => names.includes(job.name));
}

/** Run one job, log one JSON line with its counts, and remember the outcome in collector_runs. */
export async function runJob(ctx: WorkerContext, job: Job, status: Map<string, JobStatus>): Promise<boolean> {
  const started = ctx.now();
  await markAttempt(ctx.pool, job.name, started);
  let counts = emptyCounts();
  let error: string | undefined;
  try {
    counts = await job.run(ctx);
  } catch (caught) {
    counts.errors += 1;
    error = redact(caught);
  }
  const durationMs = ctx.now().getTime() - started.getTime();
  const ok = error === undefined;
  status.set(job.name, { lastRunAt: started.toISOString(), ok, durationMs, counts, ...(error ? { error } : {}) });
  ctx.log({ level: ok ? "info" : "error", job: job.name, ok, durationMs, ...counts, ...(error ? { error } : {}) });
  await markResult(ctx.pool, job.name, ctx.now(), error ?? null, { ...counts, durationMs });
  return ok;
}

/** RUN_ONCE: every job once, in order, ignoring cadence. */
export async function runAll(ctx: WorkerContext, jobs: Job[], status: Map<string, JobStatus>): Promise<boolean> {
  let ok = true;
  for (const job of jobs) {
    if (!(await runJob(ctx, job, status))) ok = false;
  }
  return ok;
}

/** In-process scheduler. State lives in collector_runs, so a restart does not refetch early. */
export function startScheduler(ctx: WorkerContext, jobs: Job[], status: Map<string, JobStatus>, tickMs = MINUTE): { stop(): Promise<void> } {
  let stopping = false;
  let current: Promise<void> = Promise.resolve();
  const tick = async () => {
    for (const job of jobs) {
      if (stopping) return;
      try {
        if (isDue(job, await readState(ctx.pool, job.name), ctx.now())) await runJob(ctx, job, status);
      } catch (error) {
        ctx.log({ level: "error", job: job.name, msg: "scheduler could not run job", error: redact(error) });
      }
    }
  };
  const loop = () => {
    if (stopping) return;
    current = tick().finally(() => {
      if (!stopping) timer = setTimeout(loop, tickMs);
    });
  };
  let timer = setTimeout(loop, 0);
  return {
    async stop() {
      stopping = true;
      clearTimeout(timer);
      await current;
    },
  };
}

export function startHealthServer(port: number, status: Map<string, JobStatus>, startedAt: Date): Server {
  const server = createServer((req, res) => {
    if (req.method !== "GET" || req.url !== "/healthz") {
      res.writeHead(404, { "content-type": "application/json" }).end(JSON.stringify({ error: "not found" }));
      return;
    }
    const jobs = Object.fromEntries(status);
    res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ok: true, startedAt: startedAt.toISOString(), jobs }));
  });
  server.listen(port);
  return server;
}
