import { rm } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { emptyCounts, type JobCounts, type WorkerContext } from "./context.js";

const DAY_MS = 86_400_000;
const BATCH = 1000;
const LIVE_STATUSES = ["open", "acknowledged", "challenged"];

/**
 * Old observations go, with their raw blobs, unless a live finding still points
 * at them through finding_evidence or a provenance evidence ref.
 */
async function pruneObservations(ctx: WorkerContext, cutoff: Date, counts: JobCounts): Promise<void> {
  const root = resolve(ctx.config.rawDir);
  for (;;) {
    const result = await ctx.pool.query(
      `with doomed as (
         select o.id from observations o
         where o.collected_at < $1
           and not exists (
             select 1 from finding_evidence fe join findings f on f.id = fe.finding_id
             where fe.object_key = o.raw_key and f.status = any($2::text[]))
           and not exists (
             select 1 from findings f
             where f.status = any($2::text[])
               and f.provenance @> jsonb_build_array(jsonb_build_object('evidenceRefs', jsonb_build_array(o.id::text))))
         limit $3
       )
       delete from observations o using doomed where o.id = doomed.id
       returning o.raw_key`,
      [cutoff, LIVE_STATUSES, BATCH],
    );
    counts.observations = (counts.observations ?? 0) + result.rows.length;
    for (const row of result.rows) {
      const path = resolve(root, String(row.raw_key));
      if (!path.startsWith(root + sep)) continue;
      try {
        await rm(path, { force: true });
        counts.blobs = (counts.blobs ?? 0) + 1;
      } catch {
        counts.errors += 1;
      }
    }
    if (result.rows.length < BATCH) return;
  }
}

async function count(ctx: WorkerContext, sql: string, params: unknown[]): Promise<number> {
  const result = await ctx.pool.query(`with gone as (${sql} returning 1) select count(*)::int as n from gone`, params);
  return Number(result.rows[0]?.n ?? 0);
}

/** Daily clean-up. Never touches audit_log, findings or consents. */
export async function runRetention(ctx: WorkerContext): Promise<JobCounts> {
  const counts = emptyCounts();
  const now = ctx.now();
  counts.magicLinks = await count(ctx, "delete from magic_links where expires_at < $1", [now]);
  counts.sessions = await count(ctx, "delete from sessions where expires_at < $1", [now]);
  await pruneObservations(ctx, new Date(now.getTime() - ctx.config.retentionDaysRaw * DAY_MS), counts);
  counts.ransomwareVictims = await count(ctx, "delete from au_ransomware_victims where discovered_at < $1", [new Date(now.getTime() - 400 * DAY_MS)]);
  counts.advisories = await count(ctx, "delete from advisories where published_at < $1", [new Date(now.getTime() - 730 * DAY_MS)]);
  return counts;
}
