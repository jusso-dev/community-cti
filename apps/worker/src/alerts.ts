import { createHash, randomUUID } from "node:crypto";
import { withTenant } from "@community-cti/db";
import { deliveryPlan, renderAlert, type Delivery } from "@community-cti/notify";
import type { ConfidenceFactor, Finding, FindingKind, Provenance } from "@community-cti/schema";
import { emptyCounts, type JobCounts, type WorkerContext } from "./context.js";
import { redact } from "./log.js";

export type Preference = "immediate" | "digest" | "off";

export interface Member {
  userId: string;
  mode: Preference | null;
}

const MAX_ATTEMPTS = 3;
const ALERT_WINDOW = "7 days";

/** Members with no saved preference get the daily digest. */
export function planAlerts(confidence: number, members: Member[]): Array<{ userId: string; delivery: Delivery }> {
  return members.map((member) => ({ userId: member.userId, delivery: deliveryPlan(confidence, member.mode ?? "digest") }));
}

export interface DigestItem {
  findingId: string;
  title: string;
  confidence: number;
}

export function renderDigest(tenantName: string, items: DigestItem[], portalBaseUrl: string): { subject: string; text: string } {
  const lines = [
    `Here is what we found for ${tenantName} in the last day.`,
    "",
    ...items.flatMap((item, index) => [
      `${index + 1}. ${item.title}. Confidence: ${item.confidence} out of 100.`,
      `   Open it: ${portalBaseUrl}/findings/${item.findingId}`,
    ]),
    "",
    "Each finding shows its sources. You can dismiss any finding that is not a problem.",
    "To change how often we email you, open Settings in the portal.",
  ];
  return { subject: `Daily summary: ${items.length} new ${items.length === 1 ? "finding" : "findings"}`, text: lines.join("\n") };
}

function rowToFinding(row: Record<string, unknown>): Finding {
  return {
    id: String(row.finding_id),
    tenantId: String(row.tenant_id),
    kind: String(row.kind) as FindingKind,
    title: String(row.title),
    plainEnglishSummary: String(row.plain_english_summary),
    confidence: Number(row.confidence),
    status: "open",
    provenance: row.provenance as Provenance[],
    stixRefs: (row.stix_refs as string[]) ?? [],
    confidenceFactors: row.confidence_factors as ConfidenceFactor[],
  };
}

/** Record one delivery decision per open finding and member, so nothing is planned or sent twice. */
async function planPending(ctx: WorkerContext, tenantIds: string[] | null, counts: JobCounts): Promise<void> {
  const findings = await ctx.pool.query(
    `select f.id, f.tenant_id, f.confidence from findings f
     where f.status = 'open' and f.created_at > now() - interval '${ALERT_WINDOW}'
       and ($1::uuid[] is null or f.tenant_id = any($1))
       and exists (
         select 1 from memberships m
         where m.tenant_id = f.tenant_id
           and not exists (select 1 from alert_deliveries d where d.finding_id = f.id and d.user_id = m.user_id)
       )`,
    [tenantIds],
  );
  for (const finding of findings.rows) {
    const tenantId = String(finding.tenant_id);
    await withTenant(ctx.pool, tenantId, async (client) => {
      const members = await client.query(
        `select m.user_id, p.mode from memberships m
         left join notification_preferences p on p.tenant_id = m.tenant_id and p.user_id = m.user_id
         where m.tenant_id = $1`,
        [tenantId],
      );
      const plan = planAlerts(Number(finding.confidence), members.rows.map((row) => ({ userId: String(row.user_id), mode: (row.mode as Preference | null) ?? null })));
      for (const item of plan) {
        const inserted = await client.query(
          `insert into alert_deliveries (id, tenant_id, finding_id, user_id, delivery, sent_at)
           values ($1, $2, $3, $4, $5::text, case when $5::text = 'none' then now() else null end)
           on conflict (finding_id, user_id) do nothing returning id`,
          [randomUUID(), tenantId, finding.id, item.userId, item.delivery],
        );
        if (inserted.rows.length > 0) counts[`planned_${item.delivery}`] = (counts[`planned_${item.delivery}`] ?? 0) + 1;
      }
    });
  }
}

async function recordSend(ctx: WorkerContext, ids: string[], result: { messageId: string } | { error: string }): Promise<void> {
  if ("messageId" in result) {
    await ctx.pool.query("update alert_deliveries set sent_at = now(), attempts = attempts + 1, message_id = $2, last_error = null where id = any($1)", [ids, result.messageId]);
  } else {
    await ctx.pool.query("update alert_deliveries set attempts = attempts + 1, last_error = $2 where id = any($1)", [ids, result.error]);
  }
}

const PAUSE_KEY = "mail-pause";
const DEFAULT_PAUSE_MS = 60_000;

/** A 429 from the mail service pauses all sending until its Retry-After passes. Attempts are not used up. */
function rateLimitedFor(error: unknown): number | null {
  const mailError = error as { status?: number; retryAfterSeconds?: number | null };
  if (mailError?.status !== 429) return null;
  return mailError.retryAfterSeconds ? mailError.retryAfterSeconds * 1000 : DEFAULT_PAUSE_MS;
}

async function pausedUntil(ctx: WorkerContext): Promise<Date | null> {
  const result = await ctx.pool.query("select summary->>'until' as until from collector_runs where key = $1", [PAUSE_KEY]);
  const until = result.rows[0]?.until ? new Date(String(result.rows[0].until)) : null;
  return until && until > ctx.now() ? until : null;
}

async function pause(ctx: WorkerContext, ms: number, counts: JobCounts): Promise<void> {
  const until = new Date(ctx.now().getTime() + ms);
  counts.rateLimited = (counts.rateLimited ?? 0) + 1;
  await ctx.pool.query(
    `insert into collector_runs (key, last_attempt_at, summary) values ($1, $2, $3::jsonb)
     on conflict (key) do update set last_attempt_at = excluded.last_attempt_at, summary = excluded.summary`,
    [PAUSE_KEY, ctx.now(), JSON.stringify({ until: until.toISOString() })],
  );
  ctx.log({ level: "warn", msg: "mail service rate limited; sending paused", until: until.toISOString() });
}

/** Plan new findings, then email the members who asked for immediate alerts. */
export async function runAlerts(ctx: WorkerContext, options: { tenantIds?: string[] } = {}): Promise<JobCounts> {
  const counts = emptyCounts();
  const tenantIds = options.tenantIds ?? null;
  await planPending(ctx, tenantIds, counts);
  if (await pausedUntil(ctx)) {
    counts.paused = 1;
    return counts;
  }
  const pending = await ctx.pool.query(
    `select d.id, d.tenant_id, u.email, f.id as finding_id, f.kind, f.title, f.plain_english_summary, f.confidence,
            f.provenance, f.stix_refs, f.confidence_factors
     from alert_deliveries d
     join users u on u.id = d.user_id
     join findings f on f.id = d.finding_id
     where d.delivery = 'immediate' and d.sent_at is null and d.attempts < $1 and f.status = 'open'
       and ($2::uuid[] is null or d.tenant_id = any($2))
     order by d.created_at`,
    [MAX_ATTEMPTS, tenantIds],
  );
  for (const row of pending.rows) {
    const finding = rowToFinding(row);
    const email = renderAlert(finding, `${ctx.config.portalBaseUrl}/findings/${finding.id}`);
    try {
      const sent = await ctx.mailer.send({ to: String(row.email), subject: email.subject, text: email.text, category: "alert", idempotencyKey: `alert:${row.id}` });
      await recordSend(ctx, [String(row.id)], sent);
      counts.sent = (counts.sent ?? 0) + 1;
    } catch (error) {
      const wait = rateLimitedFor(error);
      if (wait !== null) {
        await pause(ctx, wait, counts);
        break;
      }
      counts.errors += 1;
      await recordSend(ctx, [String(row.id)], { error: redact(error) });
    }
  }
  return counts;
}

/** One summary email per member and tenant for the digest deliveries still waiting. */
export async function runDigest(ctx: WorkerContext, options: { tenantIds?: string[] } = {}): Promise<JobCounts> {
  const counts = emptyCounts();
  if (await pausedUntil(ctx)) {
    counts.paused = 1;
    return counts;
  }
  const rows = await ctx.pool.query(
    `select d.id, d.tenant_id, d.user_id, u.email, t.name as tenant_name, f.id as finding_id, f.title, f.confidence
     from alert_deliveries d
     join users u on u.id = d.user_id
     join findings f on f.id = d.finding_id
     join tenants t on t.id = d.tenant_id
     where d.delivery = 'digest' and d.sent_at is null and d.attempts < $1 and f.status = 'open'
       and d.created_at > now() - interval '${ALERT_WINDOW}'
       and ($2::uuid[] is null or d.tenant_id = any($2))
     order by d.tenant_id, d.user_id, f.confidence desc`,
    [MAX_ATTEMPTS, options.tenantIds ?? null],
  );
  const groups = new Map<string, { email: string; tenantName: string; ids: string[]; items: DigestItem[] }>();
  for (const row of rows.rows) {
    const key = `${row.tenant_id}|${row.user_id}`;
    const group = groups.get(key) ?? { email: String(row.email), tenantName: String(row.tenant_name), ids: [], items: [] };
    group.ids.push(String(row.id));
    group.items.push({ findingId: String(row.finding_id), title: String(row.title), confidence: Number(row.confidence) });
    groups.set(key, group);
  }
  for (const group of groups.values()) {
    const digest = renderDigest(group.tenantName, group.items, ctx.config.portalBaseUrl);
    try {
      const sent = await ctx.mailer.send({ to: group.email, subject: digest.subject, text: digest.text, category: "digest", idempotencyKey: `digest:${createHash("sha256").update([...group.ids].sort().join(",")).digest("hex")}` });
      await recordSend(ctx, group.ids, sent);
      counts.sent = (counts.sent ?? 0) + 1;
    } catch (error) {
      const wait = rateLimitedFor(error);
      if (wait !== null) {
        await pause(ctx, wait, counts);
        break;
      }
      counts.errors += 1;
      await recordSend(ctx, group.ids, { error: redact(error) });
    }
  }
  return counts;
}
