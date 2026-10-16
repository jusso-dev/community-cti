import { randomUUID } from "node:crypto";
import { AU_RANSOMWARE_URL, parseAuRansomware, type AuRansomwareVictim } from "@community-cti/collectors";
import { isUnderVerifiedDomain, scoreRansomware, type Score } from "@community-cti/intel";
import type { TlpMarking } from "@community-cti/schema";
import { emptyCounts, isApproved, type JobCounts, type WorkerContext } from "./context.js";
import type { Queryable } from "./db.js";
import { persistFinding, type FindingDraft } from "./findings.js";
import { fetchFeed } from "./http.js";
import { loadTenantDomains } from "./lookalike.js";
import { redact } from "./log.js";

/** ransomware.live has AU rows back to 2016. Only the last year is kept and matched. */
const KEEP_MS = 365 * 86_400_000;
const SOURCE_ID = "ransomwatch";

export interface Victim {
  id: string;
  externalId: string;
  victim: string;
  group: string;
  published: string;
  victimDomain: string | null;
  collectedAt: string;
  licence: string;
  tlp: TlpMarking;
}

export interface TenantProfile {
  tenantId: string;
  name: string;
  verified: string[];
}

/** Ransomware mentions need a strong name match; below this nothing is raised. */
export const RANSOMWARE_MIN_CONFIDENCE = 60;

export function recentVictims(victims: AuRansomwareVictim[], now: Date): AuRansomwareVictim[] {
  return victims.filter((victim) => now.getTime() - new Date(victim.discoveredAt).getTime() <= KEEP_MS);
}

export async function insertVictim(db: Queryable, victim: AuRansomwareVictim): Promise<boolean> {
  const result = await db.query(
    `insert into au_ransomware_victims (id, external_id, victim, website, activity, group_name, discovered_at, country)
     values ($1, $2, $3, $4, $5, $6, $7, $8)
     on conflict (external_id) do nothing
     returning id`,
    [randomUUID(), victim.externalId, victim.victim, victim.website, victim.activity, victim.groupName, victim.discoveredAt, victim.country],
  );
  return result.rows.length > 0;
}

/** Public AU victim listings from ransomware.live. Leak-site links are never requested or stored. */
export async function runAuRansomware(ctx: WorkerContext): Promise<JobCounts> {
  const counts = emptyCounts();
  if (!isApproved(ctx, SOURCE_ID)) {
    counts.skipped = 1;
    return counts;
  }
  const { body } = await fetchFeed({ url: AU_RANSOMWARE_URL, allow: ["https://api.ransomware.live/"], userAgent: ctx.config.userAgent, fetchImpl: ctx.fetchImpl, sleep: ctx.sleep });
  const victims = recentVictims(parseAuRansomware(JSON.parse(body.toString("utf8"))), ctx.now());
  counts.fetched = victims.length;
  for (const victim of victims) {
    if (await insertVictim(ctx.pool, victim)) counts.inserted += 1;
    else counts.duplicates += 1;
  }
  return counts;
}

export function matchVictims(victims: Victim[], tenants: TenantProfile[], minConfidence = RANSOMWARE_MIN_CONFIDENCE): Array<{ victim: Victim; tenant: TenantProfile; score: Score; secondSignal: boolean }> {
  const out: Array<{ victim: Victim; tenant: TenantProfile; score: Score; secondSignal: boolean }> = [];
  for (const victim of victims) {
    const name = victim.victim.trim().replace(/^www\./i, "");
    if (!name) continue;
    for (const tenant of tenants) {
      const secondSignal = !!victim.victimDomain && isUnderVerifiedDomain(victim.victimDomain, tenant.verified);
      const score = scoreRansomware({ victim: name, tenantName: tenant.name, aliases: tenant.verified, secondSignal });
      if (score.confidence >= minConfidence) out.push({ victim, tenant, score, secondSignal });
    }
  }
  return out;
}

export function ransomwareDedupeKey(victim: Pick<Victim, "externalId">): string {
  return `ransomware:${victim.externalId}`;
}

export function ransomwareDraft(match: { victim: Victim; tenant: TenantProfile; score: Score; secondSignal: boolean }): FindingDraft {
  const { victim, tenant, score } = match;
  const date = victim.published.slice(0, 10);
  const summary = [
    `A public report on ${date} lists "${victim.victim}" as a ransomware victim.`,
    `The name is close to ${tenant.name}.`,
    match.secondSignal ? "The website in the report is one of your domains." : "It may be a different group with a similar name.",
    "Ask your IT helper if you were affected. Challenge this finding if it is not you.",
  ].join(" ");
  return {
    tenantId: tenant.tenantId,
    kind: "ransomware_mention",
    dedupeKey: ransomwareDedupeKey(victim),
    title: `A ransomware report names ${victim.victim}`,
    summary,
    confidence: score.confidence,
    factors: score.factors,
    provenance: [{
      sourceId: SOURCE_ID,
      sourceUrl: AU_RANSOMWARE_URL,
      collectedAt: victim.collectedAt,
      licence: victim.licence,
      accessRestriction: victim.tlp,
      evidenceRefs: [`au_ransomware_victims:${victim.id}`],
    }],
    stixRefs: [],
    stixObjects: [],
    evidence: [{
      label: `Public ransomware listing naming ${victim.victim} (${victim.group}, ${date})`,
      url: null,
      objectKey: null,
      sourceId: SOURCE_ID,
      licence: victim.licence,
      tlp: victim.tlp,
      collectedAt: victim.collectedAt,
    }],
  };
}

async function loadVictims(ctx: WorkerContext): Promise<Victim[]> {
  const licence = ctx.sources.get(SOURCE_ID)?.licence ?? "ransomware.live public API terms";
  const result = await ctx.pool.query(
    "select id, external_id, victim, website, group_name, discovered_at, collected_at from au_ransomware_victims where discovered_at > $1",
    [new Date(ctx.now().getTime() - KEEP_MS)],
  );
  return result.rows.map((row) => ({
    id: String(row.id),
    externalId: String(row.external_id),
    victim: String(row.victim),
    group: String(row.group_name),
    published: new Date(String(row.discovered_at)).toISOString(),
    victimDomain: row.website ? String(row.website).replace(/^www\./, "") : null,
    collectedAt: new Date(String(row.collected_at)).toISOString(),
    licence,
    tlp: "TLP:CLEAR",
  }));
}

/** Compare AU victims with tenant names. A victim website under a tenant's verified domain is the second signal. */
export async function runRansomwareMatch(ctx: WorkerContext, options: { tenantIds?: string[] } = {}): Promise<JobCounts> {
  const counts = emptyCounts();
  if (!isApproved(ctx, SOURCE_ID)) {
    counts.skipped = 1;
    return counts;
  }
  const names = await ctx.pool.query("select id, name from tenants where ($1::uuid[] is null or id = any($1))", [options.tenantIds ?? null]);
  const domains = new Map((await loadTenantDomains(ctx, options.tenantIds)).map((item) => [item.tenantId, item.verified]));
  const tenants = names.rows.map((row) => ({ tenantId: String(row.id), name: String(row.name), verified: domains.get(String(row.id)) ?? [] }));
  const victims = await loadVictims(ctx);
  counts.fetched = victims.length;
  const threshold = Math.max(RANSOMWARE_MIN_CONFIDENCE, ctx.config.findingMinConfidence);
  for (const match of matchVictims(victims, tenants, threshold)) {
    try {
      const persisted = await persistFinding(ctx.pool, ctx.intel, ransomwareDraft(match));
      if (persisted.outcome === "inserted") counts.findings += 1;
    } catch (error) {
      counts.errors += 1;
      ctx.log({ level: "error", job: "ransomware-match", error: redact(error) });
    }
  }
  return counts;
}
