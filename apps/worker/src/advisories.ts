import { randomUUID } from "node:crypto";
import { advisoryFields, AU_FEEDS, parseAcscRss, parseFeed, tagAdvisory, type FeedItem, type FeedSpec } from "@community-cti/collectors";
import type { StixObject } from "@community-cti/schema";
import { mapLimit, type Queryable } from "./db.js";
import { emptyCounts, isApproved, type JobCounts, type WorkerContext } from "./context.js";
import { fetchFeed } from "./http.js";
import { redact } from "./log.js";
import { stabilise } from "./stable.js";

const FEED_LIMIT = 50;

export interface AdvisoryRow {
  sourceId: string;
  externalId: string;
  title: string;
  url: string;
  summary: string;
  publishedAt: string;
  cves: string[];
  tags: string[];
  attackTechniques: string[];
  licence: string;
}

/** One advisory per feed item, keyed `${sourceId}:${guid}`. */
export function toAdvisory(spec: FeedSpec, item: FeedItem, now: Date): AdvisoryRow {
  const text = `${item.title} ${item.body}`;
  const fields = advisoryFields(text);
  const published = item.published ? new Date(item.published) : null;
  return {
    sourceId: spec.sourceId,
    externalId: `${spec.sourceId}:${item.guid}`,
    title: item.title,
    url: item.link,
    summary: item.body ? fields.summary.slice(item.title.length + 1) || item.title : item.title,
    publishedAt: (published && !Number.isNaN(published.getTime()) ? published : now).toISOString(),
    cves: fields.cves,
    tags: tagAdvisory(text, spec.sourceId),
    attackTechniques: fields.attackTechniques,
    licence: spec.licence,
  };
}

export async function insertAdvisory(db: Queryable, row: AdvisoryRow): Promise<boolean> {
  const result = await db.query(
    `insert into advisories (id, source_id, external_id, title, url, summary, published_at, cves, tags, attack_techniques, licence, tlp)
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'TLP:CLEAR')
     on conflict (external_id) do nothing
     returning id`,
    [randomUUID(), row.sourceId, row.externalId, row.title, row.url, row.summary, row.publishedAt, row.cves, row.tags, row.attackTechniques, row.licence],
  );
  return result.rows.length > 0;
}

/** ACSC items also go to the shared STIX graph as reports. Parse problems here never block the advisory rows. */
function acscReports(xml: string, fresh: Set<string>, now: Date): StixObject[] {
  try {
    return parseAcscRss(xml, now).flatMap((report) => {
      const link = String(report.external_references?.[0]?.url ?? "");
      return fresh.has(link) ? stabilise([report], `acsc-alerts|${link}`) : [];
    });
  } catch {
    return [];
  }
}

/**
 * Hourly pull of AU_FEEDS (ACSC alerts, advisories and news, plus CISA). Only
 * approved sources are fetched. One feed failing does not stop the others.
 */
export async function runAdvisories(ctx: WorkerContext, feeds: FeedSpec[] = AU_FEEDS): Promise<JobCounts> {
  const counts = emptyCounts();
  for (const spec of feeds) {
    if (!isApproved(ctx, spec.sourceId)) {
      counts.skipped = (counts.skipped ?? 0) + 1;
      continue;
    }
    try {
      const { body } = await fetchFeed({
        url: spec.url,
        allow: [`${new URL(spec.url).origin}/`],
        userAgent: ctx.config.userAgent,
        headers: { accept: "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8" },
        fetchImpl: ctx.fetchImpl,
        sleep: ctx.sleep,
      });
      const xml = body.toString("utf8");
      const now = ctx.now();
      const items = parseFeed(xml, FEED_LIMIT);
      counts.fetched += items.length;
      const fresh = new Set<string>();
      for (const item of items) {
        if (await insertAdvisory(ctx.pool, toAdvisory(spec, item, now))) {
          counts.inserted += 1;
          fresh.add(item.link);
        } else counts.duplicates += 1;
      }
      if (spec.sourceId === "acsc-alerts" && fresh.size > 0) {
        const reports = acscReports(xml, fresh, now);
        await mapLimit(reports, 4, (report) => ctx.intel.upsert(report, null));
        counts.stix = (counts.stix ?? 0) + reports.length;
      }
    } catch (error) {
      counts.errors += 1;
      ctx.log({ level: "warn", job: "advisories", feed: spec.url, error: redact(error) });
    }
  }
  return counts;
}
