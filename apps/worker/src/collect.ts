import {
  nvdLimit,
  nvdPageUrl,
  nvdRecord,
  NVD_MAX_WINDOW_MS,
  parseEpss,
  parseKev,
  parseNvd,
  RateLimiter,
  parseOpenPhish,
  parseUrlhaus,
  runCollector,
  threatSieveCollector,
  threatSieveObjectsUrl,
  type Collector,
  type KevFeed,
  type NvdFeed,
} from "@community-cti/collectors";
import type { StixObject, TlpMarking } from "@community-cti/schema";
import { createHash } from "node:crypto";
import { BATCH_SIZE, existingShas, insertObservations, readState, upsertSharedStix, withCollectorSession, type Queryable, type StoredObservationRow } from "./db.js";
import { emptyCounts, type JobCounts, type WorkerContext } from "./context.js";
import { fetchFeed, maybeGunzip } from "./http.js";
import { stabilise, stableStixId } from "./stable.js";

export interface FeedItem {
  /** Stable payload. Its SHA-256 is the dedupe key, so it holds no timestamps or random ids. */
  record: Record<string, unknown>;
  stix: StixObject[];
  licence: string;
  tlp?: TlpMarking;
  sourceUrl?: string;
}

export interface FeedDefinition {
  id: string;
  /** Overrides the cadence from SOURCE_CRONS. */
  everyMs?: number;
  load(ctx: WorkerContext, collectedAt: Date, since: Date | null): Promise<FeedItem[]>;
  /** Runs on the collector session after new observations are stored. */
  afterInsert?(db: Queryable, fresh: FeedItem[], ctx: WorkerContext): Promise<void>;
}

export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
export const URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/";
export const OPENPHISH_URL = "https://openphish.com/feed.txt";

async function get(ctx: WorkerContext, url: string, allow: string[], headers?: Record<string, string>): Promise<{ body: Buffer; finalUrl: string }> {
  return fetchFeed({ url, allow, headers, userAgent: ctx.config.userAgent, fetchImpl: ctx.fetchImpl, sleep: ctx.sleep });
}

export function kevStixId(cve: string): string {
  return stableStixId("vulnerability", `cisa-kev|${cve}`, "0");
}

const kev: FeedDefinition = {
  id: "cisa-kev",
  async load(ctx, collectedAt) {
    const { body } = await get(ctx, KEV_URL, ["https://www.cisa.gov/"]);
    const feed = JSON.parse(body.toString("utf8")) as KevFeed;
    if (!Array.isArray(feed.vulnerabilities)) throw new Error("KEV feed has no vulnerabilities list");
    const objects = parseKev(feed, collectedAt);
    return feed.vulnerabilities.map((entry, index) => ({
      record: { ...entry },
      stix: stabilise([objects[index]!], `cisa-kev|${entry.cveID}`),
      licence: "US government public domain",
      sourceUrl: KEV_URL,
    }));
  },
};

function round3(value: number): number {
  return Math.round(value * 1000) / 1000;
}

async function kevCves(db: Queryable): Promise<Set<string>> {
  const result = await db.query("select payload->>'cveID' as cve from observations where source_id = 'cisa-kev' and tenant_id is null");
  return new Set(result.rows.map((row) => String(row.cve)));
}

/**
 * EPSS covers every CVE. Keep KEV entries and the top N scores so storage stays bounded.
 * Bulk daily file only: the per-CVE api.first.org lookup would send our CVE interest offshore.
 */
const epss: FeedDefinition = {
  id: "epss",
  async load(ctx) {
    const { body } = await get(ctx, EPSS_URL, ["https://epss.empiricalsecurity.com/"]);
    const rows = parseEpss(maybeGunzip(body).toString("utf8")).filter((row) => /^CVE-\d{4}-\d+$/.test(row.cve) && Number.isFinite(row.epss));
    if (rows.length === 0) throw new Error("EPSS file had no rows");
    const known = await kevCves(ctx.pool);
    const top = new Set([...rows].sort((a, b) => b.epss - a.epss).slice(0, ctx.config.epssTopN).map((row) => row.cve));
    return rows
      .filter((row) => known.has(row.cve) || top.has(row.cve))
      .map((row) => ({
        record: { cve: row.cve, epss: round3(row.epss), percentile: round3(row.percentile), in_kev: known.has(row.cve) },
        stix: [],
        licence: "FIRST EPSS terms",
        sourceUrl: EPSS_URL,
      }));
  },
  async afterInsert(db, fresh) {
    for (const item of fresh) {
      if (!item.record.in_kev) continue;
      await db.query(
        "update stix_objects set body = body || $2::jsonb where id = $1 and tenant_id is null",
        [kevStixId(String(item.record.cve)), JSON.stringify({ x_epss_score: item.record.epss, x_epss_percentile: item.record.percentile })],
      );
    }
  },
};

/** URLhaus is mostly bare IP malware hosts. Only entries with a registered domain help matching. */
const urlhaus: FeedDefinition = {
  id: "urlhaus",
  async load(ctx, collectedAt) {
    const { body } = await get(ctx, URLHAUS_URL, ["https://urlhaus.abuse.ch/"]);
    return parseUrlhaus(body.toString("utf8"), collectedAt)
      .filter((item) => item.extracted_domain)
      .map((item) => {
        const url = String(item.objects[0]?.value ?? "");
        return {
          record: { url, unicode_host: item.unicodeHost, extracted_domain: item.extracted_domain, reference: item.reference ?? null },
          stix: stabilise(item.objects, `urlhaus|${url}`),
          licence: "abuse.ch terms",
          sourceUrl: item.reference,
        };
      });
  },
};

/** feed.txt now redirects to the project's GitHub mirror, so that one path is allow-listed too. */
const openphish: FeedDefinition = {
  id: "openphish",
  async load(ctx, collectedAt) {
    const { body } = await get(ctx, OPENPHISH_URL, ["https://openphish.com/", "https://raw.githubusercontent.com/openphish/"]);
    return parseOpenPhish(body.toString("utf8"), collectedAt).map((item) => {
      const url = String(item.objects[0]?.value ?? "");
      return {
        record: { url, unicode_host: item.unicodeHost, extracted_domain: item.extracted_domain },
        stix: stabilise(item.objects, `openphish|${url}`),
        licence: "OpenPhish community feed terms",
        sourceUrl: OPENPHISH_URL,
      };
    });
  },
};

const NVD_FIRST_WINDOW_MS = 86_400_000;
/** The next window starts an hour before the last success, so changes made during a run are not missed. */
const NVD_OVERLAP_MS = 3_600_000;
const NVD_MAX_PAGES = 100;
/** NVD answers slowly: a 2000-row page took 111 s live, a 500-row page 62 s. Small pages keep each request well inside the timeout. */
const NVD_PAGE_SIZE = 500;

/** NVD CVE API 2.0 by lastModified window, paged at 500, paced by nvdLimit. The key goes in the apiKey header only. */
const nvd: FeedDefinition = {
  id: "nvd",
  everyMs: 2 * 3_600_000,
  async load(ctx, collectedAt, since) {
    const end = collectedAt;
    const floor = new Date(end.getTime() - NVD_MAX_WINDOW_MS);
    const wanted = since ? new Date(since.getTime() - NVD_OVERLAP_MS) : new Date(end.getTime() - NVD_FIRST_WINDOW_MS);
    const start = wanted < floor ? floor : wanted;
    const pace = nvdLimit(!!ctx.config.nvdApiKey);
    const limiter = new RateLimiter(pace.limit, pace.windowMs, () => ctx.now().getTime());
    const headers = ctx.config.nvdApiKey ? { apiKey: ctx.config.nvdApiKey } : undefined;
    const items: FeedItem[] = [];
    let index = 0;
    for (let page = 0; page < NVD_MAX_PAGES; page++) {
      for (let delay = limiter.delayForNext(); delay > 0; delay = limiter.delayForNext()) await ctx.sleep(delay);
      const { body } = await fetchFeed({
        url: nvdPageUrl(start, end, index, NVD_PAGE_SIZE),
        allow: ["https://services.nvd.nist.gov/"],
        headers,
        userAgent: ctx.config.userAgent,
        fetchImpl: ctx.fetchImpl,
        sleep: ctx.sleep,
        timeoutMs: 180_000,
      });
      const feed = JSON.parse(body.toString("utf8")) as NvdFeed;
      const entries = Array.isArray(feed.vulnerabilities) ? feed.vulnerabilities.filter((entry) => entry?.cve?.id) : [];
      const objects = parseNvd({ vulnerabilities: entries }, collectedAt);
      entries.forEach((entry, i) => items.push({
        record: nvdRecord(entry.cve),
        stix: stabilise([objects[i]!], `nvd|${entry.cve.id}`),
        licence: "NIST NVD public terms",
        sourceUrl: `https://nvd.nist.gov/vuln/detail/${entry.cve.id}`,
      }));
      index += entries.length;
      if (entries.length === 0 || index >= (feed.totalResults ?? 0)) break;
    }
    return items;
  },
};

const MAX_TAXII_PAGES = 20;

/** Read-only TAXII 2.1 pull. Nothing about tenants is sent; the request has no body. */
const threatsieve: FeedDefinition = {
  id: "threatsieve",
  async load(ctx, _collectedAt, since) {
    const configured = ctx.config.threatSieveUrl;
    if (!configured || !ctx.config.threatSieveApiKey) return [];
    const base = new URL(configured);
    const objectsUrl = threatSieveObjectsUrl(configured, new Set([base.hostname.toLowerCase()]));
    const allow = [`${base.origin}/`];
    const headers = { accept: "application/taxii+json;version=2.1", authorization: `Bearer ${ctx.config.threatSieveApiKey}` };
    const envelopes: unknown[] = [];
    let next: string | null = null;
    for (let page = 0; page < MAX_TAXII_PAGES; page++) {
      const url = new URL(objectsUrl);
      if (since) url.searchParams.set("added_after", since.toISOString());
      if (next) url.searchParams.set("next", next);
      const { body } = await get(ctx, url.toString(), allow, headers);
      const envelope = JSON.parse(body.toString("utf8")) as { more?: boolean; next?: string };
      envelopes.push(envelope);
      if (!envelope.more || !envelope.next) break;
      next = envelope.next;
    }
    const items: FeedItem[] = [];
    for (const envelope of envelopes) {
      for (const entry of await threatSieveCollector(async () => envelope).collect(since ?? new Date(0))) {
        items.push({ record: entry.record, stix: [entry.record], licence: entry.provenance.licence, tlp: entry.provenance.accessRestriction });
      }
    }
    return items;
  },
};

/** ACSC and CISA advisories run in advisories.ts, AU ransomware in ransomware.ts. */
export const FEEDS: FeedDefinition[] = [kev, epss, nvd, urlhaus, openphish, threatsieve];

/**
 * Fetch one feed and store new observations through runCollector, which refuses
 * any source that is not approved. STIX for new entries goes to the shared graph.
 */
export async function runFeed(ctx: WorkerContext, def: FeedDefinition): Promise<JobCounts> {
  const counts = emptyCounts();
  const source = ctx.sources.get(def.id) ?? null;
  if (!source || source.status !== "approved") {
    counts.skipped = 1;
    return counts;
  }
  if (def.id === "threatsieve" && (!ctx.config.threatSieveUrl || !ctx.config.threatSieveApiKey)) {
    counts.skipped = 1;
    return counts;
  }
  const collectedAt = ctx.now();
  const since = (await readState(ctx.pool, `collect:${def.id}`)).lastSuccessAt;
  const items = await def.load(ctx, collectedAt, since);
  counts.fetched = items.length;
  const byRecord = new Map<unknown, FeedItem>(items.map((item) => [item.record, item]));
  const collector: Collector<Record<string, unknown>> = {
    sourceId: def.id,
    async collect() {
      return items.map((item) => ({
        record: item.record,
        provenance: {
          sourceId: def.id,
          ...(item.sourceUrl ? { sourceUrl: item.sourceUrl } : {}),
          collectedAt: collectedAt.toISOString(),
          licence: item.licence,
          accessRestriction: item.tlp ?? "TLP:CLEAR",
          evidenceRefs: item.stix.map((object) => object.id),
        },
      }));
    },
  };
  // One transaction, batched: look up known hashes once, buffer new rows, flush 500 at a time.
  const fresh: FeedItem[] = [];
  const objects: StixObject[] = [];
  const result = await withCollectorSession(ctx.pool, async (client) => {
    const shas = items.map((item) => createHash("sha256").update(JSON.stringify(item.record)).digest("hex"));
    const known = await existingShas(client, def.id, shas);
    const pending: StoredObservationRow[] = [];
    await client.query("begin");
    try {
      const outcome = await runCollector({
        source,
        collector,
        since: since ?? new Date(0),
        now: collectedAt,
        putRaw: ctx.putRaw,
        insertObservation: async (obs) => {
          if (known.has(obs.sha256)) return "duplicate";
          known.add(obs.sha256);
          pending.push(obs);
          fresh.push(byRecord.get(obs.payload)!);
          if (pending.length >= BATCH_SIZE) await insertObservations(client, pending.splice(0));
          return "inserted";
        },
      });
      await insertObservations(client, pending);
      objects.push(...fresh.flatMap((item) => item.stix));
      await upsertSharedStix(client, objects);
      if (def.afterInsert && fresh.length > 0) await def.afterInsert(client, fresh, ctx);
      await client.query("commit");
      return outcome;
    } catch (error) {
      await client.query("rollback");
      throw error;
    }
  });
  counts.inserted = result.inserted;
  counts.duplicates = result.duplicates;
  counts.stix = objects.length;
  return counts;
}
