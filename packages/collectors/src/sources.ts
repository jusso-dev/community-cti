import { createHash } from "node:crypto";
import type { Provenance, StixObject } from "@community-cti/schema";
import { buildIndicator, buildReport, buildUrl, buildVulnerability, type SourceRef } from "@community-cti/schema/stix";
import { assertAllowedHost, normaliseUrl } from "./urls.js";
import { tagSectors } from "./sectors.js";
import { RateLimiter, nvdLimit } from "./rate.js";

export interface Collected {
  record: StixObject;
  provenance: Provenance;
  extractedDomain?: string;
}

const NOW = "2026-10-13T00:00:00.000Z";

function provenance(source: SourceRef, collectedAt: string, evidenceRefs: string[] = []): Provenance {
  return {
    sourceId: source.sourceId,
    sourceUrl: source.url,
    collectedAt,
    licence: source.licence,
    accessRestriction: source.tlp,
    evidenceRefs,
  };
}

export function parseKev(body: { vulnerabilities?: Array<Record<string, string>> }, collectedAt = NOW): Collected[] {
  const source: SourceRef = {
    sourceId: "cisa-kev",
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    licence: "CC0",
    tlp: "TLP:CLEAR",
  };
  return (body.vulnerabilities ?? []).map((row) => ({
    record: buildVulnerability({
      cve: row.cveID ?? "",
      confidence: 90,
      source,
      kev: true,
      now: collectedAt,
    }),
    provenance: provenance(source, collectedAt, [source.url ?? ""]),
  }));
}

export function parseNvd(body: { vulnerabilities?: Array<{ cve?: { id?: string; descriptions?: Array<{ lang?: string; value?: string }> } }> }, collectedAt = NOW): Collected[] {
  const source: SourceRef = {
    sourceId: "nvd",
    url: "https://services.nvd.nist.gov/rest/json/cves/2.0",
    licence: "NVD public service terms",
    tlp: "TLP:CLEAR",
  };
  return (body.vulnerabilities ?? []).map((row) => ({
    record: buildVulnerability({
      cve: row.cve?.id ?? "",
      confidence: 60,
      source,
      now: collectedAt,
    }),
    provenance: provenance(source, collectedAt, [source.url ?? ""]),
  }));
}

export function parseEpss(csv: string): Map<string, number> {
  const scores = new Map<string, number>();
  for (const line of csv.split(/\r?\n/)) {
    if (!line || line.startsWith("#") || line.startsWith("cve,")) continue;
    const [cve, score] = line.split(",");
    if (cve && score) scores.set(cve.trim(), Number(score));
  }
  return scores;
}

export function attachEpss<T extends { record: StixObject }>(items: T[], scores: Map<string, number>): T[] {
  return items.map((item) => {
    const cve = typeof item.record.name === "string" ? item.record.name : "";
    const score = scores.get(cve);
    if (score === undefined) return item;
    return { ...item, record: { ...item.record, x_epss_score: score } };
  });
}

export function nvdRequests(since: Date, hasApiKey: boolean, now: () => number): { urls: string[]; limiter: RateLimiter } {
  const limit = nvdLimit(hasApiKey);
  const start = encodeURIComponent(since.toISOString());
  return {
    urls: [`https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=${start}`],
    limiter: new RateLimiter(limit.limit, limit.windowMs, now),
  };
}

export interface PhishRow { url: string; reference: string }

export function parsePhishRows(rows: PhishRow[], source: SourceRef, collectedAt = NOW): Collected[] {
  return rows.map((row) => {
    const norm = normaliseUrl(row.url);
    const observable = buildUrl({ value: norm.url, source, now: collectedAt });
    const indicator = buildIndicator({
      pattern: `[url:value = '${norm.url.replaceAll("'", "\\'")}']`,
      confidence: 70,
      source,
      now: collectedAt,
    });
    indicator.x_unicode_host = norm.unicodeHost;
    indicator.x_url_object_id = observable.id;
    return {
      record: indicator,
      provenance: provenance(source, collectedAt, [row.reference, observable.id]),
      extractedDomain: norm.registeredDomain,
    };
  });
}

export const ACSC_HOSTS = ["www.cyber.gov.au"] as const;
export const RANSOM_HOSTS = ["api.ransomware.live"] as const;
export const ACSC_FEED = "https://www.cyber.gov.au/rss/alerts";
export const RANSOM_FEED = "https://api.ransomware.live/v2/recentvictims";

export function parseAcscRss(xml: string, collectedAt = NOW): Collected[] {
  assertAllowedHost(ACSC_FEED, ACSC_HOSTS);
  const source: SourceRef = {
    sourceId: "acsc-alerts",
    url: ACSC_FEED,
    licence: "Commonwealth copyright, check cyber.gov.au terms",
    tlp: "TLP:CLEAR",
  };
  const items = [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)];
  const anchor = buildIndicator({ pattern: "[domain-name:value = 'cyber.gov.au']", confidence: 40, source, now: collectedAt });
  return items.map((match) => {
    const block = match[1] ?? "";
    const title = /<title>([\s\S]*?)<\/title>/.exec(block)?.[1]?.trim() ?? "ACSC alert";
    const link = /<link>([\s\S]*?)<\/link>/.exec(block)?.[1]?.trim() ?? ACSC_FEED;
    const pub = /<pubDate>([\s\S]*?)<\/pubDate>/.exec(block)?.[1]?.trim() ?? collectedAt;
    const report = buildReport({
      name: title,
      objectRefs: [anchor.id],
      published: toMillis(pub, collectedAt),
      source: { ...source, url: link },
      extra: { x_country: "AU", x_sectors: tagSectors(title).join(",") },
      now: collectedAt,
    });
    return { record: report, provenance: provenance(source, collectedAt, [link]) };
  });
}

export interface RansomPost { victim: string; group: string; published: string }

export function parseRansomPosts(posts: RansomPost[], collectedAt = NOW): Collected[] {
  assertAllowedHost(RANSOM_FEED, RANSOM_HOSTS);
  const source: SourceRef = {
    sourceId: "ransomwatch",
    url: RANSOM_FEED,
    licence: "ransomware.live API terms, reporting only",
    tlp: "TLP:CLEAR",
  };
  const anchor = buildIndicator({ pattern: "[domain-name:value = 'example.org']", confidence: 40, source, now: collectedAt });
  return posts.map((post) => {
    const text = `${post.victim} ${post.group}`;
    return {
      record: buildReport({
        name: `${post.group} listed ${post.victim}`,
        objectRefs: [anchor.id],
        published: toMillis(post.published, collectedAt),
        source,
        extra: {
          x_victim_name: post.victim,
          x_group: post.group,
          x_sectors: tagSectors(text).join(","),
        },
        now: collectedAt,
      }),
      provenance: provenance(source, collectedAt, [RANSOM_FEED]),
    };
  });
}

export function ransomRequestUrls(): string[] {
  assertAllowedHost(RANSOM_FEED, RANSOM_HOSTS);
  return [RANSOM_FEED];
}

function toMillis(value: string, fallback: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return fallback;
  return parsed.toISOString();
}

export function sha256Json(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

const PASSWORD_KEY = /pass(word|wd)?|passwd|pwd|secret|hash/i;

/** Drops password material before anything is stored. Data-class labels such as "Passwords" are kept. */
export function sanitiseBreachRecord(raw: Record<string, unknown>): {
  email: string;
  breachName: string;
  breachDate: string;
  dataClasses: string[];
} {
  const clean: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (PASSWORD_KEY.test(key)) continue;
    clean[key] = value;
  }
  return {
    email: String(clean.email ?? ""),
    breachName: String(clean.breachName ?? clean.Name ?? ""),
    breachDate: String(clean.breachDate ?? clean.BreachDate ?? ""),
    dataClasses: Array.isArray(clean.dataClasses) ? clean.dataClasses.map(String) : [],
  };
}

export function assertNoPasswordMaterial(record: unknown, secrets: string[]): void {
  const blob = JSON.stringify(record);
  for (const secret of secrets) {
    if (secret && blob.includes(secret)) throw new Error("password data was persisted");
  }
}

export async function lookupHibpDomain(
  domain: string,
  opts: { verified: boolean; fetchImpl: (url: string, init?: RequestInit) => Promise<Response> },
): Promise<ReturnType<typeof sanitiseBreachRecord>[]> {
  if (!opts.verified) throw new Error("refusing HIBP lookup for an unverified domain");
  const response = await opts.fetchImpl(`https://haveibeenpwned.com/api/v3/breacheddomain/${encodeURIComponent(domain)}`, {
    headers: { "hibp-api-key": "redacted" },
  });
  const body = (await response.json()) as Record<string, unknown>[];
  return body.map((row) => sanitiseBreachRecord(row));
}

export function retentionDue(resolvedAt: string | null, now: Date): boolean {
  if (!resolvedAt) return false;
  const end = new Date(resolvedAt);
  end.setUTCMonth(end.getUTCMonth() + 12);
  return now.getTime() >= end.getTime();
}
