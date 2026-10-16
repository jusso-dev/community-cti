import { buildVulnerability, type StixObject } from "@community-cti/schema";
import { RateLimiter, nvdLimit } from "../rate-limit.js";

export interface NvdCve {
  id: string;
  descriptions?: Array<{ lang: string; value: string }>;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  metrics?: Record<string, Array<{ type?: string; cvssData?: { baseScore?: number; baseSeverity?: string } }> | undefined>;
}

export interface NvdFeed {
  resultsPerPage?: number;
  startIndex?: number;
  totalResults?: number;
  vulnerabilities: Array<{ cve: NvdCve }>;
}

export const NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
/** NVD refuses lastModified windows longer than 120 days. */
export const NVD_MAX_WINDOW_MS = 120 * 86_400_000;

/** One page of a lastModified window. NVD wants both ends and ISO-8601 with a zone. */
export function nvdPageUrl(start: Date, end: Date, startIndex: number, perPage = 2000): string {
  const url = new URL(NVD_API_URL);
  url.searchParams.set("lastModStartDate", start.toISOString());
  url.searchParams.set("lastModEndDate", end.toISOString());
  url.searchParams.set("resultsPerPage", String(perPage));
  url.searchParams.set("startIndex", String(startIndex));
  return url.toString();
}

/** Stable, small record for an NVD entry: no timestamps of ours, so a re-fetch dedupes. */
export function nvdRecord(cve: NvdCve): Record<string, unknown> {
  const primary = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    .flatMap((key) => cve.metrics?.[key] ?? [])
    .find((metric) => metric.type === "Primary" && metric.cvssData?.baseScore !== undefined);
  return {
    cveID: cve.id,
    published: cve.published ?? null,
    lastModified: cve.lastModified ?? null,
    vulnStatus: cve.vulnStatus ?? null,
    description: cve.descriptions?.find((item) => item.lang === "en")?.value ?? null,
    baseScore: primary?.cvssData?.baseScore ?? null,
    baseSeverity: primary?.cvssData?.baseSeverity ?? null,
  };
}

export function parseNvd(feed: NvdFeed, collectedAt: Date): StixObject[] {
  return feed.vulnerabilities.map((entry) => {
    const description = entry.cve.descriptions?.find((item) => item.lang === "en")?.value ?? entry.cve.id;
    return buildVulnerability({
      sourceId: "nvd",
      licence: "NIST NVD public terms",
      sourceUrl: "https://nvd.nist.gov/developers/vulnerabilities",
      collectedAt,
      confidence: 70,
      name: entry.cve.id,
      description,
      cve: entry.cve.id,
    });
  });
}

export function nvdLimiter(hasKey: boolean, now: () => number): RateLimiter {
  const limit = nvdLimit(hasKey);
  return new RateLimiter(limit.limit, limit.windowMs, now);
}
