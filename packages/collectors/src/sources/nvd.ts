import { buildVulnerability, type StixObject } from "@community-cti/schema";
import { RateLimiter, nvdLimit } from "../rate-limit.js";

export interface NvdFeed {
  vulnerabilities: Array<{
    cve: {
      id: string;
      descriptions?: Array<{ lang: string; value: string }>;
      published?: string;
    };
  }>;
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
