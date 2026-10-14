import { buildIndicator, buildReport, type StixObject } from "@community-cti/schema";
import { assertAllowListed, RANSOM_HOSTS } from "../allow.js";
import { tagSector } from "../sectors.js";

export interface RansomVictim {
  victim: string;
  group: string;
  published: string;
  country?: string;
  description?: string;
  leak_url?: string;
  download?: string;
}

const KEPT = new Set(["victim", "group", "published", "country", "description"]);

export function parseRansomwareReport(body: unknown, collectedAt: Date, requestUrl: string): StixObject[] {
  assertAllowListed(requestUrl, RANSOM_HOSTS);
  if (!Array.isArray(body)) throw new Error("ransomware report must be a list");
  return body.map((entry) => {
    const row = entry as RansomVictim;
    const kept: Record<string, string> = {};
    for (const [key, value] of Object.entries(row)) {
      if (!KEPT.has(key) || typeof value !== "string") continue;
      kept[key] = value;
    }
    const sectors = tagSector(`${kept.description ?? ""} ${kept.victim ?? ""}`);
    const indicator = buildIndicator({
      sourceId: "ransomwatch",
      licence: "ransomware.live public API terms",
      sourceUrl: requestUrl,
      collectedAt,
      confidence: 60,
      name: kept.victim ?? "unknown victim",
      pattern: `[identity:name = '${(kept.victim ?? "unknown").replaceAll("'", "\\'")}']`,
    });
    return buildReport({
      sourceId: "ransomwatch",
      licence: "ransomware.live public API terms",
      sourceUrl: "https://www.ransomware.live/",
      collectedAt,
      confidence: 60,
      name: kept.victim ?? "Ransomware report",
      published: toStix(kept.published, collectedAt),
      objectRefs: [indicator.id],
      description: "Public reporting of a named victim. Leak-site content is not collected.",
      extra: {
        x_victim_name: kept.victim ?? "",
        x_group: kept.group ?? "",
        x_country: kept.country ?? "",
        x_sectors: sectors.join(","),
      },
    });
  });
}

export function storedText(objects: StixObject[]): string {
  return JSON.stringify(objects);
}

function toStix(value: string | undefined, fallback: Date): string {
  const parsed = value ? new Date(value) : fallback;
  const date = Number.isNaN(parsed.getTime()) ? fallback : parsed;
  return date.toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}
