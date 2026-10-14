import { buildIndicator, buildReport, type StixObject } from "@community-cti/schema";
import { assertAllowListed, ACSC_HOSTS } from "../allow.js";
import { tagSector } from "../sectors.js";

export interface AcscItem {
  title: string;
  link: string;
  published: string;
  description: string;
}

export function parseAcscRss(xml: string, collectedAt: Date): StixObject[] {
  const items: AcscItem[] = [];
  const blocks = xml.split("<item>").slice(1);
  for (const block of blocks) {
    const title = text(block, "title");
    const link = text(block, "link");
    const pubDate = text(block, "pubDate");
    const description = text(block, "description");
    if (!title || !link) continue;
    assertAllowListed(link, ACSC_HOSTS);
    items.push({ title, link, published: pubDate || collectedAt.toISOString(), description });
  }
  return items.map((item) => {
    const indicator = buildIndicator({
      sourceId: "acsc-alerts",
      licence: "ACSC website terms",
      sourceUrl: item.link,
      collectedAt,
      confidence: 75,
      name: item.title,
      pattern: `[url:value = '${item.link}']`,
    });
    const sectors = tagSector(`${item.title} ${item.description}`);
    return buildReport({
      sourceId: "acsc-alerts",
      licence: "ACSC website terms",
      sourceUrl: item.link,
      collectedAt,
      confidence: 75,
      name: item.title,
      description: item.description,
      published: toStixTime(item.published, collectedAt),
      objectRefs: [indicator.id],
      extra: { x_country: "AU", x_sectors: sectors.join(",") },
    });
  });
}

function text(block: string, tag: string): string {
  const match = block.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`));
  return match?.[1]?.replace(/<!\[CDATA\[|\]\]>/g, "").trim() ?? "";
}

function toStixTime(value: string, fallback: Date): string {
  const parsed = new Date(value);
  const date = Number.isNaN(parsed.getTime()) ? fallback : parsed;
  return date.toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}
