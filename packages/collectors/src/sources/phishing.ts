import { buildIndicator, buildUrl, type StixObject } from "@community-cti/schema";
import { normaliseUrl } from "../url-normalise.js";

export interface PhishRecord {
  objects: StixObject[];
  extracted_domain: string | null;
  unicodeHost: string;
}

function fromUrl(sourceId: string, licence: string, sourceUrl: string, rawUrl: string, collectedAt: Date): PhishRecord {
  const normalised = normaliseUrl(rawUrl);
  const pattern = `[url:value = '${normalised.url.replaceAll("'", "\\'")}']`;
  const url = buildUrl({
    sourceId,
    licence,
    sourceUrl,
    collectedAt,
    confidence: 70,
    value: normalised.url,
    extra: { x_unicode_host: normalised.unicodeHost },
  });
  const indicator = buildIndicator({
    sourceId,
    licence,
    sourceUrl,
    collectedAt,
    confidence: 70,
    name: normalised.host,
    pattern,
  });
  return { objects: [url, indicator], extracted_domain: normalised.registeredDomain, unicodeHost: normalised.unicodeHost };
}

export function parseUrlhaus(csv: string, collectedAt: Date): PhishRecord[] {
  const records: PhishRecord[] = [];
  for (const line of csv.split("\n")) {
    if (!line.trim() || line.startsWith("#") || line.startsWith("id,")) continue;
    const cells = line.split(",");
    const url = cells[2];
    if (!url?.startsWith("http")) continue;
    records.push(fromUrl("urlhaus", "abuse.ch terms", "https://urlhaus.abuse.ch/api/", url.replaceAll('"', ""), collectedAt));
  }
  return records;
}

export function parseOpenPhish(text: string, collectedAt: Date): PhishRecord[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("http"))
    .map((url) => fromUrl("openphish", "OpenPhish community feed terms", "https://openphish.com/feed.txt", url, collectedAt));
}

export function parsePhishTank(csv: string, collectedAt: Date): PhishRecord[] {
  const records: PhishRecord[] = [];
  for (const line of csv.split("\n")) {
    if (!line.trim() || line.startsWith("phish_id,")) continue;
    const match = line.match(/https?:\/\/[^,"]+/);
    if (!match) continue;
    records.push(fromUrl("phishtank", "PhishTank terms", "https://www.phishtank.com/developer_info.php", match[0], collectedAt));
  }
  return records;
}
