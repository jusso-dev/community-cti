import { buildIndicator, buildUrl, type StixObject } from "@community-cti/schema";
import { normaliseUrl } from "../url-normalise.js";

export interface PhishRecord {
  objects: StixObject[];
  extracted_domain: string | null;
  unicodeHost: string;
  /** Public report page for the entry, when the feed gives one. */
  reference?: string;
}

/** Split one CSV line. The live URLhaus dump quotes every cell and tags hold commas. */
export function csvCells(line: string): string[] {
  const cells: string[] = [];
  let cell = "";
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i]!;
    if (quoted) {
      if (char === '"' && line[i + 1] === '"') {
        cell += '"';
        i += 1;
      } else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"') quoted = true;
    else if (char === ",") {
      cells.push(cell);
      cell = "";
    } else cell += char;
  }
  cells.push(cell.replace(/\r$/, ""));
  return cells;
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
    const cells = csvCells(line);
    const url = cells[2];
    if (!url?.startsWith("http")) continue;
    let record: PhishRecord;
    try {
      record = fromUrl("urlhaus", "abuse.ch terms", "https://urlhaus.abuse.ch/api/", url, collectedAt);
    } catch {
      continue;
    }
    const reference = cells[7];
    if (reference?.startsWith("https://urlhaus.abuse.ch/")) record.reference = reference;
    records.push(record);
  }
  return records;
}

export function parseOpenPhish(text: string, collectedAt: Date): PhishRecord[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.startsWith("http"))
    .flatMap((url) => {
      try {
        return [fromUrl("openphish", "OpenPhish community feed terms", "https://openphish.com/feed.txt", url, collectedAt)];
      } catch {
        return [];
      }
    });
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
