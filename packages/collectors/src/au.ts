/**
 * Australian advisory intake: feed list, a small RSS/Atom parser, tagging
 * and field extraction. Pure functions only; the worker does the fetching.
 */

export interface FeedSpec {
  sourceId: string;
  url: string;
  licence: string;
}

export const AU_FEEDS: FeedSpec[] = [
  { sourceId: "acsc-alerts", url: "https://www.cyber.gov.au/rss/alerts", licence: "Commonwealth of Australia, CC BY 4.0 (check each item)" },
  { sourceId: "acsc-alerts", url: "https://www.cyber.gov.au/rss/advisories", licence: "Commonwealth of Australia, CC BY 4.0 (check each item)" },
  { sourceId: "acsc-alerts", url: "https://www.cyber.gov.au/rss/news", licence: "Commonwealth of Australia, CC BY 4.0 (check each item)" },
  { sourceId: "cisa-advisories", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml", licence: "US government public domain" },
];

export const AU_RANSOMWARE_URL = "https://api.ransomware.live/v2/countryvictims/AU";

export interface FeedItem {
  guid: string;
  title: string;
  link: string;
  published: string | null;
  body: string;
}

const ENTITIES: Record<string, string> = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&#39;": "'", "&apos;": "'", "&quot;": '"', "&nbsp;": " " };

export function decodeText(value: string): string {
  return value
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&(?:amp|lt|gt|#39|apos|quot|nbsp);/g, (entity) => ENTITIES[entity] ?? entity)
    .replace(/&#(\d+);/g, (_, code: string) => String.fromCodePoint(Number(code)))
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function tag(block: string, name: string): string {
  const match = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, "i"));
  return match?.[1] ? decodeText(match[1]) : "";
}

/** Parses RSS 2.0 items and Atom entries. Entity decoding runs twice because feeds often double-encode HTML. */
export function parseFeed(xml: string, limit = 50): FeedItem[] {
  const items: FeedItem[] = [];
  for (const match of xml.matchAll(/<(item|entry)\b[^>]*>([\s\S]*?)<\/\1>/gi)) {
    const block = match[2]!;
    const atomLink = block.match(/<link\b[^>]*href="([^"]+)"/i)?.[1] ?? "";
    const link = tag(block, "link") || decodeText(atomLink);
    const title = tag(block, "title");
    if (!title || !/^https?:\/\//.test(link)) continue;
    const guid = tag(block, "guid") || tag(block, "id") || link;
    const published = tag(block, "pubDate") || tag(block, "updated") || tag(block, "published") || null;
    const body = decodeText(tag(block, "description") || tag(block, "summary") || tag(block, "content"));
    items.push({ guid, title, link, published, body });
    if (items.length >= limit) break;
  }
  return items;
}

export const ADVISORY_TAGS = [
  "AUSTRALIA",
  "INDIGENOUS",
  "COMMUNITY_SERVICES",
  "HEALTHCARE",
  "GOVERNMENT",
  "CRITICAL_INFRASTRUCTURE",
  "SMB",
  "FINANCE",
  "EDUCATION",
] as const;

export type AdvisoryTag = (typeof ADVISORY_TAGS)[number];

const TAG_HINTS: Array<[RegExp, AdvisoryTag]> = [
  [/australia|\bACSC\b|\bASD\b|cyber\.gov\.au|\bAUS\b/i, "AUSTRALIA"],
  [/aboriginal|torres strait|first nations|indigenous|\bACCOs?\b|\bACCHOs?\b|land council|native title|\bPBCs?\b/i, "INDIGENOUS"],
  [/community (?:sector|organisation|organization|service)|not-for-profit|non-profit|charit|\bNFPs?\b|NGO/i, "COMMUNITY_SERVICES"],
  [/health|hospital|medical|clinic|aged care|disability|\bAMS\b/i, "HEALTHCARE"],
  [/government|agency|federal|state entities|local council|shire/i, "GOVERNMENT"],
  [/critical infrastructure|\bOT\b|\bICS\b|SCADA|energy|water utilit/i, "CRITICAL_INFRASTRUCTURE"],
  [/small business|\bSMBs?\b|small and medium|\bSMEs?\b/i, "SMB"],
  [/bank|financ|payment/i, "FINANCE"],
  [/universit|school|education/i, "EDUCATION"],
];

export function tagAdvisory(text: string, sourceId: string): AdvisoryTag[] {
  const tags = new Set<AdvisoryTag>();
  if (sourceId.startsWith("acsc")) tags.add("AUSTRALIA");
  for (const [pattern, name] of TAG_HINTS) if (pattern.test(text)) tags.add(name);
  return ADVISORY_TAGS.filter((name) => tags.has(name));
}

const TECHNIQUE_HINTS: Array<[RegExp, string]> = [
  [/anydesk|screenconnect|connectwise control|teamviewer|splashtop|rustdesk|atera/i, "T1219"],
  [/shadow cop|vssadmin/i, "T1490"],
  [/mimikatz|lsass|procdump/i, "T1003.001"],
  [/lockbit|akira|rhysida|ransomware/i, "T1486"],
  [/fortigate|fortios|ivanti|citrix/i, "T1190"],
  [/encoded powershell|powershell -enc/i, "T1059.001"],
  [/phishing|phish/i, "T1566"],
];

export function advisoryFields(text: string): { cves: string[]; attackTechniques: string[]; summary: string } {
  const cves = [...new Set((text.match(/CVE-\d{4}-\d{4,7}/gi) ?? []).map((value) => value.toUpperCase()))];
  const techniques = new Set((text.match(/\bT\d{4}(?:\.\d{3})?\b/g) ?? []));
  for (const [pattern, id] of TECHNIQUE_HINTS) if (pattern.test(text)) techniques.add(id);
  return { cves, attackTechniques: [...techniques].sort(), summary: text.slice(0, 2000) };
}

export interface AuRansomwareVictim {
  externalId: string;
  victim: string;
  website: string | null;
  activity: string | null;
  groupName: string;
  discoveredAt: string;
  country: string;
}

/** ransomware.live country listing. Only rows marked AU are kept. */
export function parseAuRansomware(body: unknown): AuRansomwareVictim[] {
  if (!Array.isArray(body)) throw new Error("ransomware.live response is not a list");
  const out: AuRansomwareVictim[] = [];
  for (const row of body as Array<Record<string, unknown>>) {
    if (String(row.country ?? "").toUpperCase() !== "AU") continue;
    const victim = String(row.victim ?? row.post_title ?? "").trim();
    const groupName = String(row.group_name ?? row.group ?? "").trim();
    const discovered = new Date(String(row.discovered ?? row.attackdate ?? ""));
    if (!victim || !groupName || Number.isNaN(discovered.getTime())) continue;
    const website = String(row.website ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "") || null;
    const activity = String(row.activity ?? "").trim() || null;
    out.push({
      externalId: `${groupName}:${victim}:${discovered.toISOString().slice(0, 10)}`.toLowerCase(),
      victim,
      website,
      activity: activity === "Not Found" ? null : activity,
      groupName,
      discoveredAt: discovered.toISOString(),
      country: "AU",
    });
  }
  return out;
}

/** Tags each organisation type watches for, in addition to AUSTRALIA. */
export const ORG_TYPE_TAGS: Record<string, AdvisoryTag[]> = {
  ACCO: ["INDIGENOUS", "COMMUNITY_SERVICES", "HEALTHCARE", "SMB"],
  "Land Council": ["INDIGENOUS", "GOVERNMENT", "COMMUNITY_SERVICES", "SMB"],
  AMS: ["INDIGENOUS", "HEALTHCARE", "COMMUNITY_SERVICES"],
  "Indigenous corporation": ["INDIGENOUS", "SMB"],
  other: ["SMB"],
};

/** ransomware.live "activity" values mapped onto our tags, for sector-level awareness. */
export function activityTags(activity: string | null): AdvisoryTag[] {
  if (!activity) return [];
  return tagAdvisory(activity, "");
}
