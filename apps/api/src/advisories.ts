import { ORG_TYPE_TAGS, activityTags, type AdvisoryTag } from "@community-cti/collectors";

export interface AdvisoryRecord {
  id: string;
  sourceId: string;
  title: string;
  url: string;
  summary: string;
  publishedAt: string;
  cves: string[];
  tags: string[];
  attackTechniques: string[];
  licence: string;
}

export interface VictimRecord {
  activity: string | null;
  groupName: string;
  discoveredAt: string;
}

const PLAIN: Record<AdvisoryTag, string> = {
  AUSTRALIA: "Australia",
  INDIGENOUS: "First Nations organisations",
  COMMUNITY_SERVICES: "community organisations",
  HEALTHCARE: "health services",
  GOVERNMENT: "government and councils",
  CRITICAL_INFRASTRUCTURE: "essential services",
  SMB: "small organisations",
  FINANCE: "banking and payments",
  EDUCATION: "schools and education",
};

export function watchedTags(orgType: string): AdvisoryTag[] {
  return ["AUSTRALIA", ...(ORG_TYPE_TAGS[orgType] ?? ORG_TYPE_TAGS.other!)];
}

/** Ranks shared advisories for one organisation and explains each score in plain English. */
export function rankAdvisories(rows: AdvisoryRecord[], orgType: string) {
  const watched = new Set<string>(watchedTags(orgType));
  return rows
    .map((row) => {
      const reasons: string[] = [];
      let score = 0;
      if (row.sourceId.startsWith("acsc")) {
        score += 40;
        reasons.push("From the Australian Cyber Security Centre.");
      } else if (row.tags.includes("AUSTRALIA")) {
        score += 30;
        reasons.push("It mentions Australia.");
      }
      const sectors = row.tags.filter((tag) => tag !== "AUSTRALIA" && watched.has(tag)) as AdvisoryTag[];
      score += Math.min(2, sectors.length) * 20;
      if (sectors.length) reasons.push(`It is about ${sectors.map((tag) => PLAIN[tag]).join(" and ")}.`);
      if (row.tags.includes("INDIGENOUS")) score += 10;
      if (row.attackTechniques.includes("T1486")) {
        score += 10;
        reasons.push("It is linked to ransomware.");
      }
      if (row.attackTechniques.includes("T1566")) {
        score += 5;
        reasons.push("It is about phishing emails.");
      }
      return { ...row, relevance: Math.min(100, score), reasons };
    })
    .filter((row) => row.relevance > 0)
    .sort((a, b) => b.relevance - a.relevance || b.publishedAt.localeCompare(a.publishedAt));
}

/**
 * Sector-level view of ransomware listings in Australia. Victim names are
 * left out on purpose: the point is "groups like yours are being hit", not
 * naming other organisations.
 */
export function summariseRansomware(rows: VictimRecord[], orgType: string, now: Date) {
  const watched = new Set<string>(watchedTags(orgType));
  const since90 = now.getTime() - 90 * 86_400_000;
  const recent = rows.filter((row) => new Date(row.discoveredAt).getTime() >= since90);
  const bySector = new Map<string, number>();
  const groups = new Map<string, number>();
  let likeYou = 0;
  for (const row of recent) {
    const sector = row.activity ?? "Unknown";
    bySector.set(sector, (bySector.get(sector) ?? 0) + 1);
    groups.set(row.groupName, (groups.get(row.groupName) ?? 0) + 1);
    if (activityTags(row.activity).some((tag) => watched.has(tag))) likeYou += 1;
  }
  const top = (map: Map<string, number>) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count]) => ({ name, count }));
  return {
    days: 90,
    total: recent.length,
    similarSectors: likeYou,
    sectors: top(bySector),
    groups: top(groups),
    summary: recent.length === 0
      ? "No Australian ransomware listings were seen in the last 90 days."
      : `${recent.length} Australian organisations were listed on ransomware leak sites in the last 90 days. ${likeYou} were in sectors like yours.`,
  };
}
