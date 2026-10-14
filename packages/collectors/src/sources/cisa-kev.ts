import { buildVulnerability, type StixObject } from "@community-cti/schema";

export interface KevFeed {
  vulnerabilities: Array<{
    cveID: string;
    vulnerabilityName: string;
    shortDescription: string;
    dateAdded: string;
    knownRansomwareCampaignUse?: string;
  }>;
}

export function parseKev(feed: KevFeed, collectedAt: Date): StixObject[] {
  return feed.vulnerabilities.map((entry) =>
    buildVulnerability({
      sourceId: "cisa-kev",
      licence: "US government public domain",
      sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      collectedAt,
      confidence: 90,
      name: entry.vulnerabilityName,
      description: entry.shortDescription,
      cve: entry.cveID,
      extra: {
        x_kev: true,
        x_date_added: entry.dateAdded,
        x_known_ransomware: entry.knownRansomwareCampaignUse === "Known",
      },
    }),
  );
}
