export interface AssetDomain {
  name: string;
  verified: boolean;
}

export interface ExposureRecord {
  id: string;
  host: string;
  cve: string;
  kev: boolean;
  epss: number;
  versionCertainty: "exact" | "inferred";
}

/** Passive lookup only. This module does not scan ports or send probes. */
export function domainsToQuery(domains: AssetDomain[]): string[] {
  return domains.filter((domain) => domain.verified).map((domain) => domain.name.toLowerCase());
}

export function confidenceForCertainty(certainty: ExposureRecord["versionCertainty"]): number {
  return certainty === "exact" ? 80 : 55;
}

export function rankExposures(items: ExposureRecord[]): ExposureRecord[] {
  return [...items].sort((left, right) => {
    if (left.kev !== right.kev) return left.kev ? -1 : 1;
    const leftHot = left.epss > 0.1;
    const rightHot = right.epss > 0.1;
    if (leftHot !== rightHot) return rightHot ? 1 : -1;
    return right.epss - left.epss;
  });
}

export interface ExposureProvider {
  lookupIp(ip: string): Promise<Array<{ port: number; product: string; version?: string }>>;
}

export async function correlateExposures(input: {
  domains: AssetDomain[];
  resolve: (host: string) => Promise<string[]>;
  provider: ExposureProvider;
  cves: Array<{ product: string; cve: string; kev: boolean; epss: number; version?: string }>;
}): Promise<ExposureRecord[]> {
  const records: ExposureRecord[] = [];
  for (const domain of domainsToQuery(input.domains)) {
    const ips = await input.resolve(domain);
    for (const ip of ips) {
      const services = await input.provider.lookupIp(ip);
      for (const service of services) {
        const match = input.cves.find((cve) => cve.product.toLowerCase() === service.product.toLowerCase());
        if (!match) continue;
        const certainty = service.version && match.version && service.version === match.version ? "exact" : "inferred";
        records.push({
          id: `${ip}:${service.port}:${match.cve}`,
          host: domain,
          cve: match.cve,
          kev: match.kev,
          epss: match.epss,
          versionCertainty: certainty,
        });
      }
    }
  }
  return rankExposures(records);
}
