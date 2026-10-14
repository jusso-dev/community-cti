import { createFinding, type Provenance } from "@community-cti/schema";

export interface ExposedService {
  host: string;
  ip: string;
  cpe: string;
  versionCertainty: "exact" | "inferred";
}

export interface KnownVuln {
  cve: string;
  cpe: string;
  kev: boolean;
  epss: number;
}

export interface ExposureFinding {
  rank: number;
  cve: string;
  kev: boolean;
  epss: number;
  confidence: number;
  finding: ReturnType<typeof createFinding>;
}

export function correlateExposure(input: {
  tenantId: string;
  services: ExposedService[];
  vulns: KnownVuln[];
  verifiedHosts: string[];
  provenance: Provenance;
  now: string;
}): ExposureFinding[] {
  const allowed = new Set(input.verifiedHosts.map((host) => host.toLowerCase()));
  const findings: ExposureFinding[] = [];
  for (const service of input.services) {
    if (!allowed.has(service.host.toLowerCase())) {
      throw new Error(`refusing exposure lookup for unverified host ${service.host}`);
    }
    for (const vuln of input.vulns.filter((item) => item.cpe === service.cpe)) {
      const confidence = service.versionCertainty === "exact" ? 80 : 55;
      const factors = [
        {
          code: service.versionCertainty === "exact" ? "banner_exact" : "version_inferred",
          points: confidence,
          reason: service.versionCertainty === "exact"
            ? "The service banner matches a known vulnerable version."
            : "The version was inferred, so this is a medium confidence match.",
        },
      ];
      if (vuln.kev) factors.push({ code: "kev", points: 0, reason: "This flaw is on the known exploited list, so it is ranked first." });
      const rank = vuln.kev ? 0 : vuln.epss > 0.1 ? 1 : 2;
      findings.push({
        rank,
        cve: vuln.cve,
        kev: vuln.kev,
        epss: vuln.epss,
        confidence,
        finding: createFinding({
          id: `${service.host}-${vuln.cve}`,
          tenantId: input.tenantId,
          kind: "exposed_service",
          title: `${service.host} may be affected by ${vuln.cve}`,
          plainEnglishSummary: "A public service on a domain you verified matches a known flaw.",
          confidence,
          provenance: [input.provenance],
          stixRefs: [],
          confidenceFactors: factors,
          createdAt: input.now,
        }),
      });
    }
  }
  return findings.sort((a, b) => a.rank - b.rank || b.epss - a.epss);
}
