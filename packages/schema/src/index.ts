/**
 * Core finding model. Every finding must carry provenance, a confidence
 * score and a status that supports dismissal or challenge.
 */
export type TlpMarking = "TLP:CLEAR" | "TLP:GREEN" | "TLP:AMBER" | "TLP:AMBER+STRICT" | "TLP:RED";

export interface Provenance {
  sourceId: string;          // id from docs/SOURCES.md inventory
  sourceUrl?: string;
  collectedAt: string;       // ISO 8601
  licence: string;           // licence or terms reference
  accessRestriction: TlpMarking;
  evidenceRefs: string[];    // object storage keys or URLs
}

export type FindingStatus = "open" | "acknowledged" | "dismissed" | "challenged" | "resolved";

export interface Finding {
  id: string;
  tenantId: string;
  kind: "lookalike_domain" | "credential_exposure" | "exposed_service" | "ransomware_mention" | "phishing_campaign";
  title: string;
  plainEnglishSummary: string;
  confidence: number;        // 0 to 100, see docs/ARCHITECTURE.md
  provenance: Provenance[];
  status: FindingStatus;
  stixRefs: string[];        // STIX 2.1 ids in the intelligence graph
}

export function validateFinding(f: Finding): string[] {
  const errors: string[] = [];
  if (!f.tenantId) errors.push("tenantId is required");
  if (f.provenance.length === 0) errors.push("at least one provenance record is required");
  if (!Number.isInteger(f.confidence) || f.confidence < 0 || f.confidence > 100) errors.push("confidence must be an integer from 0 to 100");
  return errors;
}

export function canTransition(from: FindingStatus, to: FindingStatus): boolean {
  const allowed: Record<FindingStatus, FindingStatus[]> = {
    open: ["acknowledged", "dismissed", "challenged", "resolved"],
    acknowledged: ["dismissed", "challenged", "resolved"],
    challenged: ["open", "dismissed"],
    dismissed: ["open"],
    resolved: ["open"],
  };
  return allowed[from].includes(to);
}
