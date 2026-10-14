/**
 * Core finding model. Every finding must carry provenance, a confidence
 * score and a status that supports dismissal or challenge.
 */
export type TlpMarking = "TLP:CLEAR" | "TLP:GREEN" | "TLP:AMBER" | "TLP:AMBER+STRICT" | "TLP:RED";

export interface Provenance {
  sourceId: string;
  sourceUrl?: string;
  collectedAt: string;
  licence: string;
  accessRestriction: TlpMarking;
  evidenceRefs: string[];
}

export type FindingStatus = "open" | "acknowledged" | "dismissed" | "challenged" | "resolved";

export type FindingKind =
  | "lookalike_domain"
  | "credential_exposure"
  | "exposed_service"
  | "ransomware_mention"
  | "phishing_campaign";

export interface ConfidenceFactor {
  code: string;
  points: number;
  reason: string;
}

export interface Finding {
  id: string;
  tenantId: string;
  kind: FindingKind;
  title: string;
  plainEnglishSummary: string;
  confidence: number;
  provenance: Provenance[];
  status: FindingStatus;
  stixRefs: string[];
  confidenceFactors?: ConfidenceFactor[];
  createdAt?: string;
  cultural?: boolean;
}

export function validateFinding(f: Finding): string[] {
  const errors: string[] = [];
  if (!f.tenantId) errors.push("tenantId is required");
  if (!f.provenance || f.provenance.length === 0) errors.push("at least one provenance record is required");
  else {
    for (const [i, p] of f.provenance.entries()) {
      if (!p.sourceId) errors.push(`provenance[${i}].sourceId is required`);
      if (!p.collectedAt) errors.push(`provenance[${i}].collectedAt is required`);
      if (!p.licence) errors.push(`provenance[${i}].licence is required`);
      if (!p.accessRestriction) errors.push(`provenance[${i}].accessRestriction is required`);
    }
  }
  if (!Number.isInteger(f.confidence) || f.confidence < 0 || f.confidence > 100) {
    errors.push("confidence must be an integer from 0 to 100");
  }
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

export const DISMISS_REASONS = [
  "not_ours",
  "already_handled",
  "legitimate_domain",
  "not_relevant",
  "other",
] as const;

export type DismissReason = (typeof DISMISS_REASONS)[number];

export function isDismissReason(value: string): value is DismissReason {
  return (DISMISS_REASONS as readonly string[]).includes(value);
}
