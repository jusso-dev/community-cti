import {
  type ConfidenceFactor,
  type Finding,
  type Provenance,
  validateFinding,
} from "./model.js";

export interface CreateFindingInput {
  id: string;
  tenantId: string;
  kind: Finding["kind"];
  title: string;
  plainEnglishSummary: string;
  confidence: number;
  provenance: Provenance[];
  stixRefs: string[];
  confidenceFactors: ConfidenceFactor[];
  createdAt?: string;
  cultural?: boolean;
}

/** Build an open finding. Rejects missing provenance, factors, or an out-of-range score. */
export function createFinding(input: CreateFindingInput): Finding {
  const finding: Finding = {
    ...input,
    status: "open",
    confidenceFactors: input.confidenceFactors,
  };
  const errors = validateFinding(finding);
  if (!finding.confidenceFactors || finding.confidenceFactors.length === 0) {
    errors.push("at least one confidence factor is required");
  }
  if (errors.length > 0) {
    throw new Error(errors.join("; "));
  }
  return finding;
}
