import type { Finding } from "@community-cti/schema";
import { capConfidence, rejectUnsafeOutput, runAgent, type ModelProvider } from "./runtime.js";
import { wrapUntrusted } from "./untrusted.js";

export interface InvestigatorOutput {
  findingId: string;
  supporting: string[];
  contradicting: string[];
  proposedConfidence: number;
  reasons: string[];
  needsReview: boolean;
}

export async function investigate(options: {
  finding: Finding;
  evidenceIds: string[];
  untrustedText: string;
  sourceId: string;
  model: ModelProvider;
  budget: { monthlyAud: number; spentAud: number };
  cultural?: boolean;
}): Promise<{ output: InvestigatorOutput | null; status: string; changedStatus: false }> {
  const result = await runAgent({
    role: "investigator",
    tenantId: options.finding.tenantId,
    evidenceIds: options.evidenceIds,
    budget: options.budget,
    model: options.model,
    cultural: options.cultural,
    input: `${wrapUntrusted(options.untrustedText, options.sourceId)}\nFinding ${options.finding.id}`,
    validate: (output, evidenceIds) => {
      const errors = rejectUnsafeOutput(output, evidenceIds, options.finding.tenantId);
      const record = output as { supporting?: unknown; contradicting?: unknown; proposedConfidence?: unknown; reasons?: unknown };
      if (!Array.isArray(record.supporting) || !Array.isArray(record.contradicting) || !Array.isArray(record.reasons)) {
        errors.push("investigator shape");
      }
      if (!Number.isInteger(record.proposedConfidence)) errors.push("confidence must be an integer");
      return errors;
    },
  });
  if (result.status !== "ok" || !result.output) return { output: null, status: result.status, changedStatus: false };
  const raw = result.output as { supporting: string[]; contradicting: string[]; proposedConfidence: number; reasons: string[] };
  const capped = capConfidence(options.finding.confidence, raw.proposedConfidence);
  return {
    status: "ok",
    changedStatus: false,
    output: {
      findingId: options.finding.id,
      supporting: raw.supporting,
      contradicting: raw.contradicting,
      proposedConfidence: capped.confidence,
      reasons: raw.reasons,
      needsReview: capped.needsReview,
    },
  };
}
