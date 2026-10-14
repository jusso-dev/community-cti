import type { Finding } from "@community-cti/schema";
import { fleschKincaidGrade, wordCount } from "@community-cti/notify";
import { runAgent, type ModelProvider } from "./runtime.js";

export interface AnalystStep {
  text: string;
  requiresApproval: boolean;
}

export interface AnalystDraft {
  summary: string;
  whyItMatters: string;
  steps: AnalystStep[];
  confidenceExplanation: string;
}

const SYSTEM_CHANGE = /block|reset password|delete|disable|takedown|remove the account/i;

export function flagApproval(steps: AnalystStep[]): AnalystStep[] {
  return steps.map((step) => ({
    ...step,
    requiresApproval: step.requiresApproval || SYSTEM_CHANGE.test(step.text),
  }));
}

export function plainFallback(finding: Finding): AnalystDraft {
  return {
    summary: "We found a possible threat that matches your organisation. Please read the sources before you act.",
    whyItMatters: "It may affect your staff or the people you serve.",
    steps: [
      { text: "Read the sources on the finding.", requiresApproval: false },
      { text: "Ask your IT helper what to change.", requiresApproval: false },
    ],
    confidenceExplanation: `Our confidence is ${finding.confidence} out of 100. Sources: ${finding.provenance.map((item) => item.sourceId).join(", ")}.`,
  };
}

export function assessDraft(draft: AnalystDraft, finding: Finding): string[] {
  const errors: string[] = [];
  if (wordCount(draft.summary) > 80) errors.push("summary is over 80 words");
  if (fleschKincaidGrade(`${draft.summary} ${draft.whyItMatters}`) > 8) errors.push("reading level");
  const sourceIds = finding.provenance.map((item) => item.sourceId);
  if (!sourceIds.some((id) => draft.confidenceExplanation.includes(id) || draft.summary.includes(id))) {
    errors.push("sources not cited");
  }
  return errors;
}

export async function analyse(options: {
  finding: Finding;
  model: ModelProvider;
  budget: { monthlyAud: number; spentAud: number };
}): Promise<AnalystDraft> {
  let attempts = 0;
  const result = await runAgent({
    role: "analyst",
    tenantId: options.finding.tenantId,
    evidenceIds: options.finding.provenance.flatMap((item) => item.evidenceRefs),
    budget: options.budget,
    model: {
      ...options.model,
      async complete(request) {
        attempts += 1;
        const response = await options.model.complete(request);
        return response;
      },
    },
    input: JSON.stringify({
      findingId: options.finding.id,
      sources: options.finding.provenance.map((item) => item.sourceId),
      summary: options.finding.plainEnglishSummary,
    }),
    validate: (output) => {
      const draft = output as AnalystDraft;
      if (!draft?.summary || !Array.isArray(draft.steps)) return ["bad draft"];
      const flagged = { ...draft, steps: flagApproval(draft.steps) };
      const errors = assessDraft(flagged, options.finding);
      if (errors.length > 0 && attempts < 2) return errors;
      return [];
    },
  });
  if (result.status !== "ok" || !result.output) return plainFallback(options.finding);
  const draft = result.output as AnalystDraft;
  const flagged = { ...draft, steps: flagApproval(draft.steps) };
  if (assessDraft(flagged, options.finding).length > 0) return plainFallback(options.finding);
  return flagged;
}
