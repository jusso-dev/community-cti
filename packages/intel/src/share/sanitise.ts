import { createFinding, type Finding, type Provenance } from "@community-cti/schema";

export interface SanitiseInput {
  text: string;
  names: string[];
  people: string[];
  emails: string[];
  hosts: string[];
}

export function sanitiseText(input: SanitiseInput): string {
  const needles = [...input.names, ...input.people, ...input.emails, ...input.hosts]
    .map((value) => value.trim())
    .filter((value) => value.length >= 3)
    .sort((a, b) => b.length - a.length);
  let text = input.text;
  for (const needle of needles) {
    text = text.replace(new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi"), "[removed]");
  }
  text = text.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[removed]");
  return text;
}

export interface ShareRequest {
  cultural: boolean;
  categoryEnabled: boolean;
  approvedBy?: string;
  approvedAt?: string;
  launchApproved: boolean;
  tenantId: string;
  findingId: string;
  confidence: number;
  factors: Finding["confidenceFactors"];
  text: string;
  secrets: Omit<SanitiseInput, "text">;
}

export function prepareShare(input: ShareRequest): Finding {
  if (!input.launchApproved) throw new Error("sharing is blocked until the governance group endorses the rules");
  if (input.cultural) throw new Error("cultural data cannot be shared");
  if (!input.categoryEnabled) throw new Error("sharing is off for this category");
  if (!input.approvedBy || !input.approvedAt) throw new Error("each shared item needs approval");
  const provenance: Provenance[] = [{
    sourceId: "community",
    sourceUrl: "community-share",
    collectedAt: input.approvedAt,
    licence: "opt-in community warning",
    accessRestriction: "TLP:GREEN",
    evidenceRefs: [input.findingId],
  }];
  return createFinding({
    id: `shared-${input.findingId}`,
    tenantId: input.tenantId,
    kind: "phishing_campaign",
    title: "A community warning",
    plainEnglishSummary: sanitiseText({ text: input.text, ...input.secrets }),
    confidence: input.confidence,
    confidenceFactors: input.factors,
    provenance,
    stixRefs: [],
  });
}
