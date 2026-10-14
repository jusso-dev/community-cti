import { createFinding, type Finding, type Provenance } from "@community-cti/schema";

const EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const PRIVATE_IP = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/g;

export interface SanitiseInput {
  text: string;
  tenantName: string;
  people: string[];
  internalHosts: string[];
}

export function sanitiseWarning(input: SanitiseInput): { text: string; removed: string[] } {
  let text = input.text;
  const removed: string[] = [];
  const replacements = [input.tenantName, ...input.people, ...input.internalHosts].filter((item) => item.trim().length > 0);
  for (const value of replacements) {
    const pattern = new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    if (pattern.test(text)) {
      removed.push(value);
      text = text.replace(pattern, "[removed]");
    }
  }
  text = text.replace(EMAIL, () => {
    removed.push("email");
    return "[removed]";
  });
  text = text.replace(PRIVATE_IP, () => {
    removed.push("private-ip");
    return "[removed]";
  });
  return { text, removed };
}

export interface ShareDecisionInput {
  categoryEnabled: boolean;
  itemApproved: boolean;
  approverId?: string;
  cultural: boolean;
}

export function decideShare(input: ShareDecisionInput): { ok: boolean; reason: string } {
  if (input.cultural) return { ok: false, reason: "cultural data cannot be shared" };
  if (!input.categoryEnabled) return { ok: false, reason: "this category is not opted in" };
  if (!input.itemApproved || !input.approverId) return { ok: false, reason: "each item needs a person's approval" };
  return { ok: true, reason: "approved" };
}

export function defaultSharingPreferences(): Array<{ category: string; enabled: boolean }> {
  return [
    { category: "phishing", enabled: false },
    { category: "lookalike", enabled: false },
    { category: "ransomware", enabled: false },
  ];
}

export function communityFinding(input: {
  id: string;
  tenantId: string;
  title: string;
  summary: string;
  confidence: number;
  factors: Finding["confidenceFactors"];
  collectedAt: string;
}): Finding {
  const provenance: Provenance[] = [{
    sourceId: "community",
    collectedAt: input.collectedAt,
    licence: "opt-in community warning",
    accessRestriction: "TLP:GREEN",
    evidenceRefs: [],
  }];
  return createFinding({
    id: input.id,
    tenantId: input.tenantId,
    kind: "phishing_campaign",
    title: input.title,
    plainEnglishSummary: input.summary,
    confidence: input.confidence,
    provenance,
    stixRefs: [],
    confidenceFactors: input.factors ?? [{ code: "community", points: input.confidence, reason: "A participating organisation approved this warning." }],
    createdAt: input.collectedAt,
  });
}
