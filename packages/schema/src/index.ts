/**
 * Core finding model. Every finding must carry provenance, a confidence
 * score, a factor breakdown, and a status that supports dismissal or challenge.
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
  confidenceFactors: ConfidenceFactor[];
  provenance: Provenance[];
  status: FindingStatus;
  stixRefs: string[];
  cultural?: boolean;
}

export function validateFinding(f: Finding): string[] {
  const errors: string[] = [];
  if (!f.tenantId) errors.push("tenantId is required");
  if (!f.id) errors.push("id is required");
  if (!f.provenance || f.provenance.length === 0) errors.push("at least one provenance record is required");
  for (const p of f.provenance ?? []) {
    if (!p.sourceId) errors.push("provenance sourceId is required");
    if (!p.collectedAt) errors.push("provenance collectedAt is required");
    if (!p.licence) errors.push("provenance licence is required");
    if (!p.accessRestriction) errors.push("provenance accessRestriction is required");
  }
  if (!Number.isInteger(f.confidence) || f.confidence < 0 || f.confidence > 100) {
    errors.push("confidence must be an integer from 0 to 100");
  }
  if (!f.confidenceFactors || f.confidenceFactors.length === 0) {
    errors.push("at least one confidence factor is required");
  }
  for (const factor of f.confidenceFactors ?? []) {
    if (!factor.code || !factor.reason) errors.push("confidence factor needs a code and a reason");
    if (!Number.isInteger(factor.points)) errors.push("confidence factor points must be an integer");
  }
  return errors;
}

export function createFinding(input: Omit<Finding, "status"> & { status?: FindingStatus }): Finding {
  const finding: Finding = { ...input, status: input.status ?? "open" };
  const errors = validateFinding(finding);
  if (errors.length > 0) throw new Error(errors.join("; "));
  return finding;
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

export function confidenceBand(confidence: number): "low" | "medium" | "high" {
  if (confidence >= 70) return "high";
  if (confidence >= 40) return "medium";
  return "low";
}

const RESTRICTED: TlpMarking[] = ["TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"];

export function evidenceIsRestricted(tlp: TlpMarking): boolean {
  return RESTRICTED.includes(tlp);
}

/** Flesch-Kincaid grade level. Year 8 is about grade 8. */
export function readingGrade(text: string): number {
  const sentences = text.split(/[.!?]+/).map((s) => s.trim()).filter(Boolean);
  const words = text.split(/\s+/).map((w) => w.replace(/[^A-Za-z']/g, "")).filter(Boolean);
  if (sentences.length === 0 || words.length === 0) return 99;
  const syllables = words.reduce((sum, word) => sum + countSyllables(word), 0);
  return 0.39 * (words.length / sentences.length) + 11.8 * (syllables / words.length) - 15.59;
}

export function wordCount(text: string): number {
  return text.split(/\s+/).filter(Boolean).length;
}

function countSyllables(word: string): number {
  const cleaned = word.toLowerCase().replace(/[^a-z]/g, "");
  if (!cleaned) return 1;
  if (cleaned.length <= 3) return 1;
  const groups = cleaned.replace(/e$/, "").match(/[aeiouy]+/g);
  return Math.max(1, groups?.length ?? 1);
}

export interface StixObject {
  type: string;
  id: string;
  spec_version?: string;
  confidence?: number;
  object_marking_refs?: string[];
  external_references?: Array<Record<string, string>>;
  [key: string]: unknown;
}

export interface IntelStore {
  upsert(obj: StixObject, tenantId: string | null): Promise<void>;
  get(id: string, tenantId: string | null): Promise<StixObject | null>;
  related(id: string, depth: number, tenantId: string | null): Promise<StixObject[]>;
  search(aliasTenantId: string, query: string): Promise<StixObject[]>;
}
