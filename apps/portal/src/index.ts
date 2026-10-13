import type { Finding } from "@community-cti/schema";

/** Placeholder for the community portal. Renders a finding as plain English. */
export function renderFindingText(f: Finding): string {
  return `${f.title}\n${f.plainEnglishSummary}\nConfidence: ${f.confidence}/100. Sources: ${f.provenance.map((p) => p.sourceId).join(", ")}`;
}
