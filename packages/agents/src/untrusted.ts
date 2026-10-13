/** Marks collector text so a model treats it as data, not as instructions. */
export function wrapUntrusted(sourceId: string, text: string): string {
  const safeId = sourceId.replace(/[^a-zA-Z0-9_-]/g, "") || "source";
  return `<<<UNTRUSTED source=${safeId}>>>\n${text}\n<<<END UNTRUSTED>>>`;
}

export function containsUntrustedMarkers(text: string): boolean {
  return text.includes("<<<UNTRUSTED") || text.includes("<<<END UNTRUSTED>>>");
}
