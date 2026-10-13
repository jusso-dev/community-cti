import type { Provenance } from "@community-cti/schema";

/** Deterministic collector contract. Collectors never call an LLM. */
export interface Collector<T> {
  sourceId: string;
  collect(since: Date): Promise<Array<{ record: T; provenance: Provenance }>>;
}

/** Generate simple lookalike candidates (character omission and swap). */
export function lookalikeCandidates(domain: string): string[] {
  const [label, ...rest] = domain.split(".");
  const tld = rest.join(".");
  const out = new Set<string>();
  for (let i = 0; i < label.length; i++) {
    out.add(label.slice(0, i) + label.slice(i + 1) + "." + tld);
    if (i < label.length - 1) out.add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2) + "." + tld);
  }
  out.delete(domain);
  return [...out];
}
