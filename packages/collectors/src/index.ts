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

export { parseSourcesMarkdown, type SourceRow } from "./sources-doc.js";
export { runCollector, rawObjectKey, type SourceRecord } from "./runner.js";
export { registry, DEFERRED_SOURCE_IDS } from "./registry.js";
export { SOURCE_CRONS, registerSchedules, type JobQueue } from "./schedule.js";
export { normaliseUrl } from "./url-normalise.js";
export { RateLimiter, nvdLimit } from "./rate-limit.js";
export { tagSector } from "./sectors.js";
export { assertAllowListed, ACSC_HOSTS, RANSOM_HOSTS } from "./allow.js";
export { dropPasswordFields, toCredentialRecords } from "./sources/hibp-domain.js";
export { parseKev } from "./sources/cisa-kev.js";
export { parseNvd } from "./sources/nvd.js";
export { parseEpss } from "./sources/epss.js";
export { parseUrlhaus, parseOpenPhish, parsePhishTank } from "./sources/phishing.js";
export { parseAcscRss } from "./sources/acsc.js";
export { parseRansomwareReport } from "./sources/ransomware-reporting.js";
export { parseCertStream, backoffMs } from "./sources/certstream.js";
export { crtShUrl } from "./sources/crtsh.js";
export {
  parseThreatSieveEnvelope,
  storeThreatSieveObjects,
  threatSieveCollector,
  threatSieveObjectsUrl,
} from "./sources/threatsieve.js";
