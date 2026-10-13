import { domainToUnicode } from "node:url";

const MULTI_PART_SUFFIXES = new Set([
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  "co.uk", "org.uk", "gov.uk", "co.nz", "net.nz", "org.nz", "com.br",
]);

const TRACKING = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid"]);

export function registeredDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (labels.length < 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo) && labels.length >= 3) return labels.slice(-3).join(".");
  return lastTwo;
}

export function normaliseUrl(raw: string): { url: string; unicodeHost: string; registeredDomain: string } {
  const parsed = new URL(raw);
  const unicodeHost = domainToUnicode(parsed.hostname.toLowerCase());
  parsed.hash = "";
  for (const key of [...parsed.searchParams.keys()]) {
    if (TRACKING.has(key.toLowerCase())) parsed.searchParams.delete(key);
  }
  return { url: parsed.toString(), unicodeHost, registeredDomain: registeredDomain(unicodeHost) };
}

export function assertAllowedHost(url: string, allowed: readonly string[]): void {
  const host = new URL(url).host;
  if (!allowed.includes(host)) throw new Error(`host not allow-listed: ${host}`);
}
