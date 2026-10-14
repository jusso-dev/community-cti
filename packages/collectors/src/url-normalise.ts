import { domainToUnicode } from "node:url";
import { getDomain } from "tldts";

const TRACKING = /^(utm_|fbclid$|gclid$|mc_cid$|mc_eid$)/i;

export function normaliseUrl(input: string): {
  url: string;
  host: string;
  unicodeHost: string;
  registeredDomain: string | null;
} {
  const parsed = new URL(input);
  parsed.hostname = parsed.hostname.toLowerCase();
  const unicodeHost = domainToUnicode(parsed.hostname);
  const kept = [...parsed.searchParams.entries()].filter(([key]) => !TRACKING.test(key));
  parsed.search = "";
  for (const [key, value] of kept) parsed.searchParams.append(key, value);
  if (unicodeHost !== parsed.hostname) parsed.hostname = parsed.hostname;
  return {
    url: parsed.toString(),
    host: parsed.hostname,
    unicodeHost,
    registeredDomain: getDomain(unicodeHost, { allowPrivateDomains: false }),
  };
}
