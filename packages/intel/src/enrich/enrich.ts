import { createHash } from "node:crypto";
import { buildNote, type StixObject } from "@community-cti/schema";
import { mmh3 } from "./mmh3.js";
import { safeFetch, type SafeFetchResult } from "./ssrf.js";

export interface DnsAnswer {
  a: string[];
  aaaa: string[];
  mx: string[];
}

export interface Enrichment {
  domain: string;
  resolves: boolean;
  hasMx: boolean;
  registeredDaysAgo: number | null;
  parked: boolean;
  contentSha256: string | null;
  faviconHash: number | null;
  faviconMatch: boolean;
  note: StixObject | null;
  errors: string[];
}

export function enrichmentAllowed(domain: string, verified: string[], lookalikes: string[]): boolean {
  const value = domain.toLowerCase();
  return verified.map((item) => item.toLowerCase()).includes(value) || lookalikes.map((item) => item.toLowerCase()).includes(value);
}

export function isParked(html: string): boolean {
  return /parked|buy this domain|domain for sale|hugedomains|sedo\.com/i.test(html);
}

export async function enrichDomain(options: {
  domain: string;
  verified: string[];
  lookalikes: string[];
  now: Date;
  lookupDns: (domain: string) => Promise<DnsAnswer>;
  fetchRdap: (domain: string) => Promise<{ registration?: string } | null>;
  fetchPage: (url: string) => Promise<SafeFetchResult>;
  tenantFaviconHash?: number | null;
  domainObjectId: string;
}): Promise<Enrichment> {
  if (!enrichmentAllowed(options.domain, options.verified, options.lookalikes)) {
    throw new Error(`enrichment refused for ${options.domain}; only verified domains and discovered lookalikes are allowed`);
  }
  const errors: string[] = [];
  let dns: DnsAnswer = { a: [], aaaa: [], mx: [] };
  try {
    dns = await options.lookupDns(options.domain);
  } catch {
    errors.push("dns failed");
  }
  let registeredDaysAgo: number | null = null;
  try {
    const rdap = await options.fetchRdap(options.domain);
    if (rdap?.registration) {
      const age = options.now.getTime() - new Date(rdap.registration).getTime();
      registeredDaysAgo = Math.floor(age / 86_400_000);
    }
  } catch {
    errors.push("rdap failed");
  }
  let body = "";
  let contentSha256: string | null = null;
  let faviconHash: number | null = null;
  try {
    const page = await options.fetchPage(`https://${options.domain}/`);
    if (!page.ok) errors.push(page.error ?? "http failed");
    else {
      body = page.body ?? "";
      contentSha256 = createHash("sha256").update(body).digest("hex");
      const icon = body.match(/<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["']/i)?.[1];
      if (icon) {
        const iconUrl = new URL(icon, `https://${options.domain}/`).toString();
        const iconPage = await options.fetchPage(iconUrl);
        if (iconPage.ok && iconPage.body) {
          faviconHash = mmh3(new TextEncoder().encode(iconPage.body));
        }
      }
    }
  } catch (error) {
    errors.push(error instanceof Error && error.name === "TimeoutError" ? "timeout" : "http failed");
  }
  const note = buildNote({
    sourceId: "crtsh",
    licence: "public DNS, RDAP and page hash",
    collectedAt: options.now,
    confidence: 40,
    content: `DNS ${dns.a.length + dns.aaaa.length > 0 ? "resolves" : "does not resolve"}. MX ${dns.mx.length > 0 ? "present" : "absent"}.`,
    objectRefs: [options.domainObjectId],
  });
  return {
    domain: options.domain,
    resolves: dns.a.length + dns.aaaa.length > 0,
    hasMx: dns.mx.length > 0,
    registeredDaysAgo,
    parked: body ? isParked(body) : false,
    contentSha256,
    faviconHash,
    faviconMatch: faviconHash !== null && options.tenantFaviconHash !== undefined && faviconHash === options.tenantFaviconHash,
    note,
    errors,
  };
}

export { safeFetch };
