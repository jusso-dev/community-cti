import type { Provenance, StixObject } from "@community-cti/schema";
import { buildNote } from "@community-cti/schema/stix";
import { lookupDns, type DnsResolver } from "./dns.js";
import { fetchRdap } from "./rdap.js";
import { fetchPublicPage, murmur3 } from "./http.js";

export interface Enrichment {
  ok: boolean;
  error?: string;
  resolves?: boolean;
  hasMx?: boolean;
  ageDays?: number | null;
  contentSha256?: string;
  faviconHash?: number;
  faviconMatch?: boolean;
  provenance: Provenance;
}

export async function enrichDomain(input: {
  domain: string;
  now: Date;
  resolver: DnsResolver;
  resolveHost: (host: string) => Promise<string[]>;
  fetchImpl: (url: string, init?: RequestInit) => Promise<Response>;
  realFavicon?: Uint8Array;
}): Promise<Enrichment> {
  const provenance: Provenance = {
    sourceId: "crtsh",
    sourceUrl: `https://${input.domain}/`,
    collectedAt: input.now.toISOString(),
    licence: "public DNS, RDAP and HTTP",
    accessRestriction: "TLP:CLEAR",
    evidenceRefs: [],
  };
  try {
    const dns = await lookupDns(input.domain, input.resolver);
    const rdap = await fetchRdap(input.domain, input.fetchImpl, input.now);
    const page = await fetchPublicPage({
      url: `https://${input.domain}/`,
      resolve: input.resolveHost,
      fetchImpl: input.fetchImpl,
    });
    let faviconHash: number | undefined;
    let faviconMatch = false;
    if (page.body) {
      const href = /rel=["']icon["'][^>]*href=["']([^"']+)["']/i.exec(page.body)?.[1];
      if (href) {
        const icon = await fetchPublicPage({
          url: new URL(href, `https://${input.domain}/`).toString(),
          resolve: input.resolveHost,
          fetchImpl: input.fetchImpl,
        });
        if (icon.body) {
          faviconHash = murmur3(new TextEncoder().encode(icon.body));
          if (input.realFavicon) faviconMatch = faviconHash === murmur3(input.realFavicon);
        }
      }
    }
    if (page.sha256) provenance.evidenceRefs.push(page.sha256);
    return {
      ok: true,
      resolves: dns.resolves,
      hasMx: dns.hasMx,
      ageDays: rdap.ageDays,
      contentSha256: page.sha256,
      faviconHash,
      faviconMatch,
      provenance,
      error: page.ok ? undefined : page.error,
    };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "enrichment failed", provenance };
  }
}

/** Stores enrichment as a STIX note linked to the domain object. */
export function enrichmentNote(enrichment: Enrichment, objectRef: string, now: string): StixObject {
  const age = enrichment.ageDays == null ? "unknown" : String(enrichment.ageDays);
  return buildNote({
    content: `The name resolves: ${Boolean(enrichment.resolves)}. It has mail: ${Boolean(enrichment.hasMx)}. Age in days: ${age}.`,
    objectRefs: [objectRef],
    source: {
      sourceId: enrichment.provenance.sourceId,
      url: enrichment.provenance.sourceUrl,
      licence: enrichment.provenance.licence,
      tlp: "TLP:CLEAR",
    },
    now,
  });
}
