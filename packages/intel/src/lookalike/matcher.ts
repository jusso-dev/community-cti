import { lookalikeCandidates } from "@community-cti/collectors";
import { foldHomoglyphs, homoglyphVariants } from "./homoglyph.js";

export interface WatchedDomain {
  tenantId: string;
  domain: string;
  verified: boolean;
  brandKeywords?: string[];
}

export interface CertMatch {
  tenantId: string;
  watched: string;
  domain: string;
  reason: "omission" | "swap" | "homoglyph" | "keyword";
}

interface Entry {
  tenantId: string;
  watched: string;
  reason: CertMatch["reason"];
}

export interface LookalikeMatcher {
  match(name: string): CertMatch[];
}

export function buildMatcher(domains: WatchedDomain[]): LookalikeMatcher {
  const exact = new Map<string, Entry>();
  const folded = new Map<string, Entry>();
  const keywords: Array<{ tenantId: string; watched: string; keyword: string }> = [];
  for (const item of domains) {
    if (!item.verified) continue;
    const domain = item.domain.toLowerCase();
    folded.set(foldHomoglyphs(domain), { tenantId: item.tenantId, watched: domain, reason: "homoglyph" });
    for (const candidate of lookalikeCandidates(domain)) {
      const [left, right] = [candidate.split(".")[0] ?? "", domain.split(".")[0] ?? ""];
      const reason: Entry["reason"] = left.length < right.length ? "omission" : "swap";
      exact.set(candidate, { tenantId: item.tenantId, watched: domain, reason });
    }
    for (const variant of homoglyphVariants(domain)) {
      exact.set(variant, { tenantId: item.tenantId, watched: domain, reason: "homoglyph" });
    }
    for (const keyword of item.brandKeywords ?? []) {
      if (keyword.trim().length >= 4) keywords.push({ tenantId: item.tenantId, watched: domain, keyword: keyword.toLowerCase() });
    }
  }
  return {
    match(name: string): CertMatch[] {
      const domain = name.toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
      const hits: CertMatch[] = [];
      const direct = exact.get(domain);
      if (direct) hits.push({ ...direct, domain });
      const foldedHit = folded.get(foldHomoglyphs(domain));
      if (foldedHit && foldedHit.watched !== domain && !hits.some((hit) => hit.watched === foldedHit.watched)) {
        hits.push({ ...foldedHit, domain });
      }
      const label = domain.split(".")[0] ?? "";
      for (const keyword of keywords) {
        if (domain === keyword.watched) continue;
        if (label.includes(keyword.keyword) && !hits.some((hit) => hit.watched === keyword.watched && hit.reason === "keyword")) {
          hits.push({ tenantId: keyword.tenantId, watched: keyword.watched, domain, reason: "keyword" });
        }
      }
      return hits;
    },
  };
}
