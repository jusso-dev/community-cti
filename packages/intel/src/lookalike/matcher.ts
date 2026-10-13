import { lookalikeCandidates } from "@community-cti/collectors";

const CONFUSABLES: Record<string, string> = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
  "@": "a", "$": "s",
  "і": "i", "í": "i", "ì": "i", "ï": "i", "ı": "i",
  "о": "o", "ο": "o",
  "а": "a", "е": "e", "р": "p", "с": "c", "х": "x", "у": "y",
};

export interface WatchedDomain {
  domain: string;
  brand?: string;
  verified: boolean;
}

export interface LookalikeHit {
  watched: string;
  kind: "omission" | "swap" | "homoglyph" | "brand";
}

export function skeleton(value: string): string {
  return [...value.toLowerCase()].map((char) => CONFUSABLES[char] ?? char).join("");
}

export function buildMatcher(domains: WatchedDomain[]) {
  const exact = new Map<string, { watched: string; kind: LookalikeHit["kind"] }>();
  const brands: Array<{ brand: string; watched: string }> = [];
  for (const row of domains) {
    if (!row.verified) continue;
    const domain = row.domain.toLowerCase();
    const [label, ...rest] = domain.split(".");
    const suffix = rest.join(".");
    if (!label || !suffix) continue;
    for (const candidate of lookalikeCandidates(domain)) {
      const candidateLabel = candidate.split(".")[0] ?? "";
      const kind = candidateLabel.length < label.length ? "omission" : "swap";
      exact.set(candidate, { watched: domain, kind });
    }
    for (let i = 0; i < label.length; i++) {
      const mapped = CONFUSABLES[label[i] ?? ""];
      if (!mapped || mapped === label[i]) continue;
      const variant = `${label.slice(0, i)}${Object.entries(CONFUSABLES).find(([, base]) => base === label[i])?.[0] ?? label[i]}${label.slice(i + 1)}.${suffix}`;
      exact.set(variant, { watched: domain, kind: "homoglyph" });
    }
    exact.set(skeleton(label) + "." + suffix, { watched: domain, kind: "homoglyph" });
    if (row.brand) brands.push({ brand: row.brand.toLowerCase(), watched: domain });
  }
  return {
    match(name: string): LookalikeHit | null {
      const host = name.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
      if (exact.has(host) && !domains.some((row) => row.verified && row.domain.toLowerCase() === host)) {
        const hit = exact.get(host);
        if (hit && hit.watched !== host) return hit;
      }
      const labels = host.split(".");
      for (const brand of brands) {
        if (labels.includes(brand.brand) && !host.endsWith(brand.watched) && host !== brand.watched) {
          return { watched: brand.watched, kind: "brand" };
        }
      }
      const skel = skeleton(labels[0] ?? "") + "." + labels.slice(1).join(".");
      const bySkeleton = exact.get(skel);
      if (bySkeleton && bySkeleton.watched !== host) return { watched: bySkeleton.watched, kind: "homoglyph" };
      return null;
    },
  };
}
