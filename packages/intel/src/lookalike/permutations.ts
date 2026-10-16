import { normaliseUrl } from "@community-cti/collectors";
import { homoglyphVariants } from "./homoglyph.js";

export type PermutationReason = "omission" | "swap" | "typo" | "homoglyph" | "tld-swap" | "keyword";

export interface Permutation {
  domain: string;
  reason: PermutationReason;
}

/** Endings people mix up for Australian organisations, plus the common global ones. */
export const AU_SUFFIXES = ["com.au", "net.au", "org.au", "asn.au", "id.au", "au", "com", "net", "org"];
export const BRAND_PREFIXES = ["my"];
export const BRAND_SUFFIXES = ["-login", "-secure", "-au", "portal", "-portal", "-online", "-signin"];
export const DEFAULT_PERMUTATION_LIMIT = 600;

const QWERTY: Record<string, string> = {
  "1": "2q", "2": "3wq1", "3": "4ew2", "4": "5re3", "5": "6tr4", "6": "7yt5", "7": "8uy6", "8": "9iu7", "9": "0oi8", "0": "po9",
  q: "12wa", w: "3esaq2", e: "4rdsw3", r: "5tfde4", t: "6ygfr5", y: "7uhgt6", u: "8ijhy7", i: "9okju8", o: "0plki9", p: "lo0",
  a: "qwsz", s: "edxzaw", d: "rfcxse", f: "tgvcdr", g: "yhbvft", h: "ujnbgy", j: "ikmnhu", k: "olmji", l: "kop",
  z: "asx", x: "zsdc", c: "xdfv", v: "cfgb", b: "vghn", n: "bhjm", m: "njk",
};
const VOWELS = "aeiou";
const VALID = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/** Split a domain into its first registrable label and the public suffix after it. */
export function splitDomain(domain: string): { label: string; suffix: string } | null {
  const value = domain.toLowerCase().replace(/\.$/, "");
  let registered: string | null = null;
  try {
    registered = normaliseUrl(`http://${value}/`).registeredDomain;
  } catch {
    return null;
  }
  if (!registered) return null;
  const [label, ...rest] = registered.split(".");
  if (!label || rest.length === 0) return null;
  return { label, suffix: rest.join(".") };
}

/**
 * The brand a tenant actually verified. A registrable domain gives its own
 * label and suffix. A verified subdomain gives only its first label, placed
 * under the public suffix: the parent's labels belong to someone else.
 */
export function brandOf(domain: string): { label: string; suffix: string; registrable: boolean } | null {
  const value = domain.toLowerCase().replace(/\.$/, "");
  const parts = splitDomain(value);
  if (!parts) return null;
  if (value === `${parts.label}.${parts.suffix}`) return { ...parts, registrable: true };
  const label = value.split(".")[0] ?? "";
  return { label, suffix: parts.suffix, registrable: false };
}

/** Subdomain labels shorter than this (www, mail, crm) are too generic to treat as a brand. */
const MIN_SUBDOMAIN_BRAND = 4;

function labelEdits(label: string): Array<[string, PermutationReason]> {
  const out: Array<[string, PermutationReason]> = [];
  for (let i = 0; i < label.length; i++) {
    out.push([label.slice(0, i) + label.slice(i + 1), "omission"]);
    if (i < label.length - 1) out.push([label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2), "swap"]);
  }
  for (let i = 0; i < label.length; i++) {
    const char = label[i]!;
    out.push([label.slice(0, i) + char + label.slice(i), "typo"]);
    for (const key of QWERTY[char] ?? "") {
      out.push([label.slice(0, i) + key + label.slice(i + 1), "typo"]);
      out.push([label.slice(0, i) + key + label.slice(i), "typo"]);
      out.push([label.slice(0, i + 1) + key + label.slice(i + 1), "typo"]);
    }
    if (VOWELS.includes(char)) {
      for (const vowel of VOWELS) if (vowel !== char) out.push([label.slice(0, i) + vowel + label.slice(i + 1), "typo"]);
    }
    if (i > 0) out.push([`${label.slice(0, i)}-${label.slice(i)}`, "typo"]);
    const code = char.charCodeAt(0);
    for (let bit = 0; bit < 8; bit++) {
      const flipped = String.fromCharCode(code ^ (1 << bit));
      if (/^[a-z0-9]$/.test(flipped)) out.push([label.slice(0, i) + flipped + label.slice(i + 1), "typo"]);
    }
  }
  return out;
}

/**
 * dnstwist-style candidates for one domain, most useful first, deduped and capped.
 * The domain itself and anything in `exclude` (with subdomains) are never returned.
 */
export function permutations(domain: string, options: { limit?: number; exclude?: string[] } = {}): Permutation[] {
  const brand = brandOf(domain);
  if (!brand) return [];
  const { label, suffix, registrable } = brand;
  if (!registrable && label.length < MIN_SUBDOMAIN_BRAND) return [];
  const limit = options.limit ?? DEFAULT_PERMUTATION_LIMIT;
  const own = `${label}.${suffix}`;
  const exclude = [...(registrable ? [own] : []), ...(options.exclude ?? []).map((item) => item.toLowerCase().replace(/\.$/, ""))];
  const seen = new Set<string>();
  const out: Permutation[] = [];
  const add = (candidate: string, reason: PermutationReason) => {
    if (out.length >= limit || seen.has(candidate)) return;
    seen.add(candidate);
    const [first] = candidate.split(".");
    if (!first || (!VALID.test(first) && !/[^\x00-\x7f]/.test(first))) return;
    if (exclude.some((item) => candidate === item || candidate.endsWith(`.${item}`))) return;
    out.push({ domain: candidate, reason });
  };
  for (const ending of AU_SUFFIXES) {
    if (!registrable) add(`${label}.${ending}`, "keyword");
    else if (ending !== suffix) add(`${label}.${ending}`, "tld-swap");
  }
  for (const variant of homoglyphVariants(own)) add(variant, "homoglyph");
  for (const prefix of BRAND_PREFIXES) add(`${prefix}${label}.${suffix}`, "keyword");
  for (const extra of BRAND_SUFFIXES) {
    add(`${label}${extra}.${suffix}`, "keyword");
    if (suffix !== "com") add(`${label}${extra}.com`, "keyword");
  }
  for (const [edited, reason] of labelEdits(label)) if (edited.length > 0) add(`${edited}.${suffix}`, reason);
  return out;
}
