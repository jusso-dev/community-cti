import { test } from "node:test";
import assert from "node:assert/strict";
import { domainToASCII } from "node:url";
import { buildMatcher, type CertMatch } from "./lookalike/matcher.js";
import { AU_SUFFIXES, brandOf, permutations, splitDomain } from "./lookalike/permutations.js";
import { scoreLookalike, type LookalikeSignals } from "./match/score.js";

const matcher = buildMatcher([
  { tenantId: "yarn", domain: "yarnangu.org.au", verified: true, brandKeywords: ["yarnangu"] },
  { tenantId: "ams", domain: "ams.org.au", verified: true, brandKeywords: ["ams"] },
  { tenantId: "unverified", domain: "pending.org.au", verified: false, brandKeywords: ["pending"] },
]);

const cyrillicA = "а";
const idn = domainToASCII(`y${cyrillicA}rnangu.org.au`);

const positives: Array<[string, CertMatch["reason"], string]> = [
  ["yarnangu.com.au", "tld-swap", "same name under .com.au"],
  ["yarnangu.org", "tld-swap", "same name under .org"],
  ["yarnangu.au", "tld-swap", "direct .au registration"],
  ["yamangu.org.au", "homoglyph", "rn written as m"],
  ["yarnanqu.org.au", "homoglyph", "g written as q"],
  ["yarnan9u.org.au", "homoglyph", "digit for a letter"],
  [idn, "homoglyph", "punycode IDN with a Cyrillic a"],
  ["yarangu.org.au", "omission", "one letter left out"],
  ["yranangu.org.au", "swap", "two letters swapped"],
  ["yarnangu-login.com", "keyword", "brand plus login"],
  ["yarnangu.org.au.evil.com", "keyword", "verified name used as a subdomain"],
  ["*.yarnangu-au.com", "keyword", "wildcard certificate name"],
  ["YARNANGU.COM.AU.", "tld-swap", "uppercase with a trailing dot"],
];

for (const [name, reason, why] of positives) {
  test(`matcher flags ${name} as ${reason} (${why})`, () => {
    const hits = matcher.match(name);
    assert.ok(hits.some((hit) => hit.reason === reason && hit.tenantId === "yarn"), JSON.stringify(hits));
    assert.ok(hits.every((hit) => hit.tenantId === "yarn"));
  });
}

const negatives: Array<[string, string]> = [
  ["yarnangu.org.au", "the tenant's own domain"],
  ["YARNANGU.ORG.AU.", "own domain after normalisation"],
  ["streams.com", "a 3-letter label never becomes a keyword"],
  ["dreams-login.com.au", "a 3-letter label never becomes a keyword"],
  ["pendng.org.au", "unverified domains are not watched"],
  ["pending-login.com", "unverified domains are not watched"],
  ["example.com", "unrelated name"],
];

for (const [name, why] of negatives) {
  test(`matcher ignores ${name} (${why})`, () => {
    assert.deepEqual(matcher.match(name), []);
  });
}

test("matcher still catches typos of a short label without keyword noise", () => {
  assert.equal(matcher.match("ams.com.au")[0]?.reason, "tld-swap");
  assert.equal(matcher.match("ams.com.au")[0]?.tenantId, "ams");
  assert.equal(matcher.match("am5.org.au")[0]?.reason, "homoglyph");
});

test("similar labels in two tenants each map to their own tenant only", () => {
  const twoTenants = buildMatcher([
    { tenantId: "t1", domain: "warlpiri.org.au", verified: true, brandKeywords: ["warlpiri"] },
    { tenantId: "t2", domain: "warlpiri-media.org.au", verified: true, brandKeywords: ["warlpiri-media"] },
  ]);
  const media = twoTenants.match("warlpiri-media.com.au");
  assert.ok(media.some((hit) => hit.tenantId === "t2" && hit.reason === "tld-swap"));
  assert.ok(media.every((hit) => hit.watched === (hit.tenantId === "t2" ? "warlpiri-media.org.au" : "warlpiri.org.au")));
  assert.ok(media.some((hit) => hit.tenantId === "t1" && hit.reason === "keyword"));
  const base = twoTenants.match("warlpiri.com.au");
  assert.deepEqual(base.map((hit) => [hit.tenantId, hit.reason]), [["t1", "tld-swap"]]);
});

test("permutations cover dnstwist kinds and AU endings, dedupe and cap", () => {
  const list = permutations("yarnangu.org.au");
  const domains = new Set(list.map((item) => item.domain));
  assert.equal(domains.size, list.length);
  assert.ok(list.length <= 600);
  for (const ending of AU_SUFFIXES.filter((item) => item !== "org.au")) assert.ok(domains.has(`yarnangu.${ending}`), ending);
  const expected: Array<[string, string]> = [
    ["yarangu.org.au", "omission"],
    ["yranangu.org.au", "swap"],
    ["yarnanngu.org.au", "typo"],
    ["yarnanfu.org.au", "typo"],
    ["yarn-angu.org.au", "typo"],
    ["yornangu.org.au", "typo"],
    ["yarnangu-login.org.au", "keyword"],
    ["yarnangu-secure.com", "keyword"],
    ["myyarnangu.org.au", "keyword"],
    ["yarnanguportal.org.au", "keyword"],
    ["yarnan9u.org.au", "homoglyph"],
  ];
  for (const [domain, reason] of expected) assert.equal(list.find((item) => item.domain === domain)?.reason, reason, domain);
  assert.equal(domains.has("yarnangu.org.au"), false);
  assert.equal(permutations("yarnangu.org.au", { limit: 25 }).length, 25);
  assert.ok(list.every((item) => !item.domain.startsWith("-") && !item.domain.split(".")[0]!.endsWith("-")));
});

test("permutations skip the tenant's legitimate domains and their subdomains", () => {
  const list = permutations("yarnangu.org.au", { exclude: ["yarnangu.com.au", "yarnangu-login.org.au"] });
  const domains = list.map((item) => item.domain);
  assert.equal(domains.includes("yarnangu.com.au"), false);
  assert.equal(domains.includes("yarnangu-login.org.au"), false);
  assert.equal(domains.includes("yarnangu.net.au"), true);
});

test("a verified subdomain lends only its own label, never the parent's", () => {
  assert.deepEqual(splitDomain("mail.yarnangu.org.au"), { label: "yarnangu", suffix: "org.au" });
  assert.deepEqual(brandOf("smoke-984fc854.example.org.au"), { label: "smoke-984fc854", suffix: "org.au", registrable: false });
  assert.deepEqual(brandOf("yarnangu.org.au"), { label: "yarnangu", suffix: "org.au", registrable: true });
  const list = permutations("smoke-984fc854.example.org.au");
  const domains = list.map((item) => item.domain);
  assert.ok(list.length > 50);
  assert.equal(domains.some((domain) => domain.includes("example")), false, "no parent-derived candidates");
  for (const expected of ["smoke-984fc854.com.au", "smoke-984fc854.org.au", "smoke-984fc854.com", "smoke-98fc854.org.au"]) assert.ok(domains.includes(expected), expected);
  assert.equal(list.find((item) => item.domain === "smoke-984fc854.com.au")?.reason, "keyword");
  assert.equal(list.some((item) => item.reason === "tld-swap"), false);
  assert.deepEqual(permutations("www.example.org.au"), [], "generic short labels are not a brand");
  assert.deepEqual(permutations("localhost"), []);
});

test("matcher never swaps the ending of a parent the tenant did not verify", () => {
  const sub = buildMatcher([
    { tenantId: "s1", domain: "smoke-984fc854.example.org.au", verified: true, brandKeywords: ["smoke-984fc854"] },
    { tenantId: "s2", domain: "smoke-ea07a77d.example.org.au", verified: true, brandKeywords: ["smoke-ea07a77d"] },
  ]);
  for (const name of ["example.com", "example.net", "example.org", "example.com.au"]) assert.deepEqual(sub.match(name), [], name);
  assert.deepEqual(sub.match("smoke-984fc854.com.au").map((hit) => [hit.tenantId, hit.reason]), [["s1", "keyword"]]);
});

const quiet: LookalikeSignals = { editDistance: null, homoglyph: false, hasMx: false, resolves: false, registeredDaysAgo: null, faviconMatch: false, parked: false };

test("scoring: tld swap, MX and a new registration add up", () => {
  const tld = scoreLookalike({ ...quiet, tldSwap: true });
  assert.equal(tld.confidence, 25);
  assert.equal(tld.factors[0]?.code, "tld_swap");
  const live = scoreLookalike({ ...quiet, tldSwap: true, resolves: true, hasMx: true, registeredDaysAgo: 3 });
  assert.equal(live.confidence, 65);
  assert.deepEqual(live.factors.map((item) => item.code), ["tld_swap", "has_mx", "resolves", "new_registration"]);
  assert.equal(scoreLookalike({ ...quiet, tldSwap: true, registeredDaysAgo: 30 }).confidence, 25);
});

test("scoring: a copied site icon pushes a lookalike to the immediate band", () => {
  const copied = scoreLookalike({ ...quiet, homoglyph: true, resolves: true, hasMx: true, faviconMatch: true });
  assert.equal(copied.confidence, 80);
  assert.ok(copied.confidence >= 70);
  const withoutIcon = scoreLookalike({ ...quiet, homoglyph: true, resolves: true, hasMx: true });
  assert.ok(withoutIcon.confidence < 70);
});

test("scoring: a parked page pulls the score down and never below zero", () => {
  const parked = scoreLookalike({ ...quiet, editDistance: 1, resolves: true, parked: true });
  assert.equal(parked.confidence, 5);
  assert.ok(parked.factors.some((item) => item.code === "parked" && item.points === -30));
  assert.equal(scoreLookalike({ ...quiet, parked: true }).confidence, 0);
  assert.equal(scoreLookalike(quiet).factors[0]?.code, "no_signal");
});
