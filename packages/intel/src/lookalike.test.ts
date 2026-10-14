import { test } from "node:test";
import assert from "node:assert/strict";
import { createFinding } from "@community-cti/schema";
import { buildMatcher } from "./lookalike/matcher.js";

test("lookalike matcher detects omission, swap and homoglyph for verified domains only", () => {
  const matcher = buildMatcher([
    { tenantId: "a", domain: "example.org.au", verified: true, brandKeywords: ["exampleland"] },
    { tenantId: "b", domain: "other.org.au", verified: false },
  ]);
  assert.equal(matcher.match("exmple.org.au")[0]?.reason, "omission");
  assert.equal(matcher.match("exmaple.org.au").some((hit) => hit.reason === "swap"), true);
  assert.equal(matcher.match("examp1e.org.au")[0]?.reason, "homoglyph");
  assert.equal(matcher.match("example.org.au").length, 0);
  assert.equal(matcher.match("othe.org.au").length, 0);
  assert.equal(matcher.match("exampleland-login.com")[0]?.reason, "keyword");
  const hit = matcher.match("examp1e.org.au")[0]!;
  const finding = createFinding({
    id: "f",
    tenantId: hit.tenantId,
    kind: "lookalike_domain",
    title: "Possible lookalike",
    plainEnglishSummary: "A certificate name looks like your domain.",
    confidence: 50,
    provenance: [{ sourceId: "certstream", collectedAt: "2026-10-14T00:00:00Z", licence: "public CT logs", accessRestriction: "TLP:CLEAR", evidenceRefs: ["raw/cert"] }],
    stixRefs: [],
    confidenceFactors: [{ code: hit.reason, points: 25, reason: "The certificate name resembles your domain." }],
  });
  assert.equal(finding.provenance.length > 0, true);
  assert.equal(finding.status, "open");
});

test("lookalike matcher handles 1000 certificate names per second", () => {
  const matcher = buildMatcher([
    { tenantId: "a", domain: "example.org.au", verified: true },
    { tenantId: "a", domain: "community.org.au", verified: true },
  ]);
  const names = Array.from({ length: 5000 }, (_, i) => `random${i}.example.net`);
  names.push("examp1e.org.au");
  const start = performance.now();
  let hits = 0;
  for (const name of names) hits += matcher.match(name).length;
  const elapsed = performance.now() - start;
  const rate = names.length / (elapsed / 1000);
  assert.ok(rate >= 1000, `rate ${rate.toFixed(0)} /s`);
  assert.ok(hits >= 1);
});
