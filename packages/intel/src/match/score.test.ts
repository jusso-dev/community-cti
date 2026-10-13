import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { alertPrecision, findingFromLookalike, labelledLookalikes, scoreLookalike, scoreRansomwareName, ALERT_THRESHOLD } from "./score.js";

test("labelled lookalikes alert with at least 80 percent precision", () => {
  const cases = labelledLookalikes();
  assert.equal(cases.length, 50);
  const precision = alertPrecision(cases, ALERT_THRESHOLD);
  assert.ok(precision >= 0.8, `precision ${precision}`);
  const finding = findingFromLookalike({
    id: "33333333-3333-4333-8333-333333333333",
    tenantId: "11111111-1111-4111-8111-111111111111",
    title: "A lookalike name",
    summary: "A website name looks like yours.",
    signals: cases[0]!.signals,
    provenance: [{
      sourceId: "crtsh",
      collectedAt: "2026-10-13T00:00:00.000Z",
      licence: "public CT",
      accessRestriction: "TLP:CLEAR",
      evidenceRefs: [],
    }],
  });
  assert.equal(finding.status, "open");
  assert.ok(finding.confidenceFactors.length > 0);
  assert.equal(scoreLookalike({
    editDistance1: false, homoglyph: false, hasMx: false, resolves: false,
    registeredUnder30Days: false, faviconMatch: false, parked: false,
  }).confidence, 0);
});

test("a ransomware name on its own stays below high confidence", () => {
  const nameOnly = scoreRansomwareName(["Example Land Council"], "Example Land Council", false);
  assert.ok(nameOnly.confidence <= 69);
  assert.ok(nameOnly.confidence >= 40);
  const supported = scoreRansomwareName(["Example Land Council"], "Example Land Council", true);
  assert.ok(supported.confidence >= 70);
  assert.equal(scoreRansomwareName(["Example Land Council"], "Unrelated Bakery", false).confidence, 0);
});

test("the weight tune script does not write new weights", () => {
  const source = readFileSync(fileURLToPath(new URL("../../../../scripts/tune-weights.ts", import.meta.url)), "utf8");
  assert.equal(source.includes("writeFile"), false);
  assert.match(source, /does not modify/);
});
