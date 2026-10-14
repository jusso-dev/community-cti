import { test } from "node:test";
import assert from "node:assert/strict";
import { canTransition } from "@community-cti/schema";
import { precisionAt, precisionFixtures } from "./match/precision.js";
import { scoreLookalike, scoreRansomware } from "./match/score.js";

test("score factors stay inside 0 to 100 and name-only ransomware stays at or below 69", () => {
  const scored = scoreLookalike({
    editDistance: 1,
    homoglyph: true,
    hasMx: true,
    resolves: true,
    registeredDaysAgo: 3,
    faviconMatch: true,
    parked: true,
  });
  assert.ok(scored.confidence >= 0 && scored.confidence <= 100);
  assert.ok(scored.factors.length > 0);
  const nameOnly = scoreRansomware({ victim: "Example Land Council", tenantName: "Example Land Council", secondSignal: false });
  assert.ok(nameOnly.confidence <= 69);
  assert.equal(nameOnly.confidence, 60);
  const supported = scoreRansomware({ victim: "Example Land Council", tenantName: "Example Land Council", secondSignal: true });
  assert.equal(supported.confidence, 80);
  const cases = precisionFixtures();
  assert.equal(cases.length, 50);
  assert.ok(precisionAt(cases) >= 0.8);
  assert.equal(canTransition("open", "dismissed"), true);
  assert.equal(canTransition("open", "challenged"), true);
});
