import { test } from "node:test";
import assert from "node:assert/strict";
import { validateFinding, canTransition, type Finding } from "./index.js";

const base: Finding = {
  id: "f1", tenantId: "t1", kind: "lookalike_domain", title: "t", plainEnglishSummary: "s",
  confidence: 70, status: "open", stixRefs: [],
  provenance: [{ sourceId: "crtsh", collectedAt: "2026-10-13T00:00:00Z", licence: "public", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }],
};

test("valid finding passes", () => assert.deepEqual(validateFinding(base), []));
test("finding without provenance fails", () => assert.ok(validateFinding({ ...base, provenance: [] }).length > 0));
test("dismissed findings can be reopened", () => assert.ok(canTransition("dismissed", "open")));
