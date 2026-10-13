import { test } from "node:test";
import assert from "node:assert/strict";
import { validateFinding, canTransition, createFinding, readingGrade, type Finding } from "./index.js";

const base: Finding = {
  id: "f1",
  tenantId: "t1",
  kind: "lookalike_domain",
  title: "t",
  plainEnglishSummary: "s",
  confidence: 70,
  confidenceFactors: [{ code: "edit_distance", points: 25, reason: "One character differs" }],
  status: "open",
  stixRefs: [],
  provenance: [{
    sourceId: "crtsh",
    collectedAt: "2026-10-13T00:00:00.000Z",
    licence: "public",
    accessRestriction: "TLP:CLEAR",
    evidenceRefs: [],
  }],
};

test("valid finding passes", () => assert.deepEqual(validateFinding(base), []));
test("finding without provenance fails", () => assert.ok(validateFinding({ ...base, provenance: [] }).length > 0));
test("finding without factors fails", () => assert.ok(validateFinding({ ...base, confidenceFactors: [] }).length > 0));
test("dismissed findings can be reopened", () => assert.equal(canTransition("dismissed", "open"), true));
test("createFinding starts open", () => {
  const { status, ...rest } = base;
  assert.equal(createFinding(rest).status, "open");
  assert.equal(status, "open");
});
test("short plain sentences sit around Year 8", () => {
  const grade = readingGrade("A website name looks like yours. Do not type your password there. Tell your IT helper.");
  assert.ok(grade <= 8, `grade ${grade}`);
});
