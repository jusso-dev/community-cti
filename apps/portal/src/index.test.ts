import { test } from "node:test";
import assert from "node:assert/strict";
import { renderFindingText } from "./index.js";

test("renders sources", () => {
  const t = renderFindingText({ id: "1", tenantId: "t", kind: "lookalike_domain", title: "T", plainEnglishSummary: "S", confidence: 50, status: "open", stixRefs: [], provenance: [{ sourceId: "crtsh", collectedAt: "x", licence: "l", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }] });
  assert.match(t, /crtsh/);
});
