import { test } from "node:test";
import assert from "node:assert/strict";
import type { Finding, FindingKind } from "@community-cti/schema";
import { assertReadable, deliveryPlan, renderAlert } from "./templates.js";
import { createAuMailer } from "./mail.js";

const kinds: FindingKind[] = ["lookalike_domain", "credential_exposure", "exposed_service", "ransomware_mention", "phishing_campaign"];

function finding(kind: FindingKind, confidence: number): Finding {
  return {
    id: "f1",
    tenantId: "t1",
    kind,
    title: "Example",
    plainEnglishSummary: "Example summary.",
    confidence,
    status: "open",
    stixRefs: [],
    provenance: [{ sourceId: "crtsh", collectedAt: "2026-10-14T00:00:00Z", licence: "public logs", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }],
    confidenceFactors: [{ code: "test", points: confidence, reason: "Test factor." }],
  };
}

test("each alert template is plain English and shows source, confidence and dismiss", () => {
  for (const kind of kinds) {
    const email = renderAlert(finding(kind, 80), "https://portal.example/findings/f1/dismiss");
    assert.doesNotThrow(() => assertReadable(email));
  }
});

test("low confidence findings are never emailed", () => {
  assert.equal(deliveryPlan(39, "immediate"), "none");
  assert.equal(deliveryPlan(40, "immediate"), "digest");
  assert.equal(deliveryPlan(70, "immediate"), "immediate");
  assert.equal(deliveryPlan(90, "digest"), "digest");
  assert.equal(deliveryPlan(90, "off"), "none");
});

test("mail region must be in Australia", () => {
  assert.throws(() => createAuMailer("eu-west-1"));
  assert.doesNotThrow(() => createAuMailer("ap-southeast-2"));
});
