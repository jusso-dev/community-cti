import { test } from "node:test";
import assert from "node:assert/strict";
import { canTransition } from "@community-cti/schema";
import { communityFinding, decideShare, defaultSharingPreferences, sanitiseWarning } from "./share/sanitise.js";

test("sharing removes identifiers and blocks cultural data without per-item approval", () => {
  const cleaned = sanitiseWarning({
    text: "Example Land Council staff member Pat Lee (pat@example.org.au) saw login.internal.example.org.au from 10.1.2.3",
    tenantName: "Example Land Council",
    people: ["Pat Lee"],
    internalHosts: ["login.internal.example.org.au"],
  });
  assert.equal(cleaned.text.includes("Example Land Council"), false);
  assert.equal(cleaned.text.includes("Pat Lee"), false);
  assert.equal(cleaned.text.includes("pat@example.org.au"), false);
  assert.equal(cleaned.text.includes("login.internal.example.org.au"), false);
  assert.equal(cleaned.text.includes("10.1.2.3"), false);
  assert.equal(defaultSharingPreferences().every((item) => item.enabled === false), true);
  assert.equal(decideShare({ categoryEnabled: true, itemApproved: false, cultural: false }).ok, false);
  assert.equal(decideShare({ categoryEnabled: true, itemApproved: true, approverId: "owner", cultural: true }).reason, "cultural data cannot be shared");
  assert.equal(decideShare({ categoryEnabled: false, itemApproved: true, approverId: "owner", cultural: false }).ok, false);
  const ok = decideShare({ categoryEnabled: true, itemApproved: true, approverId: "owner-1", cultural: false });
  assert.equal(ok.ok, true);
  const finding = communityFinding({
    id: "shared-1",
    tenantId: "recipient",
    title: "A shared phishing warning",
    summary: cleaned.text,
    confidence: 60,
    factors: [{ code: "community", points: 60, reason: "Approved by a participating organisation." }],
    collectedAt: "2026-10-14T00:00:00Z",
  });
  assert.equal(finding.provenance[0]?.sourceId, "community");
  assert.equal(finding.provenance[0]?.accessRestriction, "TLP:GREEN");
  assert.equal(canTransition(finding.status, "dismissed"), true);
  assert.equal(canTransition(finding.status, "challenged"), true);
});
