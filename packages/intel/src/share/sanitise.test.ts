import { test } from "node:test";
import assert from "node:assert/strict";
import { prepareShare, sanitiseText } from "./sanitise.js";

const secrets = {
  names: ["River Land Council"],
  people: ["Alex Example"],
  emails: ["alex@river.example.org.au"],
  hosts: ["mail.river.example.org.au"],
};

test("sharing stays off and strips names", () => {
  const clean = sanitiseText({
    text: "Alex Example at River Land Council used alex@river.example.org.au and other@hidden.example.org.au on mail.river.example.org.au.",
    ...secrets,
  });
  assert.equal(clean.includes("Alex"), false);
  assert.equal(clean.includes("River"), false);
  assert.equal(clean.includes("@"), false);
  assert.throws(() => prepareShare({
    cultural: false,
    categoryEnabled: true,
    approvedBy: "owner",
    approvedAt: "2026-10-13T00:00:00.000Z",
    launchApproved: false,
    tenantId: "11111111-1111-4111-8111-111111111111",
    findingId: "33333333-3333-4333-8333-333333333333",
    confidence: 50,
    factors: [{ code: "resolves", points: 10, reason: "The name resolves" }],
    text: "A fake site",
    secrets,
  }), /governance/);
  assert.throws(() => prepareShare({
    cultural: true,
    categoryEnabled: true,
    approvedBy: "owner",
    approvedAt: "2026-10-13T00:00:00.000Z",
    launchApproved: true,
    tenantId: "11111111-1111-4111-8111-111111111111",
    findingId: "33333333-3333-4333-8333-333333333333",
    confidence: 50,
    factors: [{ code: "resolves", points: 10, reason: "The name resolves" }],
    text: "A story",
    secrets,
  }), /cultural/i);
});
