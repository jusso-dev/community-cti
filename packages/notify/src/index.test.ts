import { test } from "node:test";
import assert from "node:assert/strict";
import { readingGrade } from "@community-cti/schema";
import { alertCopy, assertPlainAlert, channelFor } from "./index.js";

test("alerts stay quiet under 40 and digest the middle band", () => {
  assert.equal(channelFor(39, "immediate"), "none");
  assert.equal(channelFor(40, "immediate"), "digest");
  assert.equal(channelFor(69, "immediate"), "digest");
  assert.equal(channelFor(70, "immediate"), "immediate");
  assert.equal(channelFor(90, "digest"), "digest");
  assert.equal(channelFor(90, "off"), "none");
});

test("alert copy stays at Year 8 level", () => {
  for (const kind of ["lookalike_domain", "credential_exposure", "exposed_service", "ransomware_mention", "phishing_campaign"]) {
    const copy = alertCopy(kind);
    assertPlainAlert(copy);
    assert.ok(readingGrade(`${copy.subject}. ${copy.text}`) <= 8);
    assert.equal(copy.text.includes("—"), false);
  }
});
