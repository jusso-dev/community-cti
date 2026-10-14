import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";
import axe from "axe-core";
import type { Finding } from "@community-cti/schema";
import { renderDomainsPage, renderFindingDetail, renderFindingsPage, renderNotificationSettings, sortFindings } from "./index.js";

const finding: Finding = {
  id: "f1",
  tenantId: "t1",
  kind: "lookalike_domain",
  title: "A website looks like your domain",
  plainEnglishSummary: "The name is close to a domain you checked.",
  confidence: 72,
  status: "open",
  stixRefs: [],
  createdAt: "2026-10-14T00:00:00Z",
  provenance: [{ sourceId: "crtsh", collectedAt: "2026-10-14T00:00:00Z", licence: "public logs", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }],
  confidenceFactors: [{ code: "edit_distance_1", points: 25, reason: "The name is one change away from your domain." }],
};

async function axeSerious(html: string): Promise<string[]> {
  const dom = new JSDOM(html, { runScripts: "dangerously", url: "http://localhost/" });
  dom.window.eval(axe.source);
  const results = await dom.window.axe.run(dom.window.document, {
    rules: { "color-contrast": { enabled: false } },
    resultTypes: ["violations"],
  });
  return Array.from(
    results.violations
      .filter((item: { impact?: string }) => item.impact === "serious" || item.impact === "critical")
      .map((item: { id: string }) => item.id),
  );
}

test("dashboard detail shows provenance, confidence and dismiss controls", async () => {
  const html = renderFindingDetail(finding);
  assert.match(html, /crtsh/);
  assert.match(html, /72 out of 100/);
  assert.match(html, /Dismiss this finding/);
  assert.match(html, /Challenge this finding/);
  const serious = await axeSerious(html);
  assert.deepEqual(serious, []);
  const list = await axeSerious(renderFindingsPage([finding, { ...finding, id: "f2", confidence: 10, createdAt: "2026-10-15T00:00:00Z" }]));
  assert.deepEqual(list, []);
  assert.deepEqual(await axeSerious(renderDomainsPage([{ domain: "example.org.au", status: "pending", txt: "cti-verify=abc" }])), []);
  assert.deepEqual(await axeSerious(renderNotificationSettings("digest")), []);
});

test("findings are sorted by confidence then date", () => {
  const sorted = sortFindings([
    { confidence: 10, createdAt: "2026-10-15T00:00:00Z" },
    { confidence: 90, createdAt: "2026-10-01T00:00:00Z" },
    { confidence: 90, createdAt: "2026-10-02T00:00:00Z" },
  ]);
  assert.equal(sorted[0]?.createdAt, "2026-10-02T00:00:00Z");
  assert.equal(sorted[2]?.confidence, 10);
});

test("initial JavaScript stays under 200 KB", () => {
  const script = readFileSync(fileURLToPath(new URL("../client/app.js", import.meta.url)));
  assert.ok(script.length < 200 * 1024, `bundle is ${script.length} bytes`);
});
