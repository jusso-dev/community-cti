import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { JSDOM } from "jsdom";
import axe from "axe-core";
import type { Finding } from "@community-cti/schema";
import { renderAlertsPage, renderCheckEmailPage, renderDomainsPage, renderFindingDetail, renderFindingsPage, renderLoginPage, renderMessagePage, renderNotificationSettings, renderOnboardingPage, sortFindings, type PortalFinding } from "./index.js";

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

test("portal pages pass axe", async () => {
  const detail: PortalFinding = {
    ...finding,
    evidence: [
      { label: "Certificate log entry", url: "https://crt.sh/?id=1", sourceId: "crtsh", licence: "public logs", collectedAt: "2026-10-14", redacted: false },
      { label: "Partner report", sourceId: "partner", licence: "TLP:AMBER", collectedAt: "2026-10-14", redacted: true, note: "This source cannot be shown in full." },
    ],
  };
  const pages = [
    renderLoginPage({ error: "Enter your email address." }),
    renderCheckEmailPage(),
    renderMessagePage("Page not found", "We could not find that page."),
    renderOnboardingPage({ needsOrg: true, error: "Tick the box to give consent.", values: { name: "Mob Corp", orgType: "AMS" } }),
    renderOnboardingPage({ needsOrg: false }),
    renderDomainsPage([
      { id: "d1", domain: "example.org.au", status: "pending", token: "abc", verifiedAt: null },
      { id: "d2", domain: "mob.org.au", status: "verified", token: "def", verifiedAt: "2026-10-14" },
      { id: "d3", domain: "old.org.au", status: "lapsed", token: "ghi", verifiedAt: null },
    ], { error: "TXT record not found yet", notice: "We added your domain." }),
    renderFindingDetail(detail, { error: "add a short note" }),
    renderFindingDetail({ ...detail, status: "dismissed" }),
    renderNotificationSettings("off", { notice: "Saved." }),
    renderAlertsPage([{
      id: "a1", sourceId: "acsc-alerts", title: "Patch now", url: "https://www.cyber.gov.au/alert/1", summary: "Update your firewall.",
      publishedAt: "2026-10-14T00:00:00Z", cves: ["CVE-2026-0001"], tags: [], attackTechniques: [], licence: "CC BY 4.0", relevance: 80, reasons: ["It affects common software."],
    }], { days: 90, total: 3, similarSectors: 1, sectors: [{ name: "Health", count: 3 }], groups: [], summary: "3 Australian organisations were listed in the last 90 days." }),
    renderAlertsPage([], { days: 90, total: 0, similarSectors: 0, sectors: [], groups: [], summary: "No reports in the last 90 days." }),
    renderNotificationSettings("digest", { canStop: true, error: "Tick the box to confirm you want us to stop." }),
  ];
  for (const html of pages) assert.deepEqual(await axeSerious(html), []);
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
