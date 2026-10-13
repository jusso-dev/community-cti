import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readingGrade } from "@community-cti/schema";
import { renderDashboard, renderFindingDetail, renderFindingText, sortFindings } from "./index.js";

const require = createRequire(import.meta.url);

test("renders sources", () => {
  const t = renderFindingText({ id: "1", tenantId: "t", kind: "lookalike_domain", title: "T", plainEnglishSummary: "S", confidence: 50, confidenceFactors: [{ code: "resolves", points: 10, reason: "The name resolves" }], status: "open", stixRefs: [], provenance: [{ sourceId: "crtsh", collectedAt: "x", licence: "l", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }] });
  assert.match(t, /crtsh/);
});

test("dashboard copy stays at Year 8 and has no serious accessibility failures", async () => {
  const html = renderDashboard([{
    id: "1",
    tenantId: "t",
    kind: "lookalike_domain",
    title: "A website name looks like yours",
    plainEnglishSummary: "A website name looks like yours.",
    confidence: 50,
    confidenceFactors: [{ code: "resolves", points: 10, reason: "The name resolves" }],
    status: "open",
    stixRefs: [],
    provenance: [{ sourceId: "crtsh", collectedAt: "2026-10-13T00:00:00.000Z", licence: "public", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }],
  }]);
  assert.ok(readingGrade("A website name looks like yours. Do not type your password there. Tell your IT helper.") <= 8);
  const { JSDOM } = require("jsdom") as { JSDOM: new (html: string) => { window: { document: Document; Node: typeof Node; Element: typeof Element; Document: typeof Document; HTMLElement: typeof HTMLElement; SVGElement: typeof SVGElement } } };
  const dom = new JSDOM(html);
  const win = dom.window;
  const target = globalThis as unknown as Record<string, unknown>;
  target.window = win;
  target.document = win.document;
  target.Node = win.Node;
  target.Element = win.Element;
  target.Document = win.Document;
  target.HTMLElement = win.HTMLElement;
  target.SVGElement = win.SVGElement;
  const axe = require("axe-core") as { run(node: Element, options?: object): Promise<{ violations: Array<{ id: string; impact?: string | null }> }> };
  const result = await axe.run(win.document.documentElement, { rules: { "color-contrast": { enabled: false } } });
  const serious = result.violations.filter((item) => item.impact === "serious" || item.impact === "critical");
  assert.deepEqual(serious.map((item) => item.id), []);
});

test("detail page shows provenance, confidence and dismiss controls", async () => {
  const finding = {
    id: "example-lookalike",
    tenantId: "t",
    kind: "lookalike_domain" as const,
    title: "A website name looks like yours",
    plainEnglishSummary: "A website name looks like yours.",
    confidence: 72,
    confidenceFactors: [{ code: "edit_distance", points: 25, reason: "The name is close to yours." }],
    provenance: [{
      sourceId: "crtsh",
      sourceUrl: "https://crt.sh/",
      collectedAt: "2026-10-13T00:00:00.000Z",
      licence: "public certificate transparency",
      accessRestriction: "TLP:CLEAR" as const,
      evidenceRefs: ["example-evidence"],
    }],
    status: "open" as const,
    stixRefs: [],
  };
  const html = renderFindingDetail(finding);
  assert.match(html, /What we found/);
  assert.match(html, /Why we think so/);
  assert.match(html, /Sources/);
  assert.match(html, /crtsh/);
  assert.match(html, /public certificate transparency/);
  assert.match(html, /72 out of 100/);
  assert.match(html, /Dismiss/);
  assert.match(html, /Challenge/);
  const { JSDOM } = require("jsdom") as { JSDOM: new (html: string) => { window: { document: Document; Node: typeof Node; Element: typeof Element; Document: typeof Document; HTMLElement: typeof HTMLElement; SVGElement: typeof SVGElement } } };
  const dom = new JSDOM(html);
  const win = dom.window;
  const target = globalThis as unknown as Record<string, unknown>;
  target.window = win;
  target.document = win.document;
  target.Node = win.Node;
  target.Element = win.Element;
  target.Document = win.Document;
  target.HTMLElement = win.HTMLElement;
  target.SVGElement = win.SVGElement;
  delete require.cache[require.resolve("axe-core")];
  const axe = require("axe-core") as { run(node: Element, options?: object): Promise<{ violations: Array<{ id: string; impact?: string | null }> }> };
  const result = await axe.run(win.document.documentElement, { rules: { "color-contrast": { enabled: false } } });
  const serious = result.violations.filter((item) => item.impact === "serious" || item.impact === "critical");
  assert.deepEqual(serious.map((item) => item.id), []);
});

test("findings sort by confidence then collection time", () => {
  const base = {
    tenantId: "t",
    kind: "lookalike_domain" as const,
    title: "T",
    plainEnglishSummary: "S",
    confidenceFactors: [{ code: "resolves", points: 10, reason: "The name resolves" }],
    status: "open" as const,
    stixRefs: [],
  };
  const sorted = sortFindings([
    { ...base, id: "low", confidence: 10, provenance: [{ sourceId: "crtsh", collectedAt: "2026-10-13T00:00:00.000Z", licence: "public", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }] },
    { ...base, id: "older", confidence: 80, provenance: [{ sourceId: "crtsh", collectedAt: "2026-10-01T00:00:00.000Z", licence: "public", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }] },
    { ...base, id: "newer", confidence: 80, provenance: [{ sourceId: "crtsh", collectedAt: "2026-10-12T00:00:00.000Z", licence: "public", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }] },
  ]);
  assert.deepEqual(sorted.map((item) => item.id), ["newer", "older", "low"]);
});
