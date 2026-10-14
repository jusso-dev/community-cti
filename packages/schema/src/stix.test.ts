import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildDomainName,
  buildIndicator,
  buildInfrastructure,
  buildNote,
  buildObservedData,
  buildOpinion,
  buildRelationship,
  buildReport,
  buildSighting,
  buildUrl,
  buildVulnerability,
  createFinding,
  DEFAULT_DATA_REGION,
  MemoryIntelStore,
  searchWithAlias,
  validateStix,
  type StixObject,
} from "./index.js";

const ctx = {
  sourceId: "cisa-kev",
  licence: "US government public domain",
  sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
  collectedAt: new Date("2026-10-14T00:00:00.000Z"),
  confidence: 80,
};

test("builders pass STIX schema validation and carry marking plus source", () => {
  const vuln = buildVulnerability({ ...ctx, name: "Example widget", cve: "CVE-2024-12345", confidence: 80 });
  const indicator = buildIndicator({ ...ctx, name: "Example url", pattern: "[url:value = 'https://example.org/phish']", confidence: 70 });
  const domain = buildDomainName({ ...ctx, value: "example.org.au", confidence: 60 });
  const url = buildUrl({ ...ctx, value: "https://example.org/phish", confidence: 60 });
  const infra = buildInfrastructure({ ...ctx, name: "Example host", confidence: 55 });
  const relationship = buildRelationship({
    ...ctx,
    relationshipType: "related-to",
    sourceRef: indicator.id,
    targetRef: vuln.id,
    confidence: 50,
  });
  const sighting = buildSighting({ ...ctx, sightingOfRef: indicator.id, confidence: 40 });
  const note = buildNote({ ...ctx, content: "Enrichment note", objectRefs: [domain.id], confidence: 40 });
  const opinion = buildOpinion({
    ...ctx,
    opinion: "strongly-disagree",
    explanation: "Not our domain",
    objectRefs: [indicator.id],
    confidence: 30,
  });
  const report = buildReport({
    ...ctx,
    name: "Example advisory",
    published: "2026-10-14T00:00:00.000Z",
    objectRefs: [indicator.id],
    confidence: 65,
    extra: { x_country: "AU" },
  });
  const observed = buildObservedData({
    ...ctx,
    firstObserved: "2026-10-14T00:00:00.000Z",
    lastObserved: "2026-10-14T00:00:00.000Z",
    objectRefs: [domain.id],
    confidence: 50,
  });
  const objects: StixObject[] = [vuln, indicator, domain, url, infra, relationship, sighting, note, opinion, report, observed];
  for (const obj of objects) {
    const errors = validateStix(obj);
    assert.deepEqual(errors, [], `${obj.type}: ${errors.join("; ")}`);
    assert.ok(obj.object_marking_refs && obj.object_marking_refs.length > 0);
    assert.ok(obj.external_references && obj.external_references.length > 0);
    assert.equal(Number.isInteger(obj.confidence), true);
  }
});

test("confidence outside 0 to 100 is rejected", () => {
  assert.throws(() => buildIndicator({ ...ctx, name: "n", pattern: "[domain-name:value = 'a.com']", confidence: 101 }));
});

test("isolation: alias stix-A never returns tenant B objects", async () => {
  const store = new MemoryIntelStore();
  const shared = buildNote({ ...ctx, content: "shared", objectRefs: [buildDomainName({ ...ctx, value: "example.org" }).id], confidence: 10 });
  const a = buildIndicator({ ...ctx, name: "A", pattern: "[domain-name:value = 'a.example']", confidence: 10 });
  const b = buildIndicator({ ...ctx, name: "B", pattern: "[domain-name:value = 'b.example']", confidence: 10 });
  await store.upsert(shared, null);
  await store.upsert(a, "tenant-a");
  await store.upsert(b, "tenant-b");
  const docs = [
    { id: shared.id, tenant_id: null, body: shared },
    { id: a.id, tenant_id: "tenant-a", body: a },
    { id: b.id, tenant_id: "tenant-b", body: b },
  ];
  const visible = searchWithAlias(docs, "tenant-a").map((doc) => doc.id);
  assert.ok(visible.includes(shared.id));
  assert.ok(visible.includes(a.id));
  assert.equal(visible.includes(b.id), false);
  const related = await store.getRelated(a.id, 1, "tenant-a");
  assert.equal(related.some((obj) => obj.id === b.id), false);
});

test("createFinding starts open and requires provenance and factors", () => {
  const finding = createFinding({
    id: "f1",
    tenantId: "t1",
    kind: "lookalike_domain",
    title: "Lookalike",
    plainEnglishSummary: "A site looks like your domain.",
    confidence: 55,
    provenance: [{ sourceId: "crtsh", collectedAt: "2026-10-14T00:00:00Z", licence: "public", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }],
    stixRefs: [],
    confidenceFactors: [{ code: "edit_distance_1", points: 25, reason: "One change from your domain." }],
  });
  assert.equal(finding.status, "open");
  assert.throws(() => createFinding({ ...finding, provenance: [], confidenceFactors: finding.confidenceFactors! }));
});

test("default data region is Australian", () => {
  assert.equal(DEFAULT_DATA_REGION, "ap-southeast-2");
});
