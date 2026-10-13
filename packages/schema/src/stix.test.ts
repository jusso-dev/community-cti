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
  buildIdentity,
  MemoryIntelStore,
  validateStix,
  type SourceRef,
} from "./stix.js";

const source: SourceRef = {
  sourceId: "crtsh",
  url: "https://crt.sh/",
  licence: "public certificate transparency logs",
  tlp: "TLP:CLEAR",
};
const now = "2026-10-13T00:00:00.000Z";

test("builders pass STIX schema validation and carry marking plus source", () => {
  const domain = buildDomainName({ value: "example.org.au", source, now });
  const url = buildUrl({ value: "https://example.org.au/login", source, now });
  const indicator = buildIndicator({
    pattern: "[domain-name:value = 'example.org.au']",
    confidence: 70,
    source,
    now,
  });
  const vulnerability = buildVulnerability({
    cve: "CVE-2024-12345",
    confidence: 90,
    source: { ...source, sourceId: "cisa-kev", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
    epss: 0.4,
    kev: true,
    now,
  });
  const infra = buildInfrastructure({ name: "203.0.113.10", source, confidence: 60, now });
  const relationship = buildRelationship({
    sourceRef: indicator.id,
    targetRef: vulnerability.id,
    relationshipType: "indicates",
    source,
    now,
  });
  const sighting = buildSighting({ sightingOfRef: indicator.id, source, now });
  const note = buildNote({ content: "DNS resolved.", objectRefs: [domain.id], source, now });
  const opinion = buildOpinion({
    opinion: "strongly-disagree",
    objectRefs: [indicator.id],
    explanation: "The domain belongs to the organisation.",
    source,
    now,
  });
  const report = buildReport({ name: "Example advisory", objectRefs: [indicator.id], source, now });
  const observed = buildObservedData({ objectRefs: [domain.id], source, now });
  const identity = buildIdentity({ name: "Community CTI", source, now });
  for (const obj of [domain, url, indicator, vulnerability, infra, relationship, sighting, note, opinion, report, observed, identity]) {
    assert.deepEqual(validateStix(obj), [], obj.type);
    assert.ok(obj.object_marking_refs && obj.object_marking_refs.length > 0);
    assert.ok(obj.external_references && obj.external_references.length > 0);
  }
  assert.equal(indicator.confidence, 70);
});

test("alias stix-A never returns tenant B objects", async () => {
  const store = new MemoryIntelStore();
  const a = buildIndicator({ pattern: "[domain-name:value = 'a.example']", confidence: 50, source, now, id: "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" });
  const b = buildIndicator({ pattern: "[domain-name:value = 'b.example']", confidence: 50, source, now, id: "indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" });
  const shared = buildIndicator({ pattern: "[domain-name:value = 'shared.example']", confidence: 40, source, now, id: "indicator--cccccccc-cccc-4ccc-8ccc-cccccccccccc" });
  await store.upsert(a, "A");
  await store.upsert(b, "B");
  await store.upsert(shared, null);
  const hits = await store.search("A", "example");
  const ids = hits.map((hit) => hit.id);
  assert.ok(ids.includes(a.id));
  assert.ok(ids.includes(shared.id));
  assert.equal(ids.includes(b.id), false);
});
