import assert from "node:assert/strict";
import { test } from "node:test";
import { MemoryIntelStore } from "@community-cti/schema";
import {
  parseThreatSieveEnvelope,
  storeThreatSieveObjects,
  threatSieveCollector,
  threatSieveObjectsUrl,
} from "./threatsieve.js";

const INDICATOR = {
  type: "indicator",
  spec_version: "2.1",
  id: "indicator--01234567-89ab-4cde-8fab-0123456789ab",
  pattern: "[domain-name:value = 'example.com']",
  pattern_type: "stix",
  valid_from: "2026-10-14T00:00:00.000Z",
};

test("threatsieve envelope keeps shared stix and drops sightings", async () => {
  const objects = parseThreatSieveEnvelope({
    objects: [
      INDICATOR,
      {
        type: "sighting",
        spec_version: "2.1",
        id: "sighting--01234567-89ab-4cde-8fab-0123456789ac",
      },
      { type: "indicator", spec_version: "2.0", id: "indicator--nope" },
    ],
  });
  assert.equal(objects.length, 1);
  assert.equal(objects[0].id, INDICATOR.id);

  const store = new MemoryIntelStore();
  assert.equal(await storeThreatSieveObjects(store, objects), 1);
  const visible = await store.listVisible("tenant-a");
  assert.equal(visible.length, 1);
  assert.equal(visible[0].tenantId, null);

  const collected = await threatSieveCollector(async () => ({ objects: [INDICATOR] })).collect(new Date());
  assert.equal(collected[0].provenance.sourceId, "threatsieve");
  assert.equal(collected[0].provenance.evidenceRefs[0], INDICATOR.id);
});

test("threatsieve url must be allow-listed https", () => {
  const hosts = new Set(["intel.example"]);
  assert.equal(
    threatSieveObjectsUrl("https://intel.example/v1/taxii/api/collections/shared/objects/", hosts),
    "https://intel.example/v1/taxii/api/collections/shared/objects/",
  );
  assert.throws(() => threatSieveObjectsUrl("http://intel.example/objects/", hosts), /https/);
  assert.throws(() => threatSieveObjectsUrl("https://other.example/objects/", hosts), /allow-listed/);
  assert.equal(
    threatSieveObjectsUrl("http://127.0.0.1:8787/v1/taxii/api/collections/shared/objects/", new Set(["127.0.0.1"])),
    "http://127.0.0.1:8787/v1/taxii/api/collections/shared/objects/",
  );
});
