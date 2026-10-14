import type { IntelStore, StixObject } from "@community-cti/schema";
import type { Collector } from "../index.js";
import type { Provenance } from "@community-cti/schema";
import { assertAllowListed } from "../allow.js";

/** Local development hosts. Production reads must be https and allow-listed. */
export const THREATSIEVE_DEV_HOSTS = new Set(["127.0.0.1", "localhost"]);

const STIX_ID = /^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Read shared STIX from a ThreatSieve TAXII 2.1 objects URL.
 * The request body is empty. Tenant findings are not sent.
 */
export function threatSieveObjectsUrl(objectsUrl: string, allowedHosts: Set<string>): string {
  assertAllowListed(objectsUrl, allowedHosts);
  const url = new URL(objectsUrl);
  const local = THREATSIEVE_DEV_HOSTS.has(url.hostname.toLowerCase());
  if (!local && url.protocol !== "https:") {
    throw new Error("ThreatSieve TAXII must use https");
  }
  return url.toString();
}

/** Keep shared STIX 2.1 objects. Drop sightings so tenant observations stay in ThreatSieve. */
export function parseThreatSieveEnvelope(body: unknown): StixObject[] {
  if (!body || typeof body !== "object" || !Array.isArray((body as { objects?: unknown }).objects)) {
    throw new Error("ThreatSieve response is not a STIX envelope");
  }
  const objects: StixObject[] = [];
  for (const item of (body as { objects: unknown[] }).objects) {
    if (!item || typeof item !== "object") continue;
    const object = item as StixObject;
    if (object.type === "sighting") continue;
    if (object.spec_version !== "2.1") continue;
    if (typeof object.type !== "string" || typeof object.id !== "string") continue;
    if (!STIX_ID.test(object.id) || !object.id.startsWith(`${object.type}--`)) continue;
    objects.push(object);
  }
  return objects;
}

/** Store shared objects with a null tenant id. Tenant-owned rows are never written here. */
export async function storeThreatSieveObjects(store: IntelStore, objects: StixObject[]): Promise<number> {
  for (const object of objects) {
    await store.upsert(object, null);
  }
  return objects.length;
}

export function threatSieveCollector(load: () => Promise<unknown>): Collector<StixObject> {
  return {
    sourceId: "threatsieve",
    async collect(): Promise<Array<{ record: StixObject; provenance: Provenance }>> {
      const collectedAt = new Date().toISOString();
      return parseThreatSieveEnvelope(await load()).map((record) => ({
        record,
        provenance: {
          sourceId: "threatsieve",
          collectedAt,
          licence: "ThreatSieve shared collection; each object's source licence still applies",
          accessRestriction: "TLP:CLEAR",
          evidenceRefs: [record.id],
        },
      }));
    },
  };
}
