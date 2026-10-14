import { createHash } from "node:crypto";
import type { Provenance } from "@community-cti/schema";
import type { Collector } from "./index.js";

export interface SourceRecord {
  id: string;
  status: "candidate" | "approved" | "rejected" | "blocked";
  licence: string;
  tlp: Provenance["accessRestriction"];
  cron?: string;
}

export interface StoredObservation {
  sourceId: string;
  collectedAt: string;
  licence: string;
  tlp: string;
  rawKey: string;
  sha256: string;
  extractedDomain: string | null;
  payload: unknown;
}

export function rawObjectKey(sourceId: string, collectedAt: Date, sha256: string): string {
  const yyyy = String(collectedAt.getUTCFullYear());
  const mm = String(collectedAt.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(collectedAt.getUTCDate()).padStart(2, "0");
  return `raw/${sourceId}/${yyyy}/${mm}/${dd}/${sha256}.json`;
}

export async function runCollector<T>(options: {
  source: SourceRecord | null;
  collector: Collector<T> | undefined;
  since: Date;
  now?: Date;
  putRaw: (key: string, body: string) => Promise<void>;
  insertObservation: (obs: StoredObservation) => Promise<"inserted" | "duplicate">;
}): Promise<{ inserted: number; duplicates: number }> {
  if (!options.source) throw new Error("source is not in the registry");
  if (options.source.status !== "approved") {
    throw new Error(`source ${options.source.id} is not approved (status ${options.source.status})`);
  }
  if (!options.collector) throw new Error(`no collector for ${options.source.id}`);
  const collectedAt = options.now ?? new Date();
  const batch = await options.collector.collect(options.since);
  let inserted = 0;
  let duplicates = 0;
  for (const item of batch) {
    const provenance = item.provenance;
    if (!provenance.sourceId || !provenance.collectedAt || !provenance.licence || !provenance.accessRestriction) {
      throw new Error("observation provenance fields are required");
    }
    const body = JSON.stringify(item.record);
    const sha256 = createHash("sha256").update(body).digest("hex");
    const rawKey = rawObjectKey(options.source.id, collectedAt, sha256);
    const extracted = extractedDomain(item.record);
    const outcome = await options.insertObservation({
      sourceId: options.source.id,
      collectedAt: provenance.collectedAt,
      licence: provenance.licence,
      tlp: provenance.accessRestriction,
      rawKey,
      sha256,
      extractedDomain: extracted,
      payload: item.record,
    });
    if (outcome === "duplicate") {
      duplicates += 1;
      continue;
    }
    await options.putRaw(rawKey, body);
    inserted += 1;
  }
  return { inserted, duplicates };
}

function extractedDomain(record: unknown): string | null {
  if (!record || typeof record !== "object") return null;
  const value = (record as { extracted_domain?: unknown; extractedDomain?: unknown }).extracted_domain
    ?? (record as { extractedDomain?: unknown }).extractedDomain;
  return typeof value === "string" ? value : null;
}
