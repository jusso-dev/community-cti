import type { Collector } from "./index.js";
import { sha256Json } from "./sources.js";

export interface SourceRecord {
  id: string;
  status: string;
  licence: string | null;
  tlp: string | null;
}

export interface StoredObservation {
  sourceId: string;
  collectedAt: string;
  licence: string;
  tlp: string;
  rawKey: string;
  sha256: string;
  payload: unknown;
  extractedDomain?: string;
}

export interface ObservationStore {
  getSource(id: string): Promise<SourceRecord | null>;
  putRaw(key: string, body: Uint8Array): Promise<void>;
  insertObservation(row: StoredObservation): Promise<"inserted" | "duplicate">;
}

export interface RunResult {
  inserted: number;
  duplicates: number;
}

export async function runCollector(
  sourceId: string,
  collector: Collector<unknown>,
  store: ObservationStore,
  now = new Date(),
): Promise<RunResult> {
  const source = await store.getSource(sourceId);
  if (!source) throw new Error(`unknown source ${sourceId}`);
  if (source.status !== "approved") throw new Error(`refusing unapproved source ${sourceId} (${source.status})`);
  if (!source.licence || !source.tlp) throw new Error(`source ${sourceId} is missing licence or TLP`);
  const batch = await collector.collect(new Date(now.getTime() - 24 * 60 * 60 * 1000));
  let inserted = 0;
  let duplicates = 0;
  const day = now.toISOString().slice(0, 10).split("-");
  for (const item of batch) {
    const provenance = item.provenance;
    if (!provenance.sourceId || !provenance.collectedAt || !provenance.licence || !provenance.accessRestriction) {
      throw new Error("observation is missing provenance");
    }
    const sha = sha256Json(item.record);
    const key = `raw/${sourceId}/${day[0]}/${day[1]}/${day[2]}/${sha}.json`;
    await store.putRaw(key, new TextEncoder().encode(JSON.stringify(item.record)));
    const outcome = await store.insertObservation({
      sourceId: provenance.sourceId,
      collectedAt: provenance.collectedAt,
      licence: provenance.licence,
      tlp: provenance.accessRestriction,
      rawKey: key,
      sha256: sha,
      payload: item.record,
    });
    if (outcome === "inserted") inserted += 1;
    else duplicates += 1;
  }
  return { inserted, duplicates };
}

export class MemoryObservationStore implements ObservationStore {
  sources = new Map<string, SourceRecord>();
  rows: StoredObservation[] = [];
  objects = new Map<string, Uint8Array>();

  async getSource(id: string): Promise<SourceRecord | null> {
    return this.sources.get(id) ?? null;
  }

  async putRaw(key: string, body: Uint8Array): Promise<void> {
    this.objects.set(key, body);
  }

  async insertObservation(row: StoredObservation): Promise<"inserted" | "duplicate"> {
    if (this.rows.some((existing) => existing.sourceId === row.sourceId && existing.sha256 === row.sha256)) {
      return "duplicate";
    }
    for (const field of ["sourceId", "collectedAt", "licence", "tlp", "rawKey", "sha256"] as const) {
      if (!row[field]) throw new Error(`missing ${field}`);
    }
    this.rows.push(row);
    return "inserted";
  }
}

export const SCHEDULES: Record<string, string> = {
  "cisa-kev": "15 2 * * *",
  nvd: "30 2 * * *",
  epss: "45 2 * * *",
  urlhaus: "0 */6 * * *",
  openphish: "15 */6 * * *",
  phishtank: "30 */6 * * *",
  "acsc-alerts": "0 7 * * *",
  ransomwatch: "0 7 * * *",
  crtsh: "0 4 * * 1",
  "hibp-domain": "0 5 * * *",
};

export interface BossLike {
  schedule(name: string, cron: string, data?: object): Promise<void>;
}

export async function registerSchedules(boss: BossLike, schedules: Record<string, string> = SCHEDULES): Promise<void> {
  for (const [sourceId, cron] of Object.entries(schedules)) {
    await boss.schedule(`collector:${sourceId}`, cron, { sourceId });
  }
}

/** Starts pg-boss when a database URL is configured. Tests use registerSchedules with a fake boss. */
export async function startPgBoss(connectionString: string): Promise<void> {
  const imported = await import("pg-boss");
  const boss = new imported.default(connectionString);
  await boss.start();
  await registerSchedules(boss);
}
