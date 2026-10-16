import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve, sep } from "node:path";
import type pg from "pg";
import type { StixObject } from "@community-cti/schema";

export interface Queryable {
  query(sql: string, params?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>;
}

export interface StoredObservationRow {
  sourceId: string;
  collectedAt: string;
  licence: string;
  tlp: string;
  rawKey: string;
  sha256: string;
  extractedDomain: string | null;
  payload: unknown;
}

/**
 * Shared rows (tenant_id null) need app.actor_role = 'collector' under the RLS
 * policy. The setting lives on one pooled connection for the length of `fn`
 * and is cleared before the connection goes back to the pool.
 */
export async function withCollectorSession<T>(pool: pg.Pool, fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("select set_config('app.tenant_id', '', false), set_config('app.actor_role', 'collector', false)");
    return await fn(client);
  } finally {
    try {
      await client.query("select set_config('app.actor_role', '', false)");
      client.release();
    } catch {
      client.release(true);
    }
  }
}

export async function insertObservation(db: Queryable, obs: StoredObservationRow): Promise<"inserted" | "duplicate"> {
  const result = await db.query(
    `insert into observations (id, tenant_id, source_id, collected_at, licence, tlp, raw_key, sha256, extracted_domain, payload)
     values (gen_random_uuid(), null, $1, $2, $3, $4, $5, $6, $7, $8::jsonb)
     on conflict (source_id, sha256) do nothing
     returning id`,
    [obs.sourceId, obs.collectedAt, obs.licence, obs.tlp, obs.rawKey, obs.sha256, obs.extractedDomain, JSON.stringify(obs.payload)],
  );
  return result.rows.length > 0 ? "inserted" : "duplicate";
}

export const BATCH_SIZE = 500;

function chunks<T>(items: T[], size = BATCH_SIZE): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/** sha256 values a source already has, looked up in batches. */
export async function existingShas(db: Queryable, sourceId: string, shas: string[]): Promise<Set<string>> {
  const found = new Set<string>();
  for (const batch of chunks(shas, 5000)) {
    const result = await db.query("select sha256 from observations where source_id = $1 and sha256 = any($2::text[])", [sourceId, batch]);
    for (const row of result.rows) found.add(String(row.sha256));
  }
  return found;
}

/** Multi-row insert of shared observations. Conflicts are skipped. */
export async function insertObservations(db: Queryable, rows: StoredObservationRow[]): Promise<void> {
  for (const batch of chunks(rows)) {
    await db.query(
      `insert into observations (id, tenant_id, source_id, collected_at, licence, tlp, raw_key, sha256, extracted_domain, payload)
       select gen_random_uuid(), null, source_id, collected_at, licence, tlp, raw_key, sha256, extracted_domain, payload
       from unnest($1::text[], $2::timestamptz[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::jsonb[])
         as t(source_id, collected_at, licence, tlp, raw_key, sha256, extracted_domain, payload)
       on conflict (source_id, sha256) do nothing`,
      [
        batch.map((row) => row.sourceId),
        batch.map((row) => row.collectedAt),
        batch.map((row) => row.licence),
        batch.map((row) => row.tlp),
        batch.map((row) => row.rawKey),
        batch.map((row) => row.sha256),
        batch.map((row) => row.extractedDomain),
        batch.map((row) => JSON.stringify(row.payload)),
      ],
    );
  }
}

/**
 * Bulk upsert of shared STIX (tenant_id null), same rule as PostgresIntelStore:
 * an object owned by a tenant is never overwritten. Needs the collector session.
 */
export async function upsertSharedStix(db: Queryable, objects: StixObject[]): Promise<void> {
  const unique = [...new Map(objects.map((object) => [object.id, object])).values()];
  for (const batch of chunks(unique)) {
    await db.query(
      `insert into stix_objects (id, tenant_id, type, confidence, body)
       select id, null, type, confidence, body
       from unnest($1::text[], $2::text[], $3::smallint[], $4::jsonb[]) as t(id, type, confidence, body)
       on conflict (id) do update
         set body = excluded.body, type = excluded.type, confidence = excluded.confidence
         where stix_objects.tenant_id is null`,
      [
        batch.map((object) => object.id),
        batch.map((object) => object.type),
        batch.map((object) => (typeof object.confidence === "number" ? object.confidence : null)),
        batch.map((object) => JSON.stringify(object)),
      ],
    );
  }
}

/** Raw evidence blobs on the local filesystem, keyed by rawObjectKey(). */
export function fileRawStore(rawDir: string): (key: string, body: string) => Promise<void> {
  const root = resolve(rawDir);
  return async (key, body) => {
    const path = resolve(root, key);
    if (!path.startsWith(root + sep)) throw new Error("raw key escapes RAW_DIR");
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, body);
  };
}

export interface RunState {
  lastAttemptAt: Date | null;
  lastSuccessAt: Date | null;
}

export async function readState(db: Queryable, key: string): Promise<RunState> {
  const result = await db.query("select last_attempt_at, last_success_at from collector_runs where key = $1", [key]);
  const row = result.rows[0];
  return {
    lastAttemptAt: row?.last_attempt_at ? new Date(String(row.last_attempt_at)) : null,
    lastSuccessAt: row?.last_success_at ? new Date(String(row.last_success_at)) : null,
  };
}

export async function markAttempt(db: Queryable, key: string, now: Date): Promise<void> {
  await db.query(
    `insert into collector_runs (key, last_attempt_at) values ($1, $2)
     on conflict (key) do update set last_attempt_at = excluded.last_attempt_at`,
    [key, now],
  );
}

export async function markResult(db: Queryable, key: string, now: Date, error: string | null, summary: Record<string, unknown> = {}): Promise<void> {
  await db.query(
    `insert into collector_runs (key, last_attempt_at, last_success_at, last_error, summary)
     values ($1, $2::timestamptz, case when $3::text is null then $2::timestamptz else null end, $3::text, $4::jsonb)
     on conflict (key) do update set
       last_attempt_at = excluded.last_attempt_at,
       last_success_at = coalesce(excluded.last_success_at, collector_runs.last_success_at),
       last_error = excluded.last_error,
       summary = excluded.summary`,
    [key, now, error, JSON.stringify(summary)],
  );
}

/** Run `fn` over items with at most `limit` in flight. */
export async function mapLimit<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const item = items[next++]!;
      await fn(item);
    }
  });
  await Promise.all(workers);
}
