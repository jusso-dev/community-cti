import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { DEFERRED_SOURCE_IDS, SOURCE_CRONS, parseSourcesMarkdown, type SourceRecord, type SourceRow } from "@community-cti/collectors";
import type { TlpMarking } from "@community-cti/schema";
import type { Queryable } from "./db.js";

/** dist/governance.js sits at apps/worker/dist, so the docs folder is three levels up (also in Docker: /app/docs). */
export function sourcesDocPath(): string {
  return fileURLToPath(new URL("../../../docs/SOURCES.md", import.meta.url));
}

export function loadSourcesDoc(path = sourcesDocPath()): SourceRow[] {
  const rows = parseSourcesMarkdown(readFileSync(path, "utf8"));
  if (rows.length === 0) throw new Error(`no sources found in ${path}`);
  return rows;
}

/** Mirror docs/SOURCES.md into the sources table. The document is the source of truth for status. */
export async function syncSources(db: Queryable, rows: SourceRow[]): Promise<number> {
  for (const row of rows) {
    await db.query(
      `insert into sources (id, name, type, licence, commercial_use, cost, coverage, tlp, access_method, status, reviewed_by, notes, cron)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
       on conflict (id) do update set
         name = excluded.name, type = excluded.type, licence = excluded.licence,
         commercial_use = excluded.commercial_use, cost = excluded.cost, coverage = excluded.coverage,
         tlp = excluded.tlp, access_method = excluded.access_method, status = excluded.status,
         reviewed_by = excluded.reviewed_by, notes = excluded.notes, cron = excluded.cron`,
      [
        row.id,
        row.name,
        row.type,
        row.licence,
        row.commercialUse || null,
        row.cost || null,
        row.coverage || null,
        row.tlp,
        row.accessMethod || null,
        row.status,
        row.reviewedBy || null,
        row.notes || null,
        SOURCE_CRONS[row.id] ?? null,
      ],
    );
  }
  return rows.length;
}

const TLPS = new Set<TlpMarking>(["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]);

export function isDeferred(id: string): boolean {
  return (DEFERRED_SOURCE_IDS as readonly string[]).includes(id);
}

/**
 * The status the worker acts on. TEST_APPROVED_SOURCES lifts a `candidate` to
 * `approved` outside production only. Blocked, rejected and deferred sources
 * are never lifted, whatever the setting.
 */
export function effectiveSource(row: SourceRow, testApproved: string[], env: string): SourceRecord {
  const tlp = TLPS.has(row.tlp as TlpMarking) ? (row.tlp as TlpMarking) : "TLP:AMBER";
  let status = row.status;
  if (isDeferred(row.id)) status = "blocked";
  else if (status === "candidate" && env !== "production" && testApproved.includes(row.id)) status = "approved";
  return { id: row.id, status, licence: row.licence, tlp, cron: SOURCE_CRONS[row.id] };
}

export function effectiveSources(rows: SourceRow[], testApproved: string[], env: string): Map<string, SourceRecord> {
  if (testApproved.length > 0 && env === "production") {
    throw new Error("TEST_APPROVED_SOURCES must not be set when CTI_ENV is production");
  }
  return new Map(rows.map((row) => [row.id, effectiveSource(row, testApproved, env)]));
}

/** Ids from TEST_APPROVED_SOURCES that were not lifted, with the reason. */
export function ignoredTestApprovals(rows: SourceRow[], testApproved: string[]): Array<{ id: string; reason: string }> {
  const byId = new Map(rows.map((row) => [row.id, row]));
  return testApproved.flatMap((id) => {
    const row = byId.get(id);
    if (!row) return [{ id, reason: "not in SOURCES.md" }];
    if (isDeferred(id) || row.status === "blocked") return [{ id, reason: "blocked" }];
    if (row.status === "rejected") return [{ id, reason: "rejected" }];
    return [];
  });
}
