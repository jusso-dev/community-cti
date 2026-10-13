import type { StixObject } from "@community-cti/schema";
import { validateStix } from "@community-cti/schema/stix";
import type { Db } from "./types.js";
import { asRole, withTenant } from "./tenant.js";

function rowToObject(row: { body: StixObject }): StixObject {
  return row.body;
}

export async function upsertStix(db: Db, obj: StixObject, tenantId: string | null): Promise<void> {
  const errors = validateStix(obj);
  if (errors.length > 0) throw new Error(errors.join("; "));
  const confidence = typeof obj.confidence === "number" ? obj.confidence : null;
  if (tenantId === null) {
    await asRole(db, "cti_worker", (tx) =>
      tx.query("select insert_shared_stix($1, $2, $3, $4::jsonb)", [obj.id, obj.type, confidence, JSON.stringify(obj)]),
    );
    return;
  }
  await withTenant(db, tenantId, (tx) =>
    tx.query(
      `insert into stix_objects (id, tenant_id, type, confidence, body)
       values ($1, $2, $3, $4, $5::jsonb)
       on conflict (id) do update set type = excluded.type, confidence = excluded.confidence, body = excluded.body`,
      [obj.id, tenantId, obj.type, confidence, JSON.stringify(obj)],
    ),
  );
}

export async function getStix(db: Db, id: string, tenantId: string): Promise<StixObject | null> {
  const result = await withTenant(db, tenantId, (tx) =>
    tx.query<{ body: StixObject }>("select body from stix_objects where id = $1", [id]),
  );
  return result.rows[0] ? rowToObject(result.rows[0]) : null;
}

export async function relatedStix(db: Db, id: string, depth: number, tenantId: string): Promise<StixObject[]> {
  const seen = new Set<string>([id]);
  let frontier = [id];
  const found: StixObject[] = [];
  for (let i = 0; i < depth; i++) {
    const next: string[] = [];
    const rows = await withTenant(db, tenantId, (tx) =>
      tx.query<{ body: StixObject }>("select body from stix_objects"),
    );
    for (const row of rows.rows) {
      const obj = row.body;
      const source = obj.source_ref;
      const target = obj.target_ref;
      if (typeof source !== "string" || typeof target !== "string") continue;
      if (!frontier.includes(source) && !frontier.includes(target)) continue;
      if (!seen.has(obj.id)) {
        seen.add(obj.id);
        next.push(obj.id);
        found.push(obj);
      }
    }
    frontier = next;
  }
  return found;
}
