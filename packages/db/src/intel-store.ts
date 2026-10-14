import type { IntelStore, StixObject } from "@community-cti/schema";
import { MemoryIntelStore, visibleToTenant } from "@community-cti/schema";
import type { Pool, PoolClient } from "pg";
import { withTenant } from "./tenant.js";

interface Row {
  tenant_id: string | null;
  body: StixObject;
}

function asObject(value: unknown): StixObject {
  return value as StixObject;
}

export class PostgresIntelStore implements IntelStore {
  constructor(private readonly pool: Pool) {}

  async upsert(obj: StixObject, tenantId: string | null): Promise<void> {
    const run = async (client: PoolClient) => {
      if (tenantId === null) {
        await client.query("select set_config('app.actor_role', 'collector', true)");
      }
      const confidence = typeof obj.confidence === "number" ? obj.confidence : null;
      const result = await client.query(
        `insert into stix_objects (id, tenant_id, type, confidence, body)
         values ($1, $2, $3, $4, $5::jsonb)
         on conflict (id) do update
           set body = excluded.body,
               type = excluded.type,
               confidence = excluded.confidence
           where stix_objects.tenant_id is not distinct from excluded.tenant_id
         returning id`,
        [obj.id, tenantId, obj.type, confidence, JSON.stringify(obj)],
      );
      if (result.rows.length === 0) {
        throw new Error("refusing to overwrite an object owned by another tenant");
      }
    };
    if (tenantId === null) {
      const client = await this.pool.connect();
      try {
        await client.query("begin");
        await client.query("select set_config('app.tenant_id', '', true)");
        await run(client);
        await client.query("commit");
      } catch (error) {
        await client.query("rollback");
        throw error;
      } finally {
        client.release();
      }
      return;
    }
    await withTenant(this.pool, tenantId, run);
  }

  async getById(id: string, tenantId: string): Promise<StixObject | null> {
    return withTenant(this.pool, tenantId, async (client) => {
      const result = await client.query("select body from stix_objects where id = $1", [id]);
      const row = result.rows[0] as { body: StixObject } | undefined;
      return row ? asObject(row.body) : null;
    });
  }

  async listVisible(tenantId: string): Promise<Array<{ tenantId: string | null; object: StixObject }>> {
    return withTenant(this.pool, tenantId, async (client) => {
      const result = await client.query("select tenant_id, body from stix_objects");
      return (result.rows as unknown as Row[])
        .filter((row) => visibleToTenant(row.tenant_id, tenantId))
        .map((row) => ({ tenantId: row.tenant_id, object: asObject(row.body) }));
    });
  }

  async getRelated(id: string, depth: number, tenantId: string): Promise<StixObject[]> {
    const memory = new MemoryIntelStore();
    const visible = await this.listVisible(tenantId);
    for (const row of visible) await memory.upsert(row.object, row.tenantId);
    return memory.getRelated(id, depth, tenantId);
  }
}
