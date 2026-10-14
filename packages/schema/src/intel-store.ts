import type { StixObject } from "./stix.js";

/**
 * Storage port for STIX 2.1 objects.
 * Shared objects come from ThreatSieve (ADR 0001) and are stored with a null
 * tenant id. Tenant findings use the same interface with the tenant's id.
 */
export interface IntelStore {
  upsert(obj: StixObject, tenantId: string | null): Promise<void>;
  getById(id: string, tenantId: string): Promise<StixObject | null>;
  getRelated(id: string, depth: number, tenantId: string): Promise<StixObject[]>;
  listVisible(tenantId: string): Promise<Array<{ tenantId: string | null; object: StixObject }>>;
}

export function visibleToTenant(rowTenant: string | null, requester: string): boolean {
  return rowTenant === null || rowTenant === requester;
}

function refsOf(obj: StixObject): string[] {
  const refs: string[] = [];
  for (const key of ["source_ref", "target_ref", "sighting_of_ref", "created_by_ref"] as const) {
    const value = obj[key];
    if (typeof value === "string") refs.push(value);
  }
  const many = obj.object_refs;
  if (Array.isArray(many)) {
    for (const item of many) if (typeof item === "string") refs.push(item);
  }
  return refs;
}

export class MemoryIntelStore implements IntelStore {
  private rows: Array<{ tenantId: string | null; object: StixObject }> = [];

  async upsert(obj: StixObject, tenantId: string | null): Promise<void> {
    const index = this.rows.findIndex((row) => row.object.id === obj.id);
    if (index >= 0) {
      const existing = this.rows[index];
      if (existing.tenantId !== tenantId) {
        throw new Error("refusing to overwrite an object owned by another tenant");
      }
      this.rows[index] = { tenantId, object: obj };
      return;
    }
    this.rows.push({ tenantId, object: obj });
  }

  async getById(id: string, tenantId: string): Promise<StixObject | null> {
    const row = this.rows.find((item) => item.object.id === id && visibleToTenant(item.tenantId, tenantId));
    return row?.object ?? null;
  }

  async listVisible(tenantId: string): Promise<Array<{ tenantId: string | null; object: StixObject }>> {
    return this.rows.filter((row) => visibleToTenant(row.tenantId, tenantId));
  }

  async getRelated(id: string, depth: number, tenantId: string): Promise<StixObject[]> {
    const visible = await this.listVisible(tenantId);
    const byId = new Map(visible.map((row) => [row.object.id, row.object]));
    if (!byId.has(id)) return [];
    const seen = new Set<string>([id]);
    let frontier = [id];
    for (let d = 0; d < depth; d++) {
      const next: string[] = [];
      for (const obj of byId.values()) {
        if (seen.has(obj.id)) continue;
        const refs = refsOf(obj);
        const touches = frontier.some((item) => refs.includes(item) || obj.id === item);
        const frontierRefs = frontier.flatMap((item) => refsOf(byId.get(item) ?? { type: "", spec_version: "2.1", id: item }));
        if (touches || frontierRefs.includes(obj.id)) {
          seen.add(obj.id);
          next.push(obj.id);
        }
      }
      frontier = next;
      if (frontier.length === 0) break;
    }
    return [...seen].map((item) => byId.get(item)!).filter(Boolean);
  }
}

export interface SearchDoc {
  id: string;
  tenant_id: string | null;
  body: StixObject;
}

/** OpenSearch alias filter: a tenant sees its rows and shared rows (tenant_id null). */
export function tenantAliasFilter(tenantId: string): Record<string, unknown> {
  return {
    bool: {
      should: [
        { term: { tenant_id: tenantId } },
        { bool: { must_not: { exists: { field: "tenant_id" } } } },
      ],
      minimum_should_match: 1,
    },
  };
}

export const STIX_INDEX = {
  name: "stix-v1",
  mappings: {
    properties: {
      tenant_id: { type: "keyword" },
      type: { type: "keyword" },
      name: { type: "text" },
      body: { type: "object", enabled: false },
    },
  },
};

export function aliasName(tenantId: string): string {
  return `stix-${tenantId}`;
}

export function searchWithAlias(docs: SearchDoc[], tenantId: string): SearchDoc[] {
  return docs.filter((doc) => doc.tenant_id === null || doc.tenant_id === tenantId);
}
