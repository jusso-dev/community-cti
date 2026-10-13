/** OpenSearch index and per-tenant alias filter. Shared objects have a null tenant_id. */
export const STIX_INDEX = {
  name: "stix-v1",
  mappings: {
    properties: {
      tenant_id: { type: "keyword" },
      type: { type: "keyword" },
      text: { type: "text" },
    },
  },
};

export function aliasFilter(tenantId: string): Record<string, unknown> {
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

export function visibleToTenant(docTenant: string | null, aliasTenant: string): boolean {
  return docTenant === null || docTenant === aliasTenant;
}
