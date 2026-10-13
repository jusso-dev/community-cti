import type { Db } from "./types.js";
import { withTenant } from "./tenant.js";

/** Downstream lookups must call this before they touch a domain. */
export async function isVerified(db: Db, tenantId: string, domain: string): Promise<boolean> {
  const result = await withTenant(db, tenantId, (tx) =>
    tx.query(
      "select 1 from verified_domains where lower(domain) = lower($1) and status = 'verified'",
      [domain],
    ),
  );
  return result.rows.length > 0;
}
