import { audit } from "./audit.js";
import type { Db } from "./types.js";

export interface ReverifyResult {
  checked: number;
  lapsed: number;
}

const FORTNIGHT_MS = 14 * 24 * 60 * 60 * 1000;

/**
 * Weekly TXT check. Uses the migration connection, not cti_app, because the
 * job has to see every organisation. Email-verified domains are left alone.
 */
export async function reverifyDomains(
  db: Db,
  resolveTxt: (domain: string) => Promise<string[][]>,
  now: Date,
): Promise<ReverifyResult> {
  const rows = await db.query<{
    id: string;
    tenant_id: string;
    domain: string;
    token: string;
    method: string | null;
    txt_missing_since: string | Date | null;
  }>("select id, tenant_id, domain, token, method, txt_missing_since from verified_domains where status = 'verified'");
  let lapsed = 0;
  for (const row of rows.rows) {
    if (row.method === "email") continue;
    const txt = (await resolveTxt(row.domain)).flat().join(" ");
    if (txt.includes(row.token)) {
      await db.query("update verified_domains set txt_missing_since = null where id = $1", [row.id]);
      continue;
    }
    const since = row.txt_missing_since ? new Date(row.txt_missing_since) : now;
    if (!row.txt_missing_since) {
      await db.query("update verified_domains set txt_missing_since = $2 where id = $1", [row.id, now.toISOString()]);
    }
    if (now.getTime() - since.getTime() >= FORTNIGHT_MS) {
      await db.query("update verified_domains set status = 'lapsed' where id = $1", [row.id]);
      lapsed += 1;
      await audit(db, {
        tenantId: row.tenant_id,
        action: "domain_lapsed",
        targetType: "verified_domain",
        targetId: row.id,
        metadata: { domain: row.domain },
      });
    }
  }
  return { checked: rows.rows.length, lapsed };
}
