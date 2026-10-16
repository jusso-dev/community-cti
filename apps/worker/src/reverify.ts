import { domainToASCII } from "node:url";
import { audit, reverifyDecision, withTenant, type ReverifyState } from "@community-cti/db";
import { emptyCounts, type Dns, type JobCounts, type WorkerContext } from "./context.js";
import { redact } from "./log.js";

const MISSING = new Set(["ENOTFOUND", "ENODATA"]);

/** True or false when DNS answered; null when the lookup failed and nothing should change. */
export async function txtPresent(dns: Pick<Dns, "resolveTxt">, domain: string, token: string): Promise<boolean | null> {
  try {
    const records = await dns.resolveTxt(domainToASCII(domain) || domain);
    const values = records.flatMap((chunks) => [chunks.join(""), ...chunks]);
    return values.some((value) => value.trim() === `cti-verify=${token}`);
  } catch (error) {
    const code = (error as { code?: string }).code;
    return code && MISSING.has(code) ? false : null;
  }
}

export async function runReverify(ctx: WorkerContext, options: { tenantIds?: string[] } = {}): Promise<JobCounts> {
  const counts = emptyCounts();
  const rows = await ctx.pool.query(
    `select id, tenant_id, domain, verify_token, status, txt_missing_since from verified_domains
     where status = 'verified' and method = 'dns_txt' and ($1::uuid[] is null or tenant_id = any($1))`,
    [options.tenantIds ?? null],
  );
  for (const row of rows.rows) {
    const present = await txtPresent(ctx.dns, String(row.domain), String(row.verify_token));
    counts.fetched += 1;
    if (present === null) {
      counts.errors += 1;
      continue;
    }
    const state: ReverifyState = {
      status: "verified",
      txtMissingSince: row.txt_missing_since ? new Date(String(row.txt_missing_since)).toISOString() : null,
    };
    const next = reverifyDecision(state, present, ctx.now());
    if (next.status === state.status && next.txtMissingSince === state.txtMissingSince) continue;
    const tenantId = String(row.tenant_id);
    try {
      await withTenant(ctx.pool, tenantId, async (client) => {
        await client.query("update verified_domains set status = $1, txt_missing_since = $2 where id = $3 and tenant_id = $4", [next.status, next.txtMissingSince, row.id, tenantId]);
        if (next.status === "lapsed") {
          await audit(client, { tenantId, actorId: null, action: "domain.lapsed", targetType: "verified_domain", targetId: String(row.id), metadata: { txtMissingSince: next.txtMissingSince } });
        }
      });
      if (next.status === "lapsed") counts.lapsed = (counts.lapsed ?? 0) + 1;
      else counts.updated = (counts.updated ?? 0) + 1;
    } catch (error) {
      counts.errors += 1;
      ctx.log({ level: "error", job: "reverify-domains", error: redact(error) });
    }
  }
  return counts;
}
