import { domainToASCII } from "node:url";
import { RateLimiter, runCollector, type Collector } from "@community-cti/collectors";
import { permutations, type PermutationReason } from "@community-cti/intel";
import type { TlpMarking } from "@community-cti/schema";
import { emptyCounts, isApproved, type Dns, type JobCounts, type WorkerContext } from "./context.js";
import { insertObservation, markResult, readState, withCollectorSession } from "./db.js";
import { liveEnrichDeps, loadTenantDomains, normaliseDomain, processHits, type EnrichDeps, type LookalikeHit, type Origin } from "./lookalike.js";
import { redact } from "./log.js";

export const SOURCE_ID = "dns-permutation";
const DAY_MS = 86_400_000;

export interface ResolveOptions {
  concurrency?: number;
  perSecond?: number;
  timeoutMs?: number;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
}

export interface DnsVerdict {
  domain: string;
  status: "registered" | "nxdomain" | "failed";
}

class LookupTimeout extends Error {
  readonly code = "ETIMEOUT";
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new LookupTimeout("dns lookup timed out")), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Is each name registered? One A query per name: NXDOMAIN means not registered,
 * an answer or NODATA means it exists. AAAA and MX are asked only when A has no
 * records. Every query waits for a shared token, so the whole job stays under
 * `perSecond` queries with at most `concurrency` in flight.
 */
export async function resolveCandidates(domains: string[], dns: Pick<Dns, "resolve4" | "resolve6" | "resolveMx">, options: ResolveOptions): Promise<DnsVerdict[]> {
  const limiter = new RateLimiter(options.perSecond ?? 20, 1000, options.now);
  const timeoutMs = options.timeoutMs ?? 3000;
  const query = async <T>(fn: () => Promise<T>): Promise<T> => {
    for (let delay = limiter.delayForNext(); delay > 0; delay = limiter.delayForNext()) await options.sleep(delay);
    return withTimeout(fn(), timeoutMs);
  };
  const code = (error: unknown) => (error as { code?: string }).code;
  const verdict = async (domain: string): Promise<DnsVerdict["status"]> => {
    const ascii = domainToASCII(domain) || domain;
    try {
      if ((await query(() => dns.resolve4(ascii))).length > 0) return "registered";
    } catch (error) {
      if (code(error) === "ENOTFOUND") return "nxdomain";
      if (code(error) !== "ENODATA") return "failed";
    }
    for (const next of [() => dns.resolve6(ascii), async () => (await dns.resolveMx(ascii)).map((record) => record.exchange)]) {
      try {
        if ((await query(next)).length > 0) return "registered";
      } catch (error) {
        if (code(error) === "ENOTFOUND") return "nxdomain";
      }
    }
    return "registered";
  };
  const out: DnsVerdict[] = [];
  let next = 0;
  const workers = Array.from({ length: Math.min(options.concurrency ?? 10, domains.length) }, async () => {
    while (next < domains.length) {
      const domain = domains[next++]!;
      out.push({ domain, status: await verdict(domain) });
    }
  });
  await Promise.all(workers);
  return out;
}

interface Plan {
  tenantId: string;
  watched: string;
  domain: string;
  reason: PermutationReason;
}

/**
 * Candidates from exactly what each tenant verified (a verified subdomain lends
 * only its first label), never equal to or under any member's verified domain
 * or the tenant's legitimate ones.
 */
export function permutationPlan(tenants: Array<{ tenantId: string; verified: string[]; legitimate: string[] }>, limit?: number): Plan[] {
  const allVerified = tenants.flatMap((tenant) => tenant.verified.map(normaliseDomain));
  const plan: Plan[] = [];
  for (const tenant of tenants) {
    const exclude = [...allVerified, ...tenant.legitimate.map(normaliseDomain)];
    for (const watched of tenant.verified.map(normaliseDomain)) {
      for (const item of permutations(watched, { limit, exclude })) plan.push({ tenantId: tenant.tenantId, watched, domain: item.domain, reason: item.reason });
    }
  }
  return plan;
}

async function storeRegistered(ctx: WorkerContext, domains: string[]): Promise<Map<string, Origin>> {
  const source = ctx.sources.get(SOURCE_ID)!;
  const collectedAt = ctx.now().toISOString();
  const collector: Collector<Record<string, unknown>> = {
    sourceId: SOURCE_ID,
    async collect() {
      return domains.map((domain) => ({
        record: { domain, extracted_domain: domain, registered: true },
        provenance: { sourceId: SOURCE_ID, collectedAt, licence: source.licence, accessRestriction: "TLP:CLEAR", evidenceRefs: [] },
      }));
    },
  };
  await withCollectorSession(ctx.pool, (client) =>
    runCollector({ source, collector, since: new Date(0), now: ctx.now(), putRaw: ctx.putRaw, insertObservation: (obs) => insertObservation(client, obs) }));
  const rows = await ctx.pool.query(
    `select distinct on (extracted_domain) id, extracted_domain, collected_at, licence, tlp, raw_key from observations
     where tenant_id is null and source_id = $1 and extracted_domain = any($2::text[])
     order by extracted_domain, collected_at desc`,
    [SOURCE_ID, domains],
  );
  return new Map(rows.rows.map((row) => [String(row.extracted_domain), {
    sourceId: SOURCE_ID,
    collectedAt: new Date(String(row.collected_at)).toISOString(),
    licence: String(row.licence),
    tlp: String(row.tlp) as TlpMarking,
    label: `DNS shows ${String(row.extracted_domain)} is registered`,
    url: null,
    objectKey: String(row.raw_key),
    ref: String(row.id),
  }]));
}

/**
 * Daily: generate lookalikes of each verified domain, keep the ones that are
 * registered, and send them through the usual enrichment and scoring. Each
 * domain's DNS results are cached for a day in collector_runs.
 */
export async function runPermutations(ctx: WorkerContext, options: { tenantIds?: string[]; deps?: EnrichDeps; resolve?: Omit<ResolveOptions, "sleep" | "now"> } = {}): Promise<JobCounts> {
  const counts = emptyCounts();
  if (!isApproved(ctx, SOURCE_ID)) {
    counts.skipped = 1;
    return counts;
  }
  const tenants = await loadTenantDomains(ctx, options.tenantIds);
  counts.tenants = tenants.length;
  const plan = permutationPlan(tenants);
  counts.candidates = plan.length;
  const registered = new Set<string>();
  const byWatched = new Map<string, Set<string>>();
  for (const item of plan) {
    byWatched.set(item.watched, (byWatched.get(item.watched) ?? new Set()).add(item.domain));
  }
  const resolveOptions = { ...options.resolve, sleep: ctx.sleep, now: () => ctx.now().getTime() };
  for (const [watched, candidates] of byWatched) {
    const key = `permutations:${watched}`;
    const state = await readState(ctx.pool, key);
    if (state.lastSuccessAt && ctx.now().getTime() - state.lastSuccessAt.getTime() < DAY_MS) {
      const cached = await ctx.pool.query("select summary->'registered' as registered from collector_runs where key = $1", [key]);
      for (const domain of (cached.rows[0]?.registered as string[] | null) ?? []) if (candidates.has(domain)) registered.add(domain);
      counts.cached = (counts.cached ?? 0) + 1;
      continue;
    }
    try {
      const verdicts = await resolveCandidates([...candidates], ctx.dns, resolveOptions);
      const found = verdicts.filter((item) => item.status === "registered").map((item) => item.domain);
      for (const domain of found) registered.add(domain);
      counts.fetched += verdicts.length;
      counts.registered = (counts.registered ?? 0) + found.length;
      counts.nxdomain = (counts.nxdomain ?? 0) + verdicts.filter((item) => item.status === "nxdomain").length;
      counts.dnsFailed = (counts.dnsFailed ?? 0) + verdicts.filter((item) => item.status === "failed").length;
      await markResult(ctx.pool, key, ctx.now(), null, { candidates: verdicts.length, registered: found });
    } catch (error) {
      counts.errors += 1;
      await markResult(ctx.pool, key, ctx.now(), redact(error));
    }
  }
  if (registered.size === 0) return counts;
  const origins = await storeRegistered(ctx, [...registered]);
  const hits: LookalikeHit[] = plan
    .filter((item) => registered.has(item.domain) && origins.has(item.domain))
    .map((item) => ({ tenantId: item.tenantId, watched: item.watched, domain: item.domain, reason: item.reason, origins: [origins.get(item.domain)!] }));
  counts.hits = hits.length;
  await processHits(ctx, hits, options.deps ?? liveEnrichDeps(ctx), counts);
  return counts;
}
