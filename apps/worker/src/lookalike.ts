import { domainToASCII, domainToUnicode } from "node:url";
import { crtShUrl, normaliseUrl, RateLimiter, runCollector, type Collector } from "@community-cti/collectors";
import { isVerified } from "@community-cti/db";
import {
  buildMatcher,
  enrichDomain,
  isUnderVerifiedDomain,
  mmh3,
  safeFetch,
  scoreLookalike,
  type CertMatch,
  type Enrichment,
  type SafeFetchResult,
  type Score,
} from "@community-cti/intel";
import { buildDomainName, type Provenance, type TlpMarking } from "@community-cti/schema";
import { insertObservation, markAttempt, markResult, readState, withCollectorSession } from "./db.js";
import { emptyCounts, isApproved, type Dns, type JobCounts, type WorkerContext } from "./context.js";
import { findingStatus, persistFinding, type EvidenceDraft, type FindingDraft } from "./findings.js";
import { fetchFeed } from "./http.js";
import { redact } from "./log.js";
import { stableStixId } from "./stable.js";

export interface TenantDomains {
  tenantId: string;
  verified: string[];
  legitimate: string[];
}

export interface Origin {
  sourceId: string;
  collectedAt: string;
  licence: string;
  tlp: TlpMarking;
  label: string;
  url: string | null;
  objectKey: string | null;
  ref: string;
}

export interface Candidate {
  domain: string;
  origins: Origin[];
}

export interface LookalikeHit {
  tenantId: string;
  watched: string;
  domain: string;
  reason: CertMatch["reason"];
  origins: Origin[];
}

export interface EnrichDeps {
  lookupDns(domain: string): Promise<{ a: string[]; aaaa: string[]; mx: string[] }>;
  fetchRdap(domain: string): Promise<{ registration?: string } | null>;
  fetchPage(url: string): Promise<SafeFetchResult>;
  /** Favicon hash of the tenant's own site, so a copied icon counts against the lookalike. */
  tenantFaviconHash?(domain: string): Promise<number | null>;
}

/** Sources whose observations carry a domain worth matching. */
export const CANDIDATE_SOURCES = ["crtsh", "urlhaus", "openphish", "phishtank"];
const MAX_ORIGINS = 5;
const CANDIDATE_WINDOW_MS = 7 * 86_400_000;
const DAY_MS = 86_400_000;

export function normaliseDomain(value: string): string {
  return domainToUnicode(value.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "")) || value.trim().toLowerCase();
}

/** Reduce a certificate or URL host to its registered domain, in Unicode form. */
export function registrable(name: string): string | null {
  const host = name.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!host || /[\s/@]/.test(host)) return null;
  try {
    return normaliseUrl(`http://${host}/`).registeredDomain;
  } catch {
    return null;
  }
}

/** First label of the verified name itself. A verified subdomain must not turn its parent's label into a keyword. */
function brandLabel(domain: string): string {
  return domain.split(".")[0] ?? domain;
}

export function mergeCandidates(candidates: Candidate[]): Candidate[] {
  const byDomain = new Map<string, Candidate>();
  for (const candidate of candidates) {
    const domain = normaliseDomain(candidate.domain);
    const existing = byDomain.get(domain);
    if (!existing) {
      byDomain.set(domain, { domain, origins: candidate.origins.slice(0, MAX_ORIGINS) });
      continue;
    }
    for (const origin of candidate.origins) {
      if (existing.origins.length >= MAX_ORIGINS) break;
      if (!existing.origins.some((item) => item.ref === origin.ref)) existing.origins.push(origin);
    }
  }
  return [...byDomain.values()];
}

/**
 * Match candidate names against every tenant's verified domains. Drops any
 * verified domain (and its subdomains) and each tenant's own legitimate domains.
 */
export function findHits(tenants: TenantDomains[], candidates: Candidate[]): LookalikeHit[] {
  const clean = tenants.map((tenant) => ({
    tenantId: tenant.tenantId,
    verified: tenant.verified.map(normaliseDomain),
    legitimate: tenant.legitimate.map(normaliseDomain),
  }));
  const matcher = buildMatcher(clean.flatMap((tenant) =>
    tenant.verified.map((domain) => ({ tenantId: tenant.tenantId, domain, verified: true, brandKeywords: [brandLabel(domain)] }))));
  const allVerified = clean.flatMap((tenant) => tenant.verified);
  const byTenant = new Map(clean.map((tenant) => [tenant.tenantId, tenant]));
  const hits = new Map<string, LookalikeHit>();
  for (const candidate of mergeCandidates(candidates)) {
    if (isUnderVerifiedDomain(candidate.domain, allVerified)) continue;
    for (const match of matcher.match(candidate.domain)) {
      const tenant = byTenant.get(match.tenantId);
      if (!tenant || isUnderVerifiedDomain(candidate.domain, tenant.legitimate)) continue;
      const key = `${match.tenantId}|${candidate.domain}`;
      const existing = hits.get(key);
      if (existing) {
        if (existing.reason === "keyword" && match.reason !== "keyword") Object.assign(existing, { reason: match.reason, watched: match.watched });
        continue;
      }
      hits.set(key, { tenantId: match.tenantId, watched: match.watched, domain: candidate.domain, reason: match.reason, origins: candidate.origins });
    }
  }
  return [...hits.values()];
}

const REASON_TEXT: Record<CertMatch["reason"], string> = {
  omission: "It is your domain with one letter left out.",
  swap: "It is your domain with two letters swapped.",
  homoglyph: "It uses letters or numbers that look like the ones in your domain.",
  typo: "It is your domain with one small typing slip.",
  "tld-swap": "It is your name with a different ending.",
  keyword: "It contains the name in your domain.",
};

export function lookalikeDedupeKey(domain: string): string {
  return `lookalike:${domain}`;
}

export function lookalikeDraft(hit: LookalikeHit, score: Score, enrichment: Enrichment, now: Date): FindingDraft {
  const domainObject = buildDomainName({
    sourceId: hit.origins[0]!.sourceId,
    licence: hit.origins[0]!.licence,
    collectedAt: now,
    value: domainToASCII(hit.domain) || hit.domain,
    id: stableStixId("domain-name", hit.tenantId, hit.domain),
  });
  const stixObjects = [domainObject, ...(enrichment.note ? [enrichment.note] : [])];
  const stixRefs = stixObjects.map((object) => object.id);
  const provenance: Provenance[] = hit.origins.map((origin) => ({
    sourceId: origin.sourceId,
    ...(origin.url ? { sourceUrl: origin.url } : {}),
    collectedAt: origin.collectedAt,
    licence: origin.licence,
    accessRestriction: origin.tlp,
    evidenceRefs: [origin.ref, domainObject.id],
  }));
  const evidence: EvidenceDraft[] = hit.origins.map((origin) => ({
    label: origin.label,
    url: origin.url,
    objectKey: origin.objectKey,
    sourceId: origin.sourceId,
    licence: origin.licence,
    tlp: origin.tlp,
    collectedAt: origin.collectedAt,
  }));
  const signals = score.factors.filter((factor) => factor.points !== 0 && !["edit_distance_1", "homoglyph"].includes(factor.code)).map((factor) => factor.reason);
  const summary = [
    `We found the website name ${hit.domain}.`,
    `It looks like your domain ${hit.watched}.`,
    REASON_TEXT[hit.reason],
    ...signals,
    "Someone could use it to trick staff or clients.",
  ].join(" ");
  return {
    tenantId: hit.tenantId,
    kind: "lookalike_domain",
    dedupeKey: lookalikeDedupeKey(hit.domain),
    title: `${hit.domain} looks like ${hit.watched}`,
    summary,
    confidence: score.confidence,
    factors: score.factors,
    provenance,
    stixRefs,
    stixObjects,
    evidence,
  };
}

/** Enrich and score one hit. Returns a draft only at or above the threshold. */
export async function assessHit(hit: LookalikeHit, deps: EnrichDeps, now: Date, threshold: number): Promise<{ draft: FindingDraft | null; score: Score }> {
  const tenantFaviconHash = deps.tenantFaviconHash ? await deps.tenantFaviconHash(hit.watched).catch(() => null) : undefined;
  const enrichment = await enrichDomain({
    domain: hit.domain,
    verified: [hit.watched],
    lookalikes: [hit.domain],
    now,
    lookupDns: deps.lookupDns,
    fetchRdap: deps.fetchRdap,
    fetchPage: deps.fetchPage,
    tenantFaviconHash,
    domainObjectId: stableStixId("domain-name", hit.tenantId, hit.domain),
  });
  const score = scoreLookalike({
    editDistance: hit.reason === "omission" || hit.reason === "swap" || hit.reason === "typo" ? 1 : null,
    homoglyph: hit.reason === "homoglyph",
    tldSwap: hit.reason === "tld-swap",
    hasMx: enrichment.hasMx,
    resolves: enrichment.resolves,
    registeredDaysAgo: enrichment.registeredDaysAgo,
    faviconMatch: enrichment.faviconMatch,
    parked: enrichment.parked,
  });
  if (score.confidence < threshold) return { draft: null, score };
  return { draft: lookalikeDraft(hit, score, enrichment, now), score };
}

/** Pure pipeline used by the job and the tests: match, enrich, score, draft. */
export async function lookalikeDrafts(tenants: TenantDomains[], candidates: Candidate[], deps: EnrichDeps, now: Date, threshold: number): Promise<FindingDraft[]> {
  const drafts: FindingDraft[] = [];
  for (const hit of findHits(tenants, candidates)) {
    const { draft } = await assessHit(hit, deps, now, threshold);
    if (draft) drafts.push(draft);
  }
  return drafts;
}

async function waitTurn(limiter: RateLimiter, sleep: (ms: number) => Promise<void>): Promise<void> {
  for (let delay = limiter.delayForNext(); delay > 0; delay = limiter.delayForNext()) await sleep(delay);
}

async function addresses(dns: Dns, host: string): Promise<string[]> {
  const ascii = domainToASCII(host) || host;
  const [v4, v6] = await Promise.all([dns.resolve4(ascii).catch(() => []), dns.resolve6(ascii).catch(() => [])]);
  return [...v4, ...v6];
}

/** Same favicon discovery and hash as enrichDomain, applied to the tenant's own site. */
export async function faviconHashOf(domain: string, fetchPage: EnrichDeps["fetchPage"]): Promise<number | null> {
  const page = await fetchPage(`https://${domain}/`);
  if (!page.ok || !page.body) return null;
  const icon = page.body.match(/<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]*href=["']([^"']+)["']/i)?.[1];
  if (!icon) return null;
  const iconPage = await fetchPage(new URL(icon, `https://${domain}/`).toString());
  return iconPage.ok && iconPage.body ? mmh3(new TextEncoder().encode(iconPage.body)) : null;
}

/** Real DNS, RDAP and page lookups. Page and RDAP fetches go through the SSRF-safe fetcher. */
export function liveEnrichDeps(ctx: WorkerContext): EnrichDeps {
  const rdapLimiter = new RateLimiter(10, 60_000, () => Date.now());
  // No fetchImpl: safeFetch then connects only to the address it checked (IP-pinned), which closes the DNS-rebinding gap.
  const lookup = (host: string) => addresses(ctx.dns, host);
  const userAgent = ctx.config.userAgent;
  const fetchPage = (url: string) => safeFetch({ url, lookup, userAgent, timeoutMs: 10_000, maxBytes: 1_048_576 });
  const favicons = new Map<string, Promise<number | null>>();
  return {
    async lookupDns(domain) {
      const ascii = domainToASCII(domain) || domain;
      const [a, aaaa, mx] = await Promise.all([
        ctx.dns.resolve4(ascii).catch(() => []),
        ctx.dns.resolve6(ascii).catch(() => []),
        ctx.dns.resolveMx(ascii).catch(() => []),
      ]);
      return { a, aaaa, mx: mx.map((record) => record.exchange) };
    },
    async fetchRdap(domain) {
      await waitTurn(rdapLimiter, ctx.sleep);
      const result = await safeFetch({
        url: `https://rdap.org/domain/${domainToASCII(domain) || domain}`,
        lookup,
        userAgent,
        timeoutMs: 15_000,
        maxBytes: 1_048_576,
      });
      if (result.ok && result.status === 404) return null;
      if (!result.ok || result.status !== 200 || !result.body) throw new Error(result.error ?? `rdap HTTP ${result.status}`);
      const events = (JSON.parse(result.body) as { events?: Array<{ eventAction?: string; eventDate?: string }> }).events ?? [];
      const registration = events.find((event) => event.eventAction === "registration")?.eventDate;
      return registration ? { registration } : {};
    },
    fetchPage,
    tenantFaviconHash(domain) {
      if (!favicons.has(domain)) favicons.set(domain, faviconHashOf(domain, fetchPage).catch(() => null));
      return favicons.get(domain)!;
    },
  };
}

interface CrtShEntry {
  id?: number;
  name_value?: string;
  common_name?: string;
  not_before?: string;
  issuer_name?: string;
}

export function parseCrtSh(body: string): Array<{ certId: number; name: string; domain: string; notBefore: string | null; issuer: string | null }> {
  const rows = JSON.parse(body) as unknown;
  if (!Array.isArray(rows)) throw new Error("crt.sh response is not a list");
  const out = new Map<string, { certId: number; name: string; domain: string; notBefore: string | null; issuer: string | null }>();
  for (const row of rows as CrtShEntry[]) {
    if (typeof row?.id !== "number") continue;
    const names = `${row.name_value ?? ""}\n${row.common_name ?? ""}`.split("\n").map((name) => name.trim()).filter(Boolean);
    for (const name of names) {
      const domain = registrable(name);
      if (!domain || out.has(`${row.id}|${domain}`)) continue;
      out.set(`${row.id}|${domain}`, { certId: row.id, name: name.toLowerCase(), domain, notBefore: row.not_before ?? null, issuer: row.issuer_name ?? null });
    }
  }
  return [...out.values()];
}

/**
 * One crt.sh query per verified domain per day. Only names that match a
 * tenant's domain are stored, as shared observations with no tenant data.
 */
async function collectCrtSh(ctx: WorkerContext, tenants: TenantDomains[], counts: JobCounts): Promise<void> {
  if (!isApproved(ctx, "crtsh")) {
    counts.crtshSkipped = 1;
    return;
  }
  const source = ctx.sources.get("crtsh")!;
  const limiter = new RateLimiter(1, 5_000, () => Date.now());
  const domains = [...new Set(tenants.flatMap((tenant) => tenant.verified.map(normaliseDomain)))];
  for (const domain of domains) {
    const key = `crtsh:${domain}`;
    const state = await readState(ctx.pool, key);
    const now = ctx.now();
    if (state.lastAttemptAt && now.getTime() - state.lastAttemptAt.getTime() < DAY_MS) continue;
    await markAttempt(ctx.pool, key, now);
    await waitTurn(limiter, ctx.sleep);
    const url = crtShUrl(brandLabel(domain), true);
    try {
      const { body } = await fetchFeed({ url, allow: ["https://crt.sh/"], userAgent: ctx.config.userAgent, fetchImpl: ctx.fetchImpl, sleep: ctx.sleep, timeoutMs: 60_000, retries: 1 });
      counts.crtshQueries = (counts.crtshQueries ?? 0) + 1;
      const entries = parseCrtSh(body.toString("utf8"));
      const collectedAt = ctx.now().toISOString();
      const matched = new Set(findHits(tenants, entries.map((entry) => ({ domain: entry.domain, origins: [] }))).map((hit) => hit.domain));
      const keep = entries.filter((entry) => matched.has(entry.domain));
      counts.fetched += entries.length;
      const collector: Collector<Record<string, unknown>> = {
        sourceId: "crtsh",
        async collect() {
          return keep.map((entry) => ({
            record: { cert_id: entry.certId, name: entry.name, extracted_domain: entry.domain, not_before: entry.notBefore, issuer_name: entry.issuer },
            provenance: { sourceId: "crtsh", sourceUrl: `https://crt.sh/?id=${entry.certId}`, collectedAt, licence: source.licence, accessRestriction: "TLP:CLEAR", evidenceRefs: [] },
          }));
        },
      };
      const result = await withCollectorSession(ctx.pool, (client) =>
        runCollector({ source, collector, since: new Date(0), now: ctx.now(), putRaw: ctx.putRaw, insertObservation: (obs) => insertObservation(client, obs) }));
      counts.inserted += result.inserted;
      counts.duplicates += result.duplicates;
      await markResult(ctx.pool, key, ctx.now(), null, { entries: entries.length, kept: keep.length });
    } catch (error) {
      counts.errors += 1;
      await markResult(ctx.pool, key, ctx.now(), redact(error));
    }
  }
}

const ORIGIN_LABEL: Record<string, (domain: string) => string> = {
  crtsh: (domain) => `Certificate log entry for ${domain}`,
  urlhaus: (domain) => `URLhaus lists a harmful link on ${domain}`,
  openphish: (domain) => `OpenPhish lists a phishing link on ${domain}`,
  phishtank: (domain) => `PhishTank lists a phishing link on ${domain}`,
};

async function loadCandidates(ctx: WorkerContext): Promise<Candidate[]> {
  const sources = CANDIDATE_SOURCES.filter((id) => isApproved(ctx, id));
  if (sources.length === 0) return [];
  const result = await ctx.pool.query(
    `select id, source_id, collected_at, licence, tlp, raw_key, extracted_domain,
            payload->>'reference' as reference, payload->>'cert_id' as cert_id
     from observations
     where tenant_id is null and extracted_domain is not null and source_id = any($1) and collected_at > $2
     order by collected_at desc`,
    [sources, new Date(ctx.now().getTime() - CANDIDATE_WINDOW_MS)],
  );
  return result.rows.map((row) => {
    const sourceId = String(row.source_id);
    const domain = String(row.extracted_domain);
    const certId = row.cert_id && /^\d+$/.test(String(row.cert_id)) ? String(row.cert_id) : null;
    const url = sourceId === "crtsh" && certId ? `https://crt.sh/?id=${certId}` : typeof row.reference === "string" && row.reference.startsWith("https://") ? row.reference : null;
    return {
      domain,
      origins: [{
        sourceId,
        collectedAt: new Date(String(row.collected_at)).toISOString(),
        licence: String(row.licence),
        tlp: String(row.tlp) as TlpMarking,
        label: (ORIGIN_LABEL[sourceId] ?? ((name: string) => `Feed entry for ${name}`))(domain),
        url,
        objectKey: String(row.raw_key),
        ref: String(row.id),
      }],
    };
  });
}

export async function loadTenantDomains(ctx: WorkerContext, tenantIds?: string[]): Promise<TenantDomains[]> {
  const verified = await ctx.pool.query(
    "select tenant_id, domain, status, verified_at from verified_domains where status = 'verified' and ($1::uuid[] is null or tenant_id = any($1))",
    [tenantIds ?? null],
  );
  const legit = await ctx.pool.query("select tenant_id, domain from legitimate_domains where ($1::uuid[] is null or tenant_id = any($1))", [tenantIds ?? null]);
  const byTenant = new Map<string, TenantDomains>();
  for (const row of verified.rows) {
    if (!isVerified({ status: String(row.status), verifiedAt: row.verified_at ? String(row.verified_at) : null })) continue;
    const tenantId = String(row.tenant_id);
    const entry = byTenant.get(tenantId) ?? { tenantId, verified: [], legitimate: [] };
    entry.verified.push(String(row.domain));
    byTenant.set(tenantId, entry);
  }
  for (const row of legit.rows) byTenant.get(String(row.tenant_id))?.legitimate.push(String(row.domain));
  return [...byTenant.values()];
}

/** Daily-gated per tenant and domain so a known hit is not re-enriched every hour. */
export async function runLookalikes(ctx: WorkerContext, options: { tenantIds?: string[]; deps?: EnrichDeps } = {}): Promise<JobCounts> {
  const counts = emptyCounts();
  const tenants = await loadTenantDomains(ctx, options.tenantIds);
  counts.tenants = tenants.length;
  if (tenants.length === 0) return counts;
  await collectCrtSh(ctx, tenants, counts);
  const hits = findHits(tenants, await loadCandidates(ctx));
  counts.hits = hits.length;
  await processHits(ctx, hits, options.deps ?? liveEnrichDeps(ctx), counts);
  return counts;
}

/**
 * Enrich, score and persist each hit. Skips dismissed or resolved findings and
 * anything enriched in the last day, so reruns do not repeat lookups or alerts.
 */
export async function processHits(ctx: WorkerContext, hits: LookalikeHit[], deps: EnrichDeps, counts: JobCounts): Promise<void> {
  for (const hit of hits) {
    const status = await findingStatus(ctx.pool, hit.tenantId, lookalikeDedupeKey(hit.domain));
    if (status === "dismissed" || status === "resolved") {
      counts.suppressed = (counts.suppressed ?? 0) + 1;
      continue;
    }
    const key = `enrich:${hit.tenantId}:${hit.domain}`;
    const state = await readState(ctx.pool, key);
    if (state.lastSuccessAt && ctx.now().getTime() - state.lastSuccessAt.getTime() < DAY_MS) continue;
    try {
      const { draft, score } = await assessHit(hit, deps, ctx.now(), ctx.config.findingMinConfidence);
      counts.enriched = (counts.enriched ?? 0) + 1;
      if (!draft) counts.belowThreshold = (counts.belowThreshold ?? 0) + 1;
      else {
        const persisted = await persistFinding(ctx.pool, ctx.intel, draft);
        if (persisted.outcome === "inserted") counts.findings += 1;
        else if (persisted.outcome === "updated") counts.rescored = (counts.rescored ?? 0) + 1;
      }
      await markResult(ctx.pool, key, ctx.now(), null, { confidence: score.confidence });
    } catch (error) {
      counts.errors += 1;
      await markResult(ctx.pool, key, ctx.now(), redact(error));
    }
  }
}
