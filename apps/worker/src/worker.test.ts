import { test } from "node:test";
import assert from "node:assert/strict";
import { runCollector } from "@community-cti/collectors";
import { buildIndicator, buildReport } from "@community-cti/schema";
import { SinkMailer } from "@community-cti/notify";
import type pg from "pg";
import { planAlerts, renderDigest } from "./alerts.js";
import { runFeed, type FeedDefinition } from "./collect.js";
import { loadConfig } from "./config.js";
import type { WorkerContext } from "./context.js";
import { draftToFinding } from "./findings.js";
import { effectiveSources, ignoredTestApprovals, loadSourcesDoc } from "./governance.js";
import { fetchFeed, type FetchLike } from "./http.js";
import { findHits, lookalikeDrafts, mergeCandidates, parseCrtSh, type Candidate, type EnrichDeps, type Origin, type TenantDomains } from "./lookalike.js";
import { redact } from "./log.js";
import { matchVictims, ransomwareDedupeKey, runAuRansomware, type Victim } from "./ransomware.js";
import { runAdvisories, toAdvisory } from "./advisories.js";
import { txtPresent } from "./reverify.js";
import { buildJobs, cadenceMs, isDue, selectJobs, type Job } from "./scheduler.js";
import { stabilise } from "./stable.js";

const NOW = new Date("2026-10-16T00:00:00.000Z");
const rows = loadSourcesDoc();

function origin(sourceId: string, ref: string): Origin {
  return {
    sourceId,
    collectedAt: "2026-10-15T00:00:00.000Z",
    licence: `${sourceId} terms`,
    tlp: "TLP:CLEAR",
    label: `${sourceId} entry`,
    url: sourceId === "crtsh" ? "https://crt.sh/?id=1" : null,
    objectKey: `raw/${sourceId}/2026/10/15/${ref}.json`,
    ref,
  };
}

function fakeCtx(overrides: Partial<WorkerContext> = {}): WorkerContext {
  return {
    pool: {} as pg.Pool,
    config: loadConfig({ DATABASE_URL: "postgres://unused" }),
    sources: effectiveSources(rows, [], "development"),
    fetchImpl: async () => {
      throw new Error("network is not allowed in unit tests");
    },
    dns: {
      resolve4: async () => [],
      resolve6: async () => [],
      resolveMx: async () => [],
      resolveTxt: async () => [],
    },
    sleep: async () => {},
    now: () => NOW,
    mailer: new SinkMailer(),
    log: () => {},
    putRaw: async () => {},
    intel: { upsert: async () => {}, getById: async () => null, getRelated: async () => [], listVisible: async () => [] },
    ...overrides,
  };
}

const TENANT: TenantDomains = { tenantId: "t1", verified: ["examplecouncil.org.au"], legitimate: ["exampecouncil.org.au"] };

/** examp1ecouncil resolves, has mail and is 10 days old. Everything else does not resolve. */
const deps: EnrichDeps = {
  async lookupDns(domain) {
    if (domain === "examp1ecouncil.org.au") return { a: ["203.0.113.10"], aaaa: [], mx: ["mx.examp1ecouncil.org.au"] };
    throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
  },
  async fetchRdap(domain) {
    return domain === "examp1ecouncil.org.au" ? { registration: "2026-10-06T00:00:00Z" } : null;
  },
  async fetchPage() {
    return { ok: false, error: "timeout" };
  },
};

const candidates: Candidate[] = [
  { domain: "examp1ecouncil.org.au", origins: [origin("crtsh", "obs-1")] },
  { domain: "EXAMP1ECOUNCIL.org.au", origins: [origin("openphish", "obs-2"), origin("crtsh", "obs-1")] },
  { domain: "examplecouncl.org.au", origins: [origin("urlhaus", "obs-3")] },
  { domain: "exampecouncil.org.au", origins: [origin("openphish", "obs-4")] },
  { domain: "examplecouncil.org.au", origins: [origin("crtsh", "obs-5")] },
];

test("TEST_APPROVED_SOURCES is refused in production", () => {
  assert.throws(() => loadConfig({ DATABASE_URL: "postgres://x", CTI_ENV: "production", TEST_APPROVED_SOURCES: "cisa-kev" }), /production/);
  assert.throws(() => effectiveSources(rows, ["cisa-kev"], "production"), /production/);
  assert.doesNotThrow(() => loadConfig({ DATABASE_URL: "postgres://x", CTI_ENV: "production" }));
  assert.equal(loadConfig({ DATABASE_URL: "postgres://x", TEST_APPROVED_SOURCES: " cisa-kev, epss " }).testApprovedSources.join(","), "cisa-kev,epss");
});

test("test approvals lift candidates only, never blocked or deferred sources", () => {
  const sources = effectiveSources(rows, ["cisa-kev", "stealer-logs", "underground"], "development");
  assert.equal(sources.get("cisa-kev")?.status, "approved");
  assert.equal(sources.get("epss")?.status, "candidate");
  assert.equal(sources.get("stealer-logs")?.status, "blocked");
  assert.equal(sources.get("underground")?.status, "blocked");
  assert.equal(sources.get("threatsieve")?.status, "approved");
  assert.deepEqual(ignoredTestApprovals(rows, ["stealer-logs", "nope"]).map((item) => item.reason), ["blocked", "not in SOURCES.md"]);
  assert.equal(effectiveSources(rows, [], "development").get("cisa-kev")?.status, "candidate");
});

test("blocked and unapproved sources never fetch", async () => {
  let loads = 0;
  const sources = effectiveSources(rows, ["stealer-logs"], "development");
  const ctx = fakeCtx({ sources });
  const def = (id: string): FeedDefinition => ({ id, async load() { loads += 1; return []; } });
  assert.equal((await runFeed(ctx, def("stealer-logs"))).skipped, 1);
  assert.equal((await runFeed(ctx, def("cisa-kev"))).skipped, 1);
  assert.equal(loads, 0);
  await assert.rejects(
    runCollector({ source: sources.get("stealer-logs")!, collector: { sourceId: "stealer-logs", async collect() { return []; } }, since: NOW, putRaw: async () => {}, insertObservation: async () => "inserted" }),
    /not approved/,
  );
});

test("lookalike pipeline raises one finding with provenance and factors for a homoglyph hit", async () => {
  const drafts = await lookalikeDrafts([TENANT], candidates, deps, NOW, 40);
  assert.equal(drafts.length, 1);
  const draft = drafts[0]!;
  assert.equal(draft.kind, "lookalike_domain");
  assert.equal(draft.dedupeKey, "lookalike:examp1ecouncil.org.au");
  assert.equal(draft.confidence, 65);
  assert.deepEqual(draft.factors.map((factor) => factor.code).sort(), ["has_mx", "homoglyph", "new_registration", "resolves"]);
  assert.deepEqual(draft.provenance.map((item) => item.sourceId), ["crtsh", "openphish"]);
  assert.ok(draft.provenance.every((item) => item.licence && item.collectedAt && item.accessRestriction && item.evidenceRefs.length > 0));
  assert.equal(draft.evidence.length, 2);
  assert.equal(draft.evidence[0]?.url, "https://crt.sh/?id=1");
  assert.ok(draft.stixRefs.length >= 1);
  assert.match(draft.summary, /examplecouncil\.org\.au/);
  assert.doesNotThrow(() => draftToFinding(draft, "f1"));
});

test("own, legitimate and below-threshold names raise nothing", async () => {
  const hits = findHits([TENANT], candidates);
  assert.deepEqual(hits.map((hit) => [hit.domain, hit.reason]).sort(), [["examp1ecouncil.org.au", "homoglyph"], ["examplecouncl.org.au", "omission"]]);
  assert.equal((await lookalikeDrafts([TENANT], candidates, deps, NOW, 70)).length, 0);
  const onlyWeak = candidates.filter((item) => item.domain === "examplecouncl.org.au");
  assert.equal((await lookalikeDrafts([TENANT], onlyWeak, deps, NOW, 40)).length, 0);
  const other: TenantDomains = { tenantId: "t2", verified: ["examp1ecouncil.org.au"], legitimate: [] };
  assert.equal(findHits([TENANT, other], candidates).some((hit) => hit.domain === "examp1ecouncil.org.au"), false);
});

test("candidates dedupe by domain and origin, and dedupe keys are stable", () => {
  const merged = mergeCandidates(candidates);
  const homoglyph = merged.find((item) => item.domain === "examp1ecouncil.org.au")!;
  assert.deepEqual(homoglyph.origins.map((item) => item.ref), ["obs-1", "obs-2"]);
  assert.equal(ransomwareDedupeKey({ externalId: "examplegroup:example land council:2026-10-15" }), "ransomware:examplegroup:example land council:2026-10-15");
  const objects = () => {
    const indicator = buildIndicator({ sourceId: "x", licence: "x", collectedAt: NOW, name: "n", pattern: "[url:value = 'a']" });
    return [buildReport({ sourceId: "x", licence: "x", collectedAt: NOW, name: "r", published: "2026-10-15T00:00:00.000Z", objectRefs: [indicator.id] })];
  };
  const first = stabilise(objects(), "seed");
  const second = stabilise(objects(), "seed");
  assert.equal(first[0]!.id, second[0]!.id);
  assert.deepEqual(first[0]!.object_refs, second[0]!.object_refs);
});

test("alert delivery respects each member's preference", () => {
  const members = [
    { userId: "a", mode: "immediate" as const },
    { userId: "b", mode: "digest" as const },
    { userId: "c", mode: "off" as const },
    { userId: "d", mode: null },
  ];
  assert.deepEqual(planAlerts(80, members).map((item) => item.delivery), ["immediate", "digest", "none", "digest"]);
  assert.deepEqual(planAlerts(55, members).map((item) => item.delivery), ["digest", "digest", "none", "digest"]);
  assert.deepEqual(planAlerts(30, members).map((item) => item.delivery), ["none", "none", "none", "none"]);
  const digest = renderDigest("Example Council", [{ findingId: "f1", title: "x looks like y", confidence: 55 }], "https://portal.example");
  assert.match(digest.text, /https:\/\/portal\.example\/findings\/f1/);
  assert.match(digest.text, /Confidence: 55 out of 100/);
});

test("feed fetches stay on allow-listed hosts, retry twice and cap the body", async () => {
  const calls: string[] = [];
  const sleeps: number[] = [];
  const respond = (handler: (url: string, n: number) => Response): FetchLike => async (url) => {
    calls.push(url);
    return handler(url, calls.length);
  };
  const base = { allow: ["https://feed.example/"], userAgent: "test-agent", sleep: async (ms: number) => { sleeps.push(ms); } };

  await assert.rejects(fetchFeed({ ...base, url: "https://feed.example/a", fetchImpl: respond(() => new Response(null, { status: 302, headers: { location: "https://evil.example/x" } })) }), /not allow-listed/);
  assert.equal(calls.length, 1);

  calls.length = 0;
  const ok = await fetchFeed({ ...base, url: "https://feed.example/a", fetchImpl: respond((url) => url.endsWith("/a") ? new Response(null, { status: 301, headers: { location: "/b" } }) : new Response("hello")) });
  assert.equal(ok.body.toString(), "hello");
  assert.equal(ok.finalUrl, "https://feed.example/b");

  calls.length = 0;
  const flaky = await fetchFeed({ ...base, url: "https://feed.example/a", fetchImpl: respond((_url, n) => n < 3 ? new Response("busy", { status: 503 }) : new Response("ok")) });
  assert.equal(flaky.body.toString(), "ok");
  assert.equal(calls.length, 3);
  assert.deepEqual(sleeps, [1000, 2000]);

  calls.length = 0;
  await assert.rejects(fetchFeed({ ...base, url: "https://feed.example/a", fetchImpl: respond(() => new Response("busy", { status: 503 })) }), /503/);
  assert.equal(calls.length, 3);

  await assert.rejects(fetchFeed({ ...base, url: "https://feed.example/a", maxBytes: 4, fetchImpl: respond(() => new Response("too large")) }), /cap/);
  await assert.rejects(fetchFeed({ ...base, url: "https://other.example/", fetchImpl: respond(() => new Response("x")) }), /not allow-listed/);
});

test("ransomware mentions need a close name, and a verified domain adds a second signal", () => {
  const victim: Victim = {
    id: "v1", externalId: "g:example land council:2026-10-15", victim: "Example Land Council", group: "g", published: "2026-10-15T00:00:00.000Z",
    victimDomain: "examplecouncil.org.au", collectedAt: "2026-10-15T00:00:00.000Z", licence: "terms", tlp: "TLP:CLEAR",
  };
  const matches = matchVictims([victim], [
    { tenantId: "t1", name: "Example Land Council", verified: ["examplecouncil.org.au"] },
    { tenantId: "t2", name: "Different Health Service", verified: [] },
  ]);
  assert.equal(matches.length, 1);
  assert.equal(matches[0]?.tenant.tenantId, "t1");
  assert.equal(matches[0]?.score.confidence, 80);
});

test("crt.sh names reduce to registered domains", () => {
  const body = JSON.stringify([
    { id: 7, common_name: "www.examp1ecouncil.org.au", name_value: "examp1ecouncil.org.au\n*.examp1ecouncil.org.au", not_before: "2026-10-01T00:00:00" },
    { id: 8, common_name: "xn--exmple-cua.org.au", name_value: "xn--exmple-cua.org.au" },
  ]);
  const entries = parseCrtSh(body);
  assert.deepEqual(entries.map((entry) => [entry.certId, entry.domain]), [[7, "examp1ecouncil.org.au"], [8, "exämple.org.au"]]);
});

test("reverification reads the TXT token and ignores lookup failures", async () => {
  const dns = (answer: () => Promise<string[][]>) => ({ resolveTxt: answer });
  assert.equal(await txtPresent(dns(async () => [["cti-verify=", "abc"]]), "example.org.au", "abc"), true);
  assert.equal(await txtPresent(dns(async () => [["other"]]), "example.org.au", "abc"), false);
  assert.equal(await txtPresent(dns(async () => { throw Object.assign(new Error("x"), { code: "ENODATA" }); }), "example.org.au", "abc"), false);
  assert.equal(await txtPresent(dns(async () => { throw Object.assign(new Error("x"), { code: "ESERVFAIL" }); }), "example.org.au", "abc"), null);
});

test("cadence follows SOURCE_CRONS and failed jobs back off", () => {
  assert.equal(cadenceMs("0 * * * *"), 3_600_000);
  assert.equal(cadenceMs("0 3 * * *"), 86_400_000);
  assert.equal(cadenceMs("0 5 * * 1"), 7 * 86_400_000);
  const job: Job = { name: "j", everyMs: 3_600_000, run: async () => ({ fetched: 0, inserted: 0, duplicates: 0, findings: 0, errors: 0 }) };
  const minutesAgo = (n: number) => new Date(NOW.getTime() - n * 60_000);
  assert.equal(isDue(job, { lastAttemptAt: null, lastSuccessAt: null }, NOW), true);
  assert.equal(isDue(job, { lastAttemptAt: minutesAgo(30), lastSuccessAt: minutesAgo(30) }, NOW), false);
  assert.equal(isDue(job, { lastAttemptAt: minutesAgo(61), lastSuccessAt: minutesAgo(61) }, NOW), true);
  assert.equal(isDue(job, { lastAttemptAt: minutesAgo(5), lastSuccessAt: minutesAgo(120) }, NOW), false);
  assert.equal(isDue(job, { lastAttemptAt: minutesAgo(20), lastSuccessAt: minutesAgo(120) }, NOW), true);
});

test("logged errors carry no emails, URL passwords or bearer tokens", () => {
  const text = redact(new Error("send to person@example.org.au failed via smtp://user:secret@relay.example with Bearer abc.def"));
  assert.equal(/person@|secret|abc\.def/.test(text), false);
});

/** Fake pool for the shared AU tables: remembers external ids so a repeat is a conflict. */
function fakePool(seen = new Set<string>()): { pool: pg.Pool; rows: unknown[][] } {
  const rows: unknown[][] = [];
  const pool = {
    async query(_sql: string, params: unknown[] = []) {
      const key = `${params[1]}|${params[2]}`;
      if (seen.has(key)) return { rows: [] };
      seen.add(key);
      rows.push(params);
      return { rows: [{ id: params[0] }] };
    },
  } as unknown as pg.Pool;
  return { pool, rows };
}

const RSS = `<?xml version="1.0"?><rss><channel>
<item><title>Critical flaw in Example VPN</title><link>https://www.cyber.gov.au/alert/example-vpn</link>
<guid isPermaLink="true">https://www.cyber.gov.au/alert/example-vpn</guid><pubDate>Wed, 14 Oct 2026 13:17:37 +1100</pubDate>
<description>&lt;p&gt;Patch CVE-2026-12345 now. Health and aged care providers are affected.&lt;/p&gt;</description></item>
</channel></rss>`;

test("advisories store tagged rows once per guid and only for approved sources", async () => {
  const { pool, rows: inserted } = fakePool();
  const calls: string[] = [];
  const fetchImpl: FetchLike = async (url) => {
    calls.push(url);
    return new Response(RSS);
  };
  const feeds = [
    { sourceId: "acsc-alerts", url: "https://www.cyber.gov.au/rss/alerts", licence: "CC BY 4.0" },
    { sourceId: "cisa-advisories", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml", licence: "US government public domain" },
  ];
  const ctx = fakeCtx({ pool, fetchImpl, sources: effectiveSources(rows, ["acsc-alerts"], "development") });
  const first = await runAdvisories(ctx, feeds);
  assert.equal(first.inserted, 1);
  assert.equal(first.skipped, 1);
  assert.deepEqual(calls, ["https://www.cyber.gov.au/rss/alerts"]);
  const again = await runAdvisories(ctx, feeds);
  assert.equal(again.inserted, 0);
  assert.equal(again.duplicates, 1);
  assert.equal(inserted.length, 1);
  const row = toAdvisory(feeds[0]!, { guid: "g1", title: "Critical flaw in Example VPN", link: "https://www.cyber.gov.au/alert/x", published: "Wed, 14 Oct 2026 13:17:37 +1100", body: "Patch CVE-2026-12345 now. Health providers are affected." }, NOW);
  assert.equal(row.externalId, "acsc-alerts:g1");
  assert.deepEqual(row.cves, ["CVE-2026-12345"]);
  assert.ok(row.tags.includes("AUSTRALIA") && row.tags.includes("HEALTHCARE"));
  assert.equal(row.publishedAt, "2026-10-14T02:17:37.000Z");
});

test("AU ransomware listing keeps the last year only and dedupes on external id", async () => {
  const listing = [
    { victim: "Example Land Council", website: "www.examplecouncil.org.au", activity: "Public Sector", group_name: "examplegroup", discovered: "2026-10-01 10:00:00", country: "AU" },
    { victim: "Old Victim", website: "", activity: "Not Found", group_name: "oldgroup", discovered: "2024-01-01 10:00:00", country: "AU" },
  ];
  const seen = new Set<string>();
  const run = async () => {
    const { pool } = fakePool(seen);
    const fetchImpl: FetchLike = async () => new Response(JSON.stringify(listing));
    return runAuRansomware(fakeCtx({ pool, fetchImpl, sources: effectiveSources(rows, ["ransomwatch"], "development") }));
  };
  const first = await run();
  assert.equal(first.fetched, 1);
  assert.equal(first.inserted, 1);
  assert.equal((await run()).duplicates, 1);
  let fetched = false;
  const blocked = await runAuRansomware(fakeCtx({ fetchImpl: async () => { fetched = true; return new Response("[]"); } }));
  assert.equal(blocked.skipped, 1);
  assert.equal(fetched, false);
});

test("WORKER_JOBS limits jobs in run order and rejects unknown names", () => {
  const jobs = buildJobs();
  assert.deepEqual(jobs.map((job) => job.name), [
    "sources-sync", "advisories", "collect:ransomwatch", "collect:cisa-kev", "collect:epss", "collect:nvd", "collect:urlhaus",
    "collect:openphish", "collect:threatsieve", "reverify-domains", "lookalike", "lookalike-permutations", "ransomware-match",
    "alerts", "digest", "retention",
  ]);
  assert.deepEqual(selectJobs(jobs, ["alerts", "ransomware-match"]).map((job) => job.name), ["ransomware-match", "alerts"]);
  assert.equal(selectJobs(jobs, []).length, jobs.length);
  assert.throws(() => selectJobs(jobs, ["ransomware-match", "alerts:immediate"]), /alerts:immediate/);
  assert.deepEqual(loadConfig({ DATABASE_URL: "postgres://x", WORKER_JOBS: "alerts, digest" }).workerJobs, ["alerts", "digest"]);
});
