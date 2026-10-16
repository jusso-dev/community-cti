import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { mmh3 } from "@community-cti/intel";
import { FEEDS } from "./collect.js";
import { assessHit, findHits, type EnrichDeps, type LookalikeHit, type Origin } from "./lookalike.js";
import { permutationPlan, resolveCandidates } from "./permutations.js";
import { dnsError, fakeCtx } from "./test-helpers.js";

const NOW = new Date("2026-10-16T00:00:00.000Z");

const origin: Origin = {
  sourceId: "dns-permutation",
  collectedAt: NOW.toISOString(),
  licence: "own DNS lookups",
  tlp: "TLP:CLEAR",
  label: "DNS shows the name is registered",
  url: null,
  objectKey: "raw/dns-permutation/x.json",
  ref: "obs-1",
};

function hit(domain: string, reason: LookalikeHit["reason"]): LookalikeHit {
  return { tenantId: "t1", watched: "yarnangu.org.au", domain, reason, origins: [origin] };
}

function deps(answer: { resolves?: boolean; mx?: boolean; ageDays?: number | null; parked?: boolean; icon?: boolean }): EnrichDeps {
  return {
    lookupDns: async () => ({ a: answer.resolves ? ["203.0.113.5"] : [], aaaa: [], mx: answer.mx ? ["mx.example"] : [] }),
    fetchRdap: async () => (answer.ageDays === null || answer.ageDays === undefined ? null : { registration: new Date(NOW.getTime() - answer.ageDays * 86_400_000).toISOString() }),
    fetchPage: async (url) => {
      if (url.endsWith("/favicon.ico")) return { ok: true, status: 200, body: "icon" };
      const html = `${answer.icon ? '<link rel="icon" href="/favicon.ico">' : ""}${answer.parked ? "This domain is parked" : "Welcome"}`;
      return { ok: true, status: 200, body: html };
    },
    tenantFaviconHash: async () => (answer.icon ? mmh3(new TextEncoder().encode("icon")) : null),
  };
}

test("tld-swap hits score their own factor and carry the reason into the summary", async () => {
  const { draft, score } = await assessHit(hit("yarnangu.com.au", "tld-swap"), deps({ resolves: true, mx: true, ageDays: 5 }), NOW, 40);
  assert.equal(score.confidence, 65);
  assert.deepEqual(score.factors.map((item) => item.code), ["tld_swap", "has_mx", "resolves", "new_registration"]);
  assert.match(draft!.summary, /different ending/);
  assert.equal(draft!.dedupeKey, "lookalike:yarnangu.com.au");
});

test("typo hits count as one change away", async () => {
  const { score } = await assessHit(hit("yarnanngu.org.au", "typo"), deps({ resolves: true }), NOW, 40);
  assert.equal(score.factors[0]?.code, "edit_distance_1");
  assert.equal(score.confidence, 35);
});

test("threshold boundaries: exactly at the threshold raises, one above does not", async () => {
  const at40 = deps({ mx: true });
  assert.equal((await assessHit(hit("yarangu.org.au", "omission"), at40, NOW, 40)).score.confidence, 40);
  assert.ok((await assessHit(hit("yarangu.org.au", "omission"), at40, NOW, 40)).draft);
  assert.equal((await assessHit(hit("yarangu.org.au", "omission"), at40, NOW, 41)).draft, null);
  assert.equal((await assessHit(hit("yarangu.org.au", "omission"), deps({ resolves: true }), NOW, 40)).draft, null);
});

test("a parked page drops a weak lookalike below the threshold", async () => {
  const { draft, score } = await assessHit(hit("yarangu.org.au", "omission"), deps({ resolves: true, mx: true, parked: true }), NOW, 40);
  assert.equal(score.confidence, 20);
  assert.equal(draft, null);
});

test("a copied site icon pushes a homoglyph into the immediate band", async () => {
  const { draft } = await assessHit(hit("yamangu.org.au", "homoglyph"), deps({ resolves: true, mx: true, icon: true }), NOW, 40);
  assert.ok(draft!.confidence >= 70);
  assert.ok(draft!.factors.some((item) => item.code === "favicon_match"));
});

test("an MX record and a new registration lift a homoglyph past the threshold", async () => {
  const quiet = await assessHit(hit("yamangu.org.au", "homoglyph"), deps({}), NOW, 40);
  assert.equal(quiet.draft, null);
  const live = await assessHit(hit("yamangu.org.au", "homoglyph"), deps({ mx: true, ageDays: 2 }), NOW, 40);
  assert.equal(live.score.confidence, 55);
});

test("permutation plan never includes own, other members' or legitimate domains", () => {
  const plan = permutationPlan([
    { tenantId: "t1", verified: ["yarnangu.org.au"], legitimate: ["yarnangu.com.au"] },
    { tenantId: "t2", verified: ["yarnangu.net.au"], legitimate: [] },
  ]);
  const t1 = plan.filter((item) => item.tenantId === "t1").map((item) => item.domain);
  assert.ok(t1.length > 100 && t1.length <= 600);
  for (const banned of ["yarnangu.org.au", "yarnangu.com.au", "yarnangu.net.au"]) assert.equal(t1.includes(banned), false, banned);
  assert.ok(t1.includes("yarnangu.asn.au"));
  const t2 = plan.filter((item) => item.tenantId === "t2").map((item) => item.domain);
  assert.equal(t2.includes("yarnangu.org.au"), false);
  assert.ok(t2.includes("yarnangu.com.au"));
});

test("two tenants that verified subdomains of one parent share no parent-swap candidates", () => {
  const plan = permutationPlan([
    { tenantId: "s1", verified: ["smoke-984fc854.example.org.au"], legitimate: [] },
    { tenantId: "s2", verified: ["smoke-ea07a77d.example.org.au"], legitimate: [] },
  ]);
  assert.ok(plan.length > 100);
  assert.equal(plan.some((item) => /(^|\.)example\./.test(item.domain)), false, "nothing derived from example.org.au");
  const s1 = new Set(plan.filter((item) => item.tenantId === "s1").map((item) => item.domain));
  const s2 = new Set(plan.filter((item) => item.tenantId === "s2").map((item) => item.domain));
  assert.equal([...s1].filter((domain) => s2.has(domain)).length, 0);
  assert.ok(plan.every((item) => item.domain.startsWith(item.tenantId === "s1" ? "smoke-984fc854" : "smoke-ea07a77d") || item.reason !== "keyword" || item.domain.startsWith("my")));
});

test("a registrable domain verified by one member is never a candidate for another", () => {
  const plan = permutationPlan([
    { tenantId: "t1", verified: ["smoke-984fc854.example.org.au"], legitimate: [] },
    { tenantId: "t2", verified: ["smoke-984fc854.com.au"], legitimate: [] },
  ]);
  assert.equal(plan.some((item) => item.tenantId === "t1" && item.domain === "smoke-984fc854.com.au"), false);
  assert.ok(plan.some((item) => item.tenantId === "t1" && item.domain === "smoke-984fc854.org.au"));
});

test("resolver: registered, NXDOMAIN, NODATA and timeouts", async () => {
  const dns = {
    resolve4: async (name: string) => {
      if (name === "live.example") return ["203.0.113.1"];
      if (name === "mailonly.example") throw dnsError("ENODATA");
      if (name === "slow.example") return new Promise<string[]>(() => {});
      if (name === "broken.example") throw dnsError("ESERVFAIL");
      throw dnsError("ENOTFOUND");
    },
    resolve6: async () => {
      throw dnsError("ENODATA");
    },
    resolveMx: async (name: string) => (name === "mailonly.example" ? [{ exchange: "mx.example", priority: 10 }] : []),
  };
  const verdicts = await resolveCandidates(
    ["live.example", "gone.example", "mailonly.example", "slow.example", "broken.example", "xn--yrnangu-4ye.org.au"],
    dns,
    { timeoutMs: 20, sleep: async () => {}, now: () => 0, perSecond: 1000 },
  );
  const status = Object.fromEntries(verdicts.map((item) => [item.domain, item.status]));
  assert.deepEqual(status, {
    "live.example": "registered",
    "gone.example": "nxdomain",
    "mailonly.example": "registered",
    "slow.example": "failed",
    "broken.example": "failed",
    "xn--yrnangu-4ye.org.au": "nxdomain",
  });
});

test("resolver keeps to 20 queries a second and 10 in flight", async () => {
  let clock = 0;
  const stamps: number[] = [];
  let inFlight = 0;
  let maxInFlight = 0;
  const dns = {
    resolve4: async () => {
      stamps.push(clock);
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setImmediate(resolve));
      inFlight -= 1;
      throw dnsError("ENOTFOUND");
    },
    resolve6: async () => [],
    resolveMx: async () => [],
  };
  const names = Array.from({ length: 95 }, (_, i) => `name${i}.example`);
  const verdicts = await resolveCandidates(names, dns, {
    sleep: async (ms) => {
      clock += ms;
    },
    now: () => clock,
  });
  assert.equal(verdicts.length, 95);
  assert.equal(stamps.length, 95);
  assert.ok(maxInFlight <= 10, `in flight ${maxInFlight}`);
  for (const stamp of stamps) {
    const window = stamps.filter((other) => other >= stamp && other < stamp + 1000).length;
    assert.ok(window <= 20, `${window} queries in one second`);
  }
  assert.ok(clock >= 4000);
});

test("matcher hits from feeds and permutation hits share one dedupe key per domain", () => {
  const hits = findHits([{ tenantId: "t1", verified: ["yarnangu.org.au"], legitimate: [] }], [
    { domain: "yarnangu.com.au", origins: [origin] },
    { domain: "YARNANGU.COM.AU", origins: [{ ...origin, ref: "obs-2" }] },
  ]);
  assert.equal(hits.length, 1);
  assert.equal(hits[0]?.reason, "tld-swap");
  assert.deepEqual(hits[0]?.origins.map((item) => item.ref), ["obs-1", "obs-2"]);
});

const nvdFixture = readFileSync(fileURLToPath(new URL("../../../packages/collectors/test/fixtures/nvd-live.json", import.meta.url)), "utf8");

test("nvd pages a lastModified window, sends the key as a header and paces requests", async () => {
  const feed = JSON.parse(nvdFixture);
  const second = structuredClone(feed);
  second.vulnerabilities[0].cve.id = "CVE-2023-99999";
  const urls: URL[] = [];
  const keys: Array<string | undefined> = [];
  const sleeps: number[] = [];
  const fetchImpl = async (url: string, init: RequestInit) => {
    const parsed = new URL(url);
    urls.push(parsed);
    keys.push((init.headers as Record<string, string>).apiKey);
    const page = parsed.searchParams.get("startIndex") === "0" ? feed : second;
    return new Response(JSON.stringify({ ...page, totalResults: 2 }));
  };
  const nvd = FEEDS.find((def) => def.id === "nvd")!;
  const ctx = fakeCtx({ fetchImpl, sleep: async (ms) => { sleeps.push(ms); } }, { NVD_API_KEY: "test-key" });
  const items = await nvd.load(ctx, NOW, null);
  assert.equal(items.length, 2);
  assert.deepEqual(urls.map((url) => url.searchParams.get("startIndex")), ["0", "1"]);
  assert.equal(urls[0]!.searchParams.get("lastModStartDate"), "2026-10-15T00:00:00.000Z", "first run looks back one day");
  assert.equal(urls[0]!.searchParams.get("lastModEndDate"), NOW.toISOString());
  assert.equal(urls[0]!.searchParams.get("resultsPerPage"), "500", "small pages keep slow NVD responses inside the timeout");
  assert.equal(urls[0]!.searchParams.has("apiKey"), false);
  assert.deepEqual(keys, ["test-key", "test-key"]);
  assert.equal(items[0]!.record.cveID, "CVE-2023-32233");
  assert.equal(items[0]!.record.baseScore, 7.8);
  assert.equal(items[0]!.stix[0]!.type, "vulnerability");

  const again = await nvd.load(ctx, NOW, null);
  assert.equal(again[0]!.stix[0]!.id, items[0]!.stix[0]!.id);
  assert.deepEqual(again[0]!.record, items[0]!.record);

  urls.length = 0;
  await nvd.load(ctx, NOW, new Date("2026-01-01T00:00:00.000Z"));
  assert.equal(urls[0]!.searchParams.get("lastModStartDate"), "2026-06-18T00:00:00.000Z");
  urls.length = 0;
  await nvd.load(ctx, NOW, new Date("2026-10-15T12:00:00.000Z"));
  assert.equal(urls[0]!.searchParams.get("lastModStartDate"), "2026-10-15T11:00:00.000Z");

  let clock = NOW.getTime();
  sleeps.length = 0;
  const sevenPages = async () => new Response(JSON.stringify({ ...feed, totalResults: 7 }));
  const noKey = fakeCtx({ fetchImpl: sevenPages, now: () => new Date(clock), sleep: async (ms) => { sleeps.push(ms); clock += ms; } });
  assert.equal((await nvd.load(noKey, NOW, null)).length, 7);
  assert.deepEqual(sleeps, [30_000], "request six waits for the 30 second window");
});
