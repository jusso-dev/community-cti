import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { domainToUnicode } from "node:url";
import { fileURLToPath } from "node:url";
import { parseAcscRss, parseEpss, parseKev, parseNvd, parsePhishRows, parseRansomPosts, attachEpss, nvdRequests, lookupHibpDomain, sanitiseBreachRecord, assertNoPasswordMaterial, retentionDue, ransomRequestUrls, ACSC_FEED } from "./sources.js";
import { normaliseUrl } from "./urls.js";
import { MemoryObservationStore, runCollector } from "./runner.js";
import { parseSourcesMarkdown } from "./sync.js";
import type { Collector } from "./index.js";
import type { SourceRef } from "@community-cti/schema/stix";

const phishSource: SourceRef = {
  sourceId: "urlhaus",
  url: "https://urlhaus.abuse.ch/",
  licence: "abuse.ch terms",
  tlp: "TLP:CLEAR",
};

test("kev fixtures parse offline with provenance and licence", () => {
  const parsed = parseKev({
    vulnerabilities: [{ cveID: "CVE-2024-12345", vulnerabilityName: "Example bug" }],
  });
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0]?.record.name, "CVE-2024-12345");
  assert.equal(parsed[0]?.record.x_kev, true);
  assert.equal(parsed[0]?.provenance.licence, "CC0");
  assert.ok(parsed[0]?.provenance.collectedAt);
  const nvd = parseNvd({ vulnerabilities: [{ cve: { id: "CVE-2024-12345" } }] });
  const withEpss = attachEpss(nvd, parseEpss("# comment\ncve,epss,percentile\nCVE-2024-12345,0.42,0.97\n"));
  assert.equal(withEpss[0]?.record.x_epss_score, 0.42);
  assert.equal(withEpss[0]?.provenance.sourceId, "nvd");
});

test("nvd rate limit blocks the sixth call until the clock moves", () => {
  let now = 1_000;
  const { limiter } = nvdRequests(new Date("2026-10-01T00:00:00.000Z"), false, () => now);
  for (let i = 0; i < 5; i++) assert.equal(limiter.tryAcquire(), true);
  assert.equal(limiter.tryAcquire(), false);
  now += 30_000;
  assert.equal(limiter.tryAcquire(), true);
});

test("phish fixtures decode punycode and the runner refuses an unapproved feed", async () => {
  const raw = "https://XN--E1AWD7F.example/login?utm_source=ad";
  const parsed = parsePhishRows([{ url: raw, reference: "https://urlhaus.abuse.ch/1" }], phishSource);
  assert.equal(parsed[0]?.record.x_unicode_host, domainToUnicode("xn--e1awd7f.example"));
  assert.equal(String(parsed[0]?.record.pattern).includes("utm_source"), false);
  assert.equal(parsed[0]?.extractedDomain, normaliseUrl(raw).registeredDomain);
  const store = new MemoryObservationStore();
  store.sources.set("urlhaus", { id: "urlhaus", status: "candidate", licence: "terms", tlp: "TLP:CLEAR" });
  const collector: Collector<unknown> = { sourceId: "urlhaus", async collect() { return parsed; } };
  await assert.rejects(() => runCollector("urlhaus", collector, store), /unapproved/);
  store.sources.set("urlhaus", { id: "urlhaus", status: "approved", licence: "terms", tlp: "TLP:CLEAR" });
  const first = await runCollector("urlhaus", collector, store);
  const second = await runCollector("urlhaus", collector, store);
  assert.equal(first.inserted, 1);
  assert.equal(second.duplicates, 1);
  assert.ok(store.rows[0]?.licence);
  assert.ok(store.rows[0]?.collectedAt);
});

test("acsc and ransomware collectors stay on allow-listed hosts and store no leak files", () => {
  const rss = `<?xml version="1.0"?><rss><channel><item><title>Health clinic advisory</title><link>https://www.cyber.gov.au/about-us/alerts/example</link><pubDate>Tue, 13 Oct 2026 00:00:00 GMT</pubDate></item></channel></rss>`;
  const reports = parseAcscRss(rss);
  assert.equal(reports[0]?.record.x_country, "AU");
  assert.match(String(reports[0]?.record.x_sectors), /health/);
  assert.equal(reports[0]?.provenance.sourceId, "acsc-alerts");
  assert.ok(reports[0]?.provenance.collectedAt);
  const posts = parseRansomPosts([{ victim: "Example Land Council", group: "TestGroup", published: "2026-10-12T00:00:00.000Z" }]);
  assert.equal(posts[0]?.record.x_victim_name, "Example Land Council");
  assert.deepEqual(ransomRequestUrls(), ["https://api.ransomware.live/v2/recentvictims"]);
  assert.doesNotThrow(() => new URL(ACSC_FEED));
  const blob = JSON.stringify(posts);
  assert.equal(blob.includes("leak"), false);
  assert.equal(blob.includes("download"), false);
});

test("hibp refuses unverified domains and drops password fields", async () => {
  await assert.rejects(() => lookupHibpDomain("example.org.au", {
    verified: false,
    fetchImpl: async () => { throw new Error("network should not be called"); },
  }));
  const secret = "hunter2-not-a-real-password";
  const clean = sanitiseBreachRecord({
    email: "ada@example.org.au",
    breachName: "ExampleBreach",
    breachDate: "2024-01-02",
    dataClasses: ["Email addresses", "Passwords"],
    Password: secret,
    passwordHash: "abc123hash",
  });
  assert.equal(clean.email, "ada@example.org.au");
  assert.deepEqual(clean.dataClasses, ["Email addresses", "Passwords"]);
  assertNoPasswordMaterial(clean, [secret, "abc123hash"]);
  assert.equal(JSON.stringify(clean).includes(secret), false);
  const called = await lookupHibpDomain("example.org.au", {
    verified: true,
    fetchImpl: async () => new Response(JSON.stringify([{ email: "ada@example.org.au", breachName: "ExampleBreach", Password: secret }])),
  });
  assert.equal(JSON.stringify(called).includes(secret), false);
  const resolved = new Date("2025-01-01T00:00:00.000Z");
  assert.equal(retentionDue(resolved.toISOString(), new Date("2025-12-31T00:00:00.000Z")), false);
  assert.equal(retentionDue(resolved.toISOString(), new Date("2026-01-01T00:00:00.000Z")), true);
});

test("source markdown parser reads the inventory ids", () => {
  const markdown = readFileSync(fileURLToPath(new URL("../../../docs/SOURCES.md", import.meta.url)), "utf8");
  const rows = parseSourcesMarkdown(markdown);
  assert.ok(rows.some((row) => row.id === "cisa-kev"));
  assert.ok(rows.some((row) => row.id === "stealer-logs" && row.status === "blocked"));
});

test("collector sources do not import a language model SDK", () => {
  const root = fileURLToPath(new URL(".", import.meta.url));
  const banned = [/from ["']openai["']/, /from ["']@anthropic-ai\//, /from ["']langchain/, /from ["']@xenova\//, /api\.x\.ai/];
  const files = walk(root).filter((path) => path.endsWith(".js") && !path.endsWith(".test.js"));
  for (const path of files) {
    const text = readFileSync(path, "utf8");
    for (const pattern of banned) assert.equal(pattern.test(text), false, path);
  }
});

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else out.push(path);
  }
  return out;
}
