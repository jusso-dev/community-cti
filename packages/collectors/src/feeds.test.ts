import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseKev } from "./sources/cisa-kev.js";
import { parseNvd, nvdLimiter, nvdPageUrl, nvdRecord } from "./sources/nvd.js";
import { parseEpss } from "./sources/epss.js";
import { parseOpenPhish, parsePhishTank, parseUrlhaus } from "./sources/phishing.js";
import { parseAcscRss } from "./sources/acsc.js";
import { parseRansomwareReport } from "./sources/ransomware-reporting.js";
import { assertDomainVerified, dropPasswordFields, toCredentialRecords } from "./sources/hibp-domain.js";
import { crtShUrl } from "./sources/crtsh.js";
import { runCollector, type SourceRecord } from "./runner.js";
import type { Collector } from "./index.js";
import type { Provenance } from "@community-cti/schema";
import { registry } from "./registry.js";

const fixture = (name: string) => readFileSync(fileURLToPath(new URL(`../test/fixtures/${name}`, import.meta.url)), "utf8");
const when = new Date("2026-10-14T00:00:00.000Z");

test("kev fixture parses with provenance and licence", () => {
  const objects = parseKev(JSON.parse(fixture("cisa-kev.json")), when);
  assert.equal(objects.length, 1);
  assert.equal(objects[0]?.external_references?.[0]?.source_name, "cisa-kev");
  assert.equal(objects[0]?.x_kev, true);
  assert.ok(objects[0]?.external_references?.some((ref) => ref.external_id === "CVE-2024-12345"));
});

test("nvd fixture parses and the rate limit uses a mocked clock", () => {
  const objects = parseNvd(JSON.parse(fixture("nvd.json")), when);
  assert.equal(objects[0]?.name, "CVE-2024-12345");
  let now = 0;
  const limiter = nvdLimiter(false, () => now);
  for (let i = 0; i < 5; i++) assert.equal(limiter.delayForNext(), 0);
  const wait = limiter.delayForNext();
  assert.ok(wait > 0);
  now = 30_000;
  assert.equal(limiter.delayForNext(), 0);
});

test("live NVD 2.0 page parses into a vulnerability and a stable record", () => {
  const feed = JSON.parse(fixture("nvd-live.json"));
  const objects = parseNvd(feed, when);
  assert.equal(objects[0]?.name, "CVE-2023-32233");
  assert.match(String(objects[0]?.description), /nf_tables/);
  assert.ok(objects[0]?.external_references?.some((ref) => ref.external_id === "CVE-2023-32233"));
  const record = nvdRecord(feed.vulnerabilities[0].cve);
  assert.equal(record.lastModified, "2026-10-15T00:16:31.683");
  assert.equal(record.baseScore, 7.8);
  assert.equal(record.baseSeverity, "HIGH");
  const url = new URL(nvdPageUrl(new Date("2026-10-01T00:00:00Z"), new Date("2026-10-02T00:00:00Z"), 2000));
  assert.equal(url.searchParams.get("lastModStartDate"), "2026-10-01T00:00:00.000Z");
  assert.equal(url.searchParams.get("startIndex"), "2000");
});

test("epss fixture attaches scores", () => {
  const rows = parseEpss(fixture("epss.csv"));
  assert.equal(rows[0]?.epss, 0.42);
});

test("phish fixtures decode punycode and keep the registered domain", () => {
  const urlhaus = parseUrlhaus(fixture("urlhaus.csv"), when);
  assert.match(urlhaus[0]?.unicodeHost ?? "", /ü/);
  assert.equal(urlhaus[0]?.objects[0]?.x_unicode_host, urlhaus[0]?.unicodeHost);
  assert.equal(String(urlhaus[0]?.objects[1]?.pattern).includes("utm_source"), false);
  assert.equal(parseOpenPhish(fixture("openphish.txt"), when).length, 1);
  assert.equal(parsePhishTank(fixture("phishtank.csv"), when)[0]?.extracted_domain, "bank-login.example");
});

test("live urlhaus dump with quoted cells and comma tags parses", () => {
  const records = parseUrlhaus(fixture("urlhaus-live.csv"), when);
  assert.equal(records.length, 2);
  assert.equal(records[0]?.extracted_domain, null);
  assert.equal(records[1]?.extracted_domain, "examp1e-council.example");
  assert.equal(records[1]?.reference, "https://urlhaus.abuse.ch/url/3950745/");
  assert.equal(String(records[1]?.objects[0]?.value).includes("utm_source"), false);
});

test("phish collector refuses an unapproved feed", async () => {
  const source: SourceRecord = { id: "openphish", status: "candidate", licence: "terms", tlp: "TLP:CLEAR" };
  const collector: Collector<{ ok: true }> = {
    sourceId: "openphish",
    async collect() {
      return [{ record: { ok: true }, provenance: provenance("openphish") }];
    },
  };
  await assert.rejects(() => runCollector({ source, collector, since: when, putRaw: async () => {}, insertObservation: async () => "inserted" }));
});

test("acsc fixture stays on the allow-listed host and stores no leak body", () => {
  const reports = parseAcscRss(fixture("acsc.xml"), when);
  assert.equal(reports.length, 1);
  assert.equal(reports[0]?.x_country, "AU");
  assert.match(String(reports[0]?.external_references?.[0]?.url), /cyber\.gov\.au/);
  assert.throws(() => parseAcscRss(fixture("acsc.xml").replace("www.cyber.gov.au", "evil.example"), when));
});

test("ransomware reporting drops leak links and only uses the allow-listed API", () => {
  const requestUrl = "https://api.ransomware.live/victims";
  const reports = parseRansomwareReport(JSON.parse(fixture("ransomware.json")), when, requestUrl);
  const text = JSON.stringify(reports);
  assert.equal(text.includes("onion"), false);
  assert.equal(text.includes("file.zip"), false);
  assert.equal(reports[0]?.x_victim_name, "Example Land Council");
  assert.ok(reports[0]?.published);
  assert.throws(() => parseRansomwareReport([], when, "https://example-leak.onion/api"));
});

test("ransomware.live v2 victims keep the date, domain and report page but no leak links", () => {
  const reports = parseRansomwareReport(JSON.parse(fixture("ransomware-v2.json")), when, "https://api.ransomware.live/v2/recentvictims");
  const text = JSON.stringify(reports);
  assert.equal(text.includes("onion"), false);
  assert.equal(text.includes("images.ransomware.live"), false);
  assert.equal(reports[0]?.published, "2026-10-15T22:59:23.132Z");
  assert.equal(reports[0]?.x_victim_domain, "examplecouncil.example");
  assert.equal(reports[0]?.x_report_url, "https://www.ransomware.live/id/ZXhhbXBsZQ==");
});

test("hibp drops password fields and refuses unverified domains", () => {
  const raw = JSON.parse(fixture("hibp.json"));
  const cleaned = dropPasswordFields(raw);
  assert.equal(JSON.stringify(cleaned).includes("hunter2"), false);
  assert.equal(JSON.stringify(cleaned).includes("abc123hash"), false);
  const records = toCredentialRecords(raw);
  assert.equal(records.length, 1);
  assert.equal(records[0]?.email, "person@example.org.au");
  assert.equal(records[0]?.breachName, "ExampleBreach");
  assert.equal(JSON.stringify(records).includes("hunter2"), false);
  assert.ok(records[0]?.dataClasses.includes("Passwords"));
  assert.throws(() => assertDomainVerified(false, "example.org.au"));
  assert.doesNotThrow(() => assertDomainVerified(true, "example.org.au"));
});

test("crt.sh lookup requires a verified domain", () => {
  assert.throws(() => crtShUrl("example.org.au", false));
  assert.match(crtShUrl("example.org.au", true), /^https:\/\/crt\.sh\//);
});

test("runner stores provenance and skips duplicate payloads", async () => {
  const seen = new Set<string>();
  const keys: string[] = [];
  const source: SourceRecord = { id: "cisa-kev", status: "approved", licence: "public", tlp: "TLP:CLEAR" };
  const collector: Collector<{ hello: string }> = {
    sourceId: "cisa-kev",
    async collect() {
      return [{ record: { hello: "world" }, provenance: provenance("cisa-kev") }];
    },
  };
  const once = await runCollector({
    source,
    collector,
    since: when,
    now: when,
    putRaw: async (key) => { keys.push(key); },
    insertObservation: async (obs) => {
      assert.ok(obs.sourceId && obs.collectedAt && obs.licence && obs.tlp && obs.rawKey && obs.sha256);
      if (seen.has(obs.sha256)) return "duplicate";
      seen.add(obs.sha256);
      return "inserted";
    },
  });
  const twice = await runCollector({
    source,
    collector,
    since: when,
    now: when,
    putRaw: async (key) => { keys.push(key); },
    insertObservation: async (obs) => (seen.has(obs.sha256) ? "duplicate" : "inserted"),
  });
  assert.equal(once.inserted, 1);
  assert.equal(twice.duplicates, 1);
  assert.equal(keys.length, 1);
});

test("deferred sources are not registered", () => {
  assert.equal(registry.get("stealer-logs"), undefined);
  assert.equal(registry.get("underground"), undefined);
  assert.throws(() => registry.register({ sourceId: "stealer-logs", async collect() { return []; } }));
});

function provenance(sourceId: string): Provenance {
  return {
    sourceId,
    collectedAt: when.toISOString(),
    licence: "public",
    accessRestriction: "TLP:CLEAR",
    evidenceRefs: [],
  };
}
