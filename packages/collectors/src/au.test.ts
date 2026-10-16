import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { activityTags, advisoryFields, parseAuRansomware, parseFeed, tagAdvisory } from "./au.js";

const fixture = (name: string) => readFileSync(fileURLToPath(new URL(`../test/fixtures/${name}`, import.meta.url)), "utf8");

test("parses the live ACSC alerts RSS format", () => {
  const items = parseFeed(fixture("acsc-alerts-live.xml"));
  assert.equal(items.length, 3);
  for (const item of items) {
    assert.match(item.link, /^https:\/\/www\.cyber\.gov\.au\//);
    assert.ok(item.guid);
    assert.ok(item.title);
    assert.ok(item.published && !Number.isNaN(new Date(item.published).getTime()));
  }
});

test("parses Atom entries and decodes CDATA and entities", () => {
  const atom = `<feed><entry><title><![CDATA[Fix &amp; patch]]></title><link href="https://example.gov/a"/><id>urn:1</id>
    <updated>2026-10-01T00:00:00Z</updated><summary>&lt;p&gt;CVE-2026-1234 used by LockBit&lt;/p&gt;</summary></entry></feed>`;
  const [item] = parseFeed(atom);
  assert.equal(item!.title, "Fix & patch");
  assert.equal(item!.guid, "urn:1");
  assert.equal(item!.body, "CVE-2026-1234 used by LockBit");
  const fields = advisoryFields(`${item!.title} ${item!.body} cve-2026-1234 T1566.001`);
  assert.deepEqual(fields.cves, ["CVE-2026-1234"]);
  assert.deepEqual(fields.attackTechniques, ["T1486", "T1566.001"]);
});

test("tags Australian and First Nations relevance", () => {
  assert.deepEqual(tagAdvisory("Patch now", "acsc-alerts"), ["AUSTRALIA"]);
  assert.deepEqual(
    tagAdvisory("Scams targeting Aboriginal Community Controlled Health Organisations and small business", "cisa-advisories"),
    ["INDIGENOUS", "HEALTHCARE", "SMB"],
  );
  assert.deepEqual(tagAdvisory("ICS advisory for water utilities", "cisa-advisories"), ["CRITICAL_INFRASTRUCTURE"]);
  assert.deepEqual(activityTags("Healthcare"), ["HEALTHCARE"]);
  assert.deepEqual(activityTags("Government & Defense"), ["GOVERNMENT"]);
});

test("keeps only AU ransomware rows and builds stable ids", () => {
  const rows = parseAuRansomware([
    { post_title: "Example Clinic", website: "https://www.example-clinic.com.au/", activity: "Healthcare", group_name: "groupx", discovered: "2026-10-01T02:00:00Z", country: "AU" },
    { post_title: "Elsewhere Ltd", website: "", activity: "Not Found", group_name: "groupx", discovered: "2026-10-01T02:00:00Z", country: "NZ" },
    { post_title: "", group_name: "groupx", discovered: "2026-10-01T02:00:00Z", country: "AU" },
  ]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.website, "www.example-clinic.com.au");
  assert.equal(rows[0]!.externalId, "groupx:example clinic:2026-10-01");
  assert.throws(() => parseAuRansomware({}));
});
