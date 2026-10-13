import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { confidenceForCertainty, correlateExposures, domainsToQuery, rankExposures } from "./discover.js";

test("exposure ranking prefers the known exploited list and skips unverified domains", async () => {
  assert.deepEqual(domainsToQuery([
    { name: "Verified.Example.org.au", verified: true },
    { name: "secret.example.org.au", verified: false },
  ]), ["verified.example.org.au"]);
  const ranked = rankExposures([
    { id: "low", host: "a.example", cve: "CVE-2024-1000", kev: false, epss: 0.01, versionCertainty: "inferred" },
    { id: "hot", host: "a.example", cve: "CVE-2024-2000", kev: false, epss: 0.4, versionCertainty: "inferred" },
    { id: "kev", host: "a.example", cve: "CVE-2024-3000", kev: true, epss: 0.02, versionCertainty: "exact" },
  ]);
  assert.deepEqual(ranked.map((item) => item.id), ["kev", "hot", "low"]);
  assert.equal(confidenceForCertainty("exact"), 80);
  assert.equal(confidenceForCertainty("inferred"), 55);
  const records = await correlateExposures({
    domains: [{ name: "verified.example.org.au", verified: true }, { name: "nope.example.org.au", verified: false }],
    resolve: async () => ["1.1.1.1"],
    provider: { async lookupIp() { return [{ port: 443, product: "nginx", version: "1.25.0" }]; } },
    cves: [{ product: "nginx", cve: "CVE-2024-3000", kev: true, epss: 0.5, version: "1.25.0" }],
  });
  assert.equal(records.length, 1);
  assert.equal(records[0]?.versionCertainty, "exact");
  assert.equal(records[0]?.host, "verified.example.org.au");
});

test("exposure code does not contain a port scanner", () => {
  const source = readFileSync(fileURLToPath(new URL("./discover.js", import.meta.url)), "utf8");
  for (const word of ["nmap", "masscan", "zmap", "scanPorts"]) {
    assert.equal(source.includes(word), false, word);
  }
});
