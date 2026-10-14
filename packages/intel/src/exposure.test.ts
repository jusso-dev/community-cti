import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { discoverAssets } from "./assets/discover.js";
import { correlateExposure } from "./exposure/correlate.js";

test("exposure correlation stays on verified assets and ranks KEV first", () => {
  const assets = discoverAssets({
    domains: [
      { domain: "example.org.au", verified: true },
      { domain: "nope.org.au", verified: false },
    ],
    ctNames: ["mail.example.org.au", "intranet.nope.org.au", "www.example.org.au"],
    dns: { "mail.example.org.au": ["1.1.1.1"], "intranet.nope.org.au": ["9.9.9.9"] },
  });
  assert.deepEqual(assets.map((asset) => asset.host).sort(), ["example.org.au", "mail.example.org.au", "www.example.org.au"]);
  const source = readFileSync(fileURLToPath(new URL("../src/assets/discover.ts", import.meta.url)), "utf8")
    + readFileSync(fileURLToPath(new URL("../src/exposure/correlate.ts", import.meta.url)), "utf8");
  assert.equal(/nmap|masscan|createConnection|port scan/i.test(source), false);
  const ranked = correlateExposure({
    tenantId: "t1",
    now: "2026-10-14T00:00:00Z",
    verifiedHosts: ["mail.example.org.au"],
    services: [{ host: "mail.example.org.au", ip: "1.1.1.1", cpe: "cpe:example", versionCertainty: "exact" }],
    vulns: [
      { cve: "CVE-2024-0002", cpe: "cpe:example", kev: false, epss: 0.9 },
      { cve: "CVE-2024-0001", cpe: "cpe:example", kev: true, epss: 0.01 },
    ],
    provenance: {
      sourceId: "cisa-kev",
      sourceUrl: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      collectedAt: "2026-10-14T00:00:00Z",
      licence: "public",
      accessRestriction: "TLP:CLEAR",
      evidenceRefs: [],
    },
  });
  assert.equal(ranked[0]?.kev, true);
  assert.equal(ranked[0]?.finding.confidence, 80);
  assert.ok(ranked[0]?.finding.provenance[0]?.sourceId);
  assert.throws(() => correlateExposure({
    tenantId: "t1",
    now: "2026-10-14T00:00:00Z",
    verifiedHosts: ["mail.example.org.au"],
    services: [{ host: "other.example", ip: "1.1.1.1", cpe: "cpe:example", versionCertainty: "inferred" }],
    vulns: [],
    provenance: ranked[0]!.finding.provenance[0]!,
  }));
});
