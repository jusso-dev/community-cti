import { test } from "node:test";
import assert from "node:assert/strict";
import { enrichDomain, enrichmentAllowed } from "./enrich/enrich.js";
import { isPrivateAddress, safeFetch } from "./enrich/ssrf.js";
import { buildDomainName } from "@community-cti/schema";

test("enrichment refuses private addresses and timeouts", async () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.0.1", "169.254.169.254", "::1"]) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }
  assert.equal(isPrivateAddress("1.1.1.1"), false);
  const blocked = await safeFetch({
    url: "http://127.0.0.1/secret",
    lookup: async () => ["127.0.0.1"],
    fetchImpl: async () => { throw new Error("should not fetch"); },
  });
  assert.equal(blocked.ok, false);
  const redirected = await safeFetch({
    url: "https://public.example/",
    lookup: async (host) => (host === "public.example" ? ["1.1.1.1"] : ["10.0.0.5"]),
    fetchImpl: async (url) => {
      if (url.startsWith("https://public.example")) {
        return { status: 302, headers: { get: () => "http://10.0.0.5/" }, async text() { return ""; } };
      }
      throw new Error("followed private redirect");
    },
  });
  assert.equal(redirected.error, "private address");
  const timed = await safeFetch({
    url: "https://slow.example/",
    timeoutMs: 20,
    lookup: async () => ["1.1.1.1"],
    fetchImpl: (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => {
        const error = new Error("timeout");
        error.name = "TimeoutError";
        reject(error);
      });
    }),
  });
  assert.equal(timed.error, "timeout");
});

test("enrichment stores a note and does not throw when a lookup fails", async () => {
  assert.equal(enrichmentAllowed("lookalike.org.au", ["example.org.au"], ["lookalike.org.au"]), true);
  assert.equal(enrichmentAllowed("stranger.org.au", ["example.org.au"], ["lookalike.org.au"]), false);
  const domain = buildDomainName({
    sourceId: "crtsh",
    licence: "public",
    confidence: 40,
    value: "lookalike.org.au",
    id: "domain-name--11111111-1111-4111-8111-111111111111",
  });
  const result = await enrichDomain({
    domain: "lookalike.org.au",
    verified: ["example.org.au"],
    lookalikes: ["lookalike.org.au"],
    now: new Date("2026-10-14T00:00:00.000Z"),
    domainObjectId: domain.id,
    lookupDns: async () => ({ a: ["1.1.1.1"], aaaa: [], mx: ["mx.example"] }),
    fetchRdap: async () => ({ registration: "2026-10-01T00:00:00.000Z" }),
    fetchPage: async () => ({ ok: false, error: "timeout" }),
  });
  assert.equal(result.resolves, true);
  assert.equal(result.hasMx, true);
  assert.equal(result.registeredDaysAgo, 13);
  assert.ok(result.note);
  assert.ok(result.note?.external_references?.length);
  assert.ok(result.errors.includes("timeout"));
  await assert.rejects(() => enrichDomain({
    domain: "stranger.org.au",
    verified: ["example.org.au"],
    lookalikes: [],
    now: new Date(),
    domainObjectId: domain.id,
    lookupDns: async () => ({ a: [], aaaa: [], mx: [] }),
    fetchRdap: async () => null,
    fetchPage: async () => ({ ok: false, error: "no" }),
  }));
});
