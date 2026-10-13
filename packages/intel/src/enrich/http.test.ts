import { test } from "node:test";
import assert from "node:assert/strict";
import { validateStix } from "@community-cti/schema/stix";
import { assertPublicHost, fetchPublicPage, isPrivateAddress, SsrfError } from "./http.js";
import { enrichDomain, enrichmentNote } from "./job.js";

test("private addresses and metadata hosts are refused", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.0.4", "169.254.169.254", "100.64.1.1", "::1", "fd00::1"]) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }
  assert.equal(isPrivateAddress("1.1.1.1"), false);
  assert.throws(() => assertPublicHost("localhost", ["1.1.1.1"]), SsrfError);
  assert.throws(() => assertPublicHost("metadata.google.internal", ["1.1.1.1"]), SsrfError);
  assert.throws(() => assertPublicHost("app.example", ["10.0.0.8"]), SsrfError);
});

test("redirects to private addresses and timeouts do not throw", async () => {
  const redirected = await fetchPublicPage({
    url: "https://public.example/",
    resolve: async (host) => host === "public.example" ? ["1.1.1.1"] : ["127.0.0.1"],
    fetchImpl: async () => new Response(null, { status: 302, headers: { location: "http://127.0.0.1/" } }),
  });
  assert.equal(redirected.ok, false);
  assert.match(redirected.error ?? "", /refusing/);
  const timedOut = await fetchPublicPage({
    url: "https://public.example/",
    resolve: async () => ["1.1.1.1"],
    fetchImpl: async () => { throw new Error("The operation was aborted"); },
  });
  assert.equal(timedOut.ok, false);
  assert.equal(timedOut.error, "timeout");
});

test("enrichment returns a note when a lookup fails closed", async () => {
  const enrichment = await enrichDomain({
    domain: "public.example",
    now: new Date("2026-10-13T00:00:00.000Z"),
    resolver: {
      async resolve4() { return ["1.1.1.1"]; },
      async resolve6() { return []; },
      async resolveMx() { return ["mx.example"]; },
    },
    resolveHost: async () => ["1.1.1.1"],
    fetchImpl: async (url) => {
      if (String(url).includes("rdap")) {
        return new Response(JSON.stringify({ events: [{ eventAction: "registration", eventDate: "2026-10-01T00:00:00.000Z" }] }), { status: 200 });
      }
      throw new Error("The operation was aborted");
    },
  });
  assert.equal(enrichment.ok, true);
  assert.equal(enrichment.error, "timeout");
  assert.equal(enrichment.ageDays, 12);
  const note = enrichmentNote(enrichment, "domain-name--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "2026-10-13T00:00:00.000Z");
  assert.deepEqual(validateStix(note), []);
});
