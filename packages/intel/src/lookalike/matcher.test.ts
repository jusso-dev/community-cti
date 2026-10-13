import { test } from "node:test";
import assert from "node:assert/strict";
import { buildMatcher } from "./matcher.js";

test("lookalike matcher finds omission, homoglyph and brand, and skips unverified names", () => {
  const matcher = buildMatcher([
    { domain: "example.org.au", brand: "example", verified: true },
    { domain: "secret.org.au", verified: false },
  ]);
  assert.equal(matcher.match("exampl.org.au")?.kind, "omission");
  assert.equal(matcher.match("examp1e.org.au")?.watched, "example.org.au");
  assert.equal(matcher.match("examp1e.org.au")?.kind, "homoglyph");
  assert.equal(matcher.match("example.evil.test")?.kind, "brand");
  assert.equal(matcher.match("example.org.au"), null);
  assert.equal(matcher.match("secre.org.au"), null);
});

test("matching a thousand certificate names stays under a second", () => {
  const matcher = buildMatcher([{ domain: "example.org.au", verified: true }]);
  const started = Date.now();
  let hits = 0;
  for (let i = 0; i < 1000; i += 1) {
    if (matcher.match(`name${i}.example.net`)) hits += 1;
  }
  assert.equal(hits, 0);
  assert.ok(Date.now() - started < 1000);
});
