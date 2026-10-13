import { test } from "node:test";
import assert from "node:assert/strict";
import { lookalikeCandidates } from "./index.js";

test("generates omission and swap candidates", () => {
  const c = lookalikeCandidates("abc.org.au");
  assert.ok(c.includes("ac.org.au"));
  assert.ok(c.includes("bac.org.au"));
  assert.ok(!c.includes("abc.org.au"));
});
