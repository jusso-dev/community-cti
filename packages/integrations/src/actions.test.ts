import { test } from "node:test";
import assert from "node:assert/strict";
import { executeAction } from "./actions.js";

test("actions executor refuses anything without stored approval", () => {
  const preview = { domain: "lookalike.example", list: "block" };
  assert.throws(() => executeAction({
    id: "a1",
    tenantId: "t1",
    status: "proposed",
    preview,
    approvedBy: null,
    approvedAt: null,
  }, () => { throw new Error("applied too early"); }));
  let applied: unknown = null;
  const result = executeAction({
    id: "a1",
    tenantId: "t1",
    status: "approved",
    preview,
    approvedBy: "owner-1",
    approvedAt: "2026-10-14T00:00:00Z",
  }, (change) => { applied = change; });
  assert.deepEqual(applied, preview);
  assert.deepEqual(result.applied, preview);
});
