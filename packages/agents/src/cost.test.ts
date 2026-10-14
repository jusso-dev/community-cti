import { test } from "node:test";
import assert from "node:assert/strict";
import { monthlyReport, recordCost } from "./cost.js";

test("cost limit degrades to deterministic processing", () => {
  const first = recordCost({ entries: [], limitAud: 1 }, {
    tenantId: "t1",
    category: "agent",
    units: 1,
    aud: 0.4,
    at: "2026-10-14T00:00:00Z",
  });
  assert.equal(first.mode, "normal");
  const second = recordCost(first.state, {
    tenantId: "t1",
    category: "enrichment",
    units: 1,
    aud: 0.7,
    at: "2026-10-14T01:00:00Z",
  });
  assert.equal(second.mode, "deterministic-only");
  assert.equal(second.notify, true);
  assert.equal(second.state.entries.length, 2);
  assert.deepEqual(monthlyReport(second.state.entries), [{ tenantId: "t1", aud: 1.1 }]);
});
