import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { TIERS, costReport, monthTotal, processingMode, type LedgerRow } from "./tiers.js";

test("config/tiers.ts matches the runtime ceilings", () => {
  const path = fileURLToPath(new URL("../../../config/tiers.ts", import.meta.url));
  const text = readFileSync(path, "utf8");
  for (const [name, tier] of Object.entries(TIERS)) {
    assert.match(text, new RegExp(`${name}:\\s*\\{\\s*monthlyAud:\\s*${tier.monthlyAud}`));
    assert.match(text, /hypothesis:\s*true/);
  }
});

test("limit breach switches to deterministic processing and the report sums a month", () => {
  const rows: LedgerRow[] = [
    { tenantId: "a", category: "inference", units: 1, aud: 10, at: "2026-10-02T00:00:00.000Z" },
    { tenantId: "a", category: "enrichment", units: 2, aud: 6, at: "2026-10-03T00:00:00.000Z" },
    { tenantId: "b", category: "inference", units: 1, aud: 3, at: "2026-10-03T00:00:00.000Z" },
    { tenantId: "a", category: "inference", units: 1, aud: 9, at: "2026-11-01T00:00:00.000Z" },
  ];
  assert.equal(monthTotal(rows, "a", "2026-10"), 16);
  assert.equal(processingMode(16, 15), "deterministic");
  assert.equal(processingMode(14, 15), "normal");
  assert.deepEqual(costReport(rows, "2026-10"), [
    { tenantId: "a", aud: 16 },
    { tenantId: "b", aud: 3 },
  ]);
});
