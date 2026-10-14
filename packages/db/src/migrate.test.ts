import { test } from "node:test";
import assert from "node:assert/strict";
import { migrate, migrationsDir } from "./migrate.js";
import { isVerified, isRoleAddress, reverifyDecision, LAPSE_AFTER_MS } from "./verified.js";

test("migrations are idempotent", async () => {
  const versions = new Set<string>();
  const db = {
    async query(sql: string, params?: unknown[]) {
      if (sql.startsWith("select version")) {
        return { rows: [...versions].map((version) => ({ version })) };
      }
      if (sql.startsWith("insert into schema_migrations")) {
        versions.add(String(params?.[0]));
        return { rows: [] };
      }
      return { rows: [] };
    },
  };
  const first = await migrate(db, migrationsDir());
  const second = await migrate(db, migrationsDir());
  assert.ok(first.applied.length >= 3);
  assert.deepEqual(second.applied, []);
});

test("isVerified rejects unverified domains", () => {
  assert.equal(isVerified(null), false);
  assert.equal(isVerified({ status: "pending", verifiedAt: null }), false);
  assert.equal(isVerified({ status: "lapsed", verifiedAt: "2026-01-01T00:00:00Z" }), false);
  assert.equal(isVerified({ status: "verified", verifiedAt: "2026-01-01T00:00:00Z" }), true);
});

test("domain email fallback only accepts role addresses", () => {
  assert.equal(isRoleAddress("admin@example.org.au", "example.org.au"), true);
  assert.equal(isRoleAddress("postmaster@example.org.au", "example.org.au"), true);
  assert.equal(isRoleAddress("webmaster@example.org.au", "example.org.au"), true);
  assert.equal(isRoleAddress("ceo@example.org.au", "example.org.au"), false);
  assert.equal(isRoleAddress("admin@other.org.au", "example.org.au"), false);
});

test("re-verification lapses a domain after 14 days without TXT", () => {
  const start = new Date("2026-10-01T00:00:00Z");
  const missing = reverifyDecision({ status: "verified", txtMissingSince: null }, false, start);
  assert.equal(missing.status, "verified");
  assert.ok(missing.txtMissingSince);
  const almost = reverifyDecision(missing, false, new Date(start.getTime() + LAPSE_AFTER_MS - 1000));
  assert.equal(almost.status, "verified");
  const lapsed = reverifyDecision(missing, false, new Date(start.getTime() + LAPSE_AFTER_MS));
  assert.equal(lapsed.status, "lapsed");
  const restored = reverifyDecision(missing, true, new Date(start.getTime() + 1000));
  assert.equal(restored.txtMissingSince, null);
});
