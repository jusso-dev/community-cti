import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { migrationsDir } from "./migrate.js";

const sql = readdirSync(migrationsDir())
  .filter((name) => name.endsWith(".sql"))
  .sort()
  .map((name) => readFileSync(join(migrationsDir(), name), "utf8"))
  .join("\n");

const tenantTables = [
  "tenants",
  "memberships",
  "verified_domains",
  "observations",
  "stix_objects",
  "findings",
  "finding_evidence",
  "finding_feedback",
  "actions",
  "consents",
  "audit_log",
  "invites",
  "notification_preferences",
  "legitimate_domains",
  "agent_runs",
  "tenant_budgets",
  "integration_tokens",
  "m365_cached_users",
  "m365_cached_domains",
  "credential_exposures",
  "sharing_preferences",
  "shared_items",
  "cost_ledger",
  "product_events",
];

test("isolation policies are forced on every tenant table", () => {
  for (const table of tenantTables) {
    assert.match(sql, new RegExp(`alter table ${table} enable row level security`, "i"));
    assert.match(sql, new RegExp(`alter table ${table} force row level security`, "i"));
    assert.match(sql, new RegExp(`create policy tenant_isolation on ${table}`, "i"));
  }
});

test("stix isolation keeps shared objects and hides other tenants", () => {
  assert.match(sql, /tenant_id is null[\s\S]*stix_objects|on stix_objects[\s\S]*tenant_id is null/);
});

test("findings require confidence 0 to 100 and a dismiss or challenge status", () => {
  assert.match(sql, /confidence smallint not null check \(confidence between 0 and 100\)/);
  assert.match(sql, /'dismissed'/);
  assert.match(sql, /'challenged'/);
});

test("audit log updates and deletes are revoked from cti_app", () => {
  assert.match(sql, /revoke update, delete on audit_log from cti_app/i);
  assert.match(sql, /audit_log is append-only/);
  assert.match(sql, /nobypassrls/);
});

test("credential exposure storage has no password column", () => {
  const block = sql.slice(sql.indexOf("create table if not exists credential_exposures"), sql.indexOf("create table if not exists sharing_preferences"));
  assert.doesNotMatch(block, /password/i);
  assert.match(block, /email_ciphertext/);
  assert.match(block, /breach_name/);
});
