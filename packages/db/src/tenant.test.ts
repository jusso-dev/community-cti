import { test } from "node:test";
import assert from "node:assert/strict";
import { createTestDb } from "./testing.js";
import { migrate } from "./migrate.js";
import { withTenant } from "./tenant.js";
import { isVerified } from "./verified.js";

const tenantA = "11111111-1111-4111-8111-111111111111";
const tenantB = "22222222-2222-4222-8222-222222222222";

async function seedTenants(db: Awaited<ReturnType<typeof createTestDb>>) {
  await db.admin("insert into tenants (id, name, type) values ($1, 'Org A', 'acco'), ($2, 'Org B', 'ams')", [tenantA, tenantB]);
}

function finding(id: string, tenant: string) {
  return [
    id,
    tenant,
    "lookalike_domain",
    "Title",
    "Summary",
    70,
    JSON.stringify([{ code: "edit_distance", points: 25, reason: "One character differs" }]),
    "open",
    JSON.stringify([{ sourceId: "crtsh", collectedAt: "2026-10-13T00:00:00.000Z", licence: "public", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }]),
  ];
}

test("migrations are idempotent and create the architecture tables", async () => {
  const db = await createTestDb();
  const second = await migrate(db);
  assert.deepEqual(second, []);
  const tables = await db.admin<{ tablename: string }>(
    "select tablename from pg_tables where schemaname = 'public' order by 1",
  );
  const names = tables.rows.map((row) => row.tablename);
  for (const name of ["tenants", "users", "memberships", "verified_domains", "sources", "observations", "stix_objects", "findings", "finding_evidence", "finding_feedback", "actions", "consents", "audit_log"]) {
    assert.ok(names.includes(name), name);
  }
  await db.close();
});

test("cti_app without a tenant sees no findings, and withTenant isolates A from B", async () => {
  const db = await createTestDb();
  await seedTenants(db);
  const insert = `insert into findings (id, tenant_id, kind, title, plain_english_summary, confidence, confidence_factors, status, provenance)
    values ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9::jsonb)`;
  await db.admin(insert, finding("33333333-3333-4333-8333-333333333333", tenantA));
  await db.admin(insert, finding("44444444-4444-4444-8444-444444444444", tenantB));

  const unscoped = await db.withTransaction(async (tx) => {
    await tx.query("set local role cti_app");
    return tx.query("select id from findings");
  });
  assert.equal(unscoped.rows.length, 0);

  const seen = await withTenant(db, tenantA, (tx) => tx.query<{ id: string }>("select id from findings"));
  assert.deepEqual(seen.rows.map((row) => row.id), ["33333333-3333-4333-8333-333333333333"]);
  await db.close();
});

test("confidence 101 and a missing status are rejected", async () => {
  const db = await createTestDb();
  await seedTenants(db);
  await assert.rejects(() => db.admin(
    `insert into findings (tenant_id, kind, title, plain_english_summary, confidence, confidence_factors, status, provenance)
     values ($1, 'lookalike_domain', 't', 's', 101, '[{"code":"x","points":1,"reason":"y"}]'::jsonb, 'open', '[{"sourceId":"crtsh"}]'::jsonb)`,
    [tenantA],
  ));
  await assert.rejects(() => db.admin(
    `insert into findings (tenant_id, kind, title, plain_english_summary, confidence, confidence_factors, provenance)
     values ($1, 'lookalike_domain', 't', 's', 10, '[{"code":"x","points":1,"reason":"y"}]'::jsonb, '[{"sourceId":"crtsh"}]'::jsonb)`,
    [tenantA],
  ));
  await db.close();
});

test("isVerified is false until the domain is verified", async () => {
  const db = await createTestDb();
  await seedTenants(db);
  await db.admin(
    "insert into verified_domains (tenant_id, domain, status, token) values ($1, 'example.org.au', 'pending', 'tok')",
    [tenantA],
  );
  assert.equal(await isVerified(db, tenantA, "example.org.au"), false);
  await db.admin("update verified_domains set status = 'verified', verified_at = now() where domain = 'example.org.au'");
  assert.equal(await isVerified(db, tenantA, "example.org.au"), true);
  assert.equal(await isVerified(db, tenantB, "example.org.au"), false);
  await db.close();
});
