import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { migrate } from "./migrate.js";
import { withTenant } from "./tenant.js";

test("isolation: tenant A cannot read tenant B in Postgres", async (t) => {
  const url = process.env.DATABASE_URL;
  if (!url) {
    t.skip("DATABASE_URL is not set; Postgres integration skipped");
    return;
  }
  const pool = new pg.Pool({ connectionString: url, connectionTimeoutMillis: 1500 });
  try {
    await pool.query("select 1");
  } catch (error) {
    await pool.end();
    t.skip(`Postgres is down (${error instanceof Error ? error.message : "connection failed"}); skipped`);
    return;
  }
  try {
    await migrate(pool);
    await migrate(pool);
    const tenantA = randomUUID();
    const tenantB = randomUUID();
    const findingA = randomUUID();
    const findingB = randomUUID();
    const provenance = JSON.stringify([{ sourceId: "cisa-kev", collectedAt: "2026-10-14T00:00:00Z", licence: "public", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }]);
    const factors = JSON.stringify([{ code: "test", points: 50, reason: "Fixture factor." }]);
    for (const [id, name] of [[tenantA, "Org A"], [tenantB, "Org B"]] as const) {
      await pool.query("insert into tenants (id, name, org_type) values ($1, $2, 'other')", [id, name]);
    }
    for (const [id, tenantId, title] of [[findingA, tenantA, "A"], [findingB, tenantB, "B"]] as const) {
      await pool.query(
        `insert into findings (id, tenant_id, kind, title, plain_english_summary, confidence, status, confidence_factors, provenance)
         values ($1, $2, 'lookalike_domain', $3, 'Summary', 50, 'open', $4::jsonb, $5::jsonb)`,
        [id, tenantId, title, factors, provenance],
      );
    }
    await assert.rejects(
      pool.query(
        `insert into findings (id, tenant_id, kind, title, plain_english_summary, confidence, status, confidence_factors, provenance)
         values ($1, $2, 'lookalike_domain', 'bad', 'Summary', 101, 'open', $3::jsonb, $4::jsonb)`,
        [randomUUID(), tenantA, factors, provenance],
      ),
    );
    const client = await pool.connect();
    try {
      await client.query("begin");
      await client.query("set local role cti_app");
      const none = await client.query("select id from findings");
      assert.equal(none.rows.length, 0);
      await client.query("rollback");

      await client.query("begin");
      await client.query("set local role cti_app");
      await client.query("select set_config('app.tenant_id', $1, true)", [tenantA]);
      const onlyA = await client.query("select id from findings");
      assert.deepEqual(onlyA.rows.map((row) => row.id).sort(), [findingA].sort());
      await client.query("rollback");
    } finally {
      client.release();
    }

    const viaHelper = await withTenant(pool, tenantA, async (scoped) => {
      await scoped.query("set local role cti_app");
      const rows = await scoped.query("select id from findings");
      return rows.rows.map((row) => row.id);
    });
    assert.deepEqual(viaHelper, [findingA]);

    const auditId = randomUUID();
    await pool.query(
      "insert into audit_log (id, tenant_id, action) values ($1, $2, 'test')",
      [auditId, tenantA],
    );
    const auditor = await pool.connect();
    try {
      await auditor.query("begin");
      await auditor.query("set local role cti_app");
      await auditor.query("select set_config('app.tenant_id', $1, true)", [tenantA]);
      await assert.rejects(auditor.query("update audit_log set action = 'changed' where id = $1", [auditId]));
      await auditor.query("rollback");
    } finally {
      auditor.release();
    }
  } finally {
    await pool.query("delete from findings where title in ('A', 'B', 'bad')");
    // The app role cannot change the audit log. The table owner disables the
    // trigger only to remove this fixture.
    await pool.query("alter table audit_log disable trigger audit_log_no_mutation");
    try {
      await pool.query("delete from audit_log where action = 'test'");
      await pool.query("delete from tenants where name in ('Org A', 'Org B')");
    } finally {
      await pool.query("alter table audit_log enable trigger audit_log_no_mutation");
    }
    await pool.end();
  }
});
