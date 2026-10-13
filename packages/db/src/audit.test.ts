import { test } from "node:test";
import assert from "node:assert/strict";
import { createTestDb } from "./testing.js";
import { audit } from "./audit.js";
import { withTenant } from "./tenant.js";

const tenantA = "11111111-1111-4111-8111-111111111111";

test("cti_app cannot update or delete audit rows", async () => {
  const db = await createTestDb();
  await db.admin("insert into tenants (id, name, type) values ($1, 'Org A', 'acco')", [tenantA]);
  await audit(db, { tenantId: tenantA, action: "domain.verified", targetType: "domain", targetId: "example.org.au" });
  await assert.rejects(() => withTenant(db, tenantA, (tx) => tx.query("update audit_log set action = 'tamper'")));
  await assert.rejects(() => withTenant(db, tenantA, (tx) => tx.query("delete from audit_log")));
  const rows = await withTenant(db, tenantA, (tx) => tx.query("select action from audit_log"));
  assert.equal(rows.rows.length, 1);
  await db.close();
});
