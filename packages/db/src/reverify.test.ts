import { test } from "node:test";
import assert from "node:assert/strict";
import { createTestDb } from "./testing.js";
import { reverifyDomains } from "./reverify.js";
import { withTenant } from "./tenant.js";

const TENANT_A = "11111111-1111-4111-8111-111111111111";
const TENANT_B = "22222222-2222-4222-8222-222222222222";

test("reverify sees every tenant and lapses DNS domains after 14 days", async () => {
  const db = await createTestDb();
  try {
    await db.admin("insert into tenants (id, name, type) values ($1, 'A', 'acco'), ($2, 'B', 'land_council')", [TENANT_A, TENANT_B]);
    const missingSince = new Date("2026-09-01T00:00:00.000Z").toISOString();
    await db.admin(
      `insert into verified_domains (tenant_id, domain, status, token, method, verified_at, txt_missing_since)
       values ($1, 'a.example.org.au', 'verified', 'cti-verify=aaa', 'dns', now(), $3),
              ($2, 'b.example.org.au', 'verified', 'cti-verify=bbb', 'dns', now(), null),
              ($2, 'mail.example.org.au', 'verified', 'cti-verify=ccc', 'email', now(), null)`,
      [TENANT_A, TENANT_B, missingSince],
    );
    const scoped = await withTenant(db, TENANT_A, (tx) => tx.query("select id from verified_domains"));
    assert.equal(scoped.rows.length, 1);
    const now = new Date("2026-10-13T00:00:00.000Z");
    const result = await reverifyDomains(db, async (domain) => {
      if (domain === "b.example.org.au") return [["cti-verify=bbb"]];
      return [[]];
    }, now);
    assert.equal(result.checked, 3);
    assert.equal(result.lapsed, 1);
    const status = await db.admin<{ domain: string; status: string }>("select domain, status from verified_domains order by domain");
    const byDomain = Object.fromEntries(status.rows.map((row) => [row.domain, row.status]));
    assert.equal(byDomain["a.example.org.au"], "lapsed");
    assert.equal(byDomain["b.example.org.au"], "verified");
    assert.equal(byDomain["mail.example.org.au"], "verified");
  } finally {
    await db.close();
  }
});
