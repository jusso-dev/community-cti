import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pg from "pg";
import { migrate, PostgresIntelStore } from "@community-cti/db";
import { SinkMailer } from "@community-cti/notify";
import { loadConfig } from "./config.js";
import type { WorkerContext } from "./context.js";
import { effectiveSources, loadSourcesDoc, syncSources } from "./governance.js";
import type { EnrichDeps } from "./lookalike.js";
import { runPermutations } from "./permutations.js";
import { runRetention } from "./retention.js";
import { dnsError } from "./test-helpers.js";

test("worker integration: permutation job raises a tenant-only finding, honours dismissals and retention", async (t) => {
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
    const rows = loadSourcesDoc();
    await syncSources(pool, rows);
    const tenantId = randomUUID();
    const otherTenant = randomUUID();
    const label = `perm${randomUUID().replace(/[^a-f]/g, "").slice(0, 8)}`;
    const domain = `${label}.org.au`;
    const comAu = `${label}.com.au`;
    const netAu = `${label}.net.au`;
    for (const [id, name] of [[tenantId, "Permutation Test Council"], [otherTenant, "Other Test Council"]] as const) {
      await pool.query("insert into tenants (id, name, org_type) values ($1, $2, 'other')", [id, name]);
    }
    await pool.query(
      "insert into verified_domains (id, tenant_id, domain, status, method, verify_token, verified_at) values ($1, $2, $3, 'verified', 'dns_txt', 'token', now())",
      [randomUUID(), tenantId, domain],
    );

    const registered = new Set([comAu]);
    const queried: string[] = [];
    const deps: EnrichDeps = {
      lookupDns: async () => ({ a: ["203.0.113.10"], aaaa: [], mx: ["mx.example.org.au"] }),
      fetchRdap: async () => ({ registration: new Date(Date.now() - 3 * 86_400_000).toISOString() }),
      fetchPage: async () => ({ ok: false, error: "timeout" }),
    };
    const rawDir = await mkdtemp(join(tmpdir(), "cti-raw-"));
    const ctx: WorkerContext = {
      pool,
      config: loadConfig({ DATABASE_URL: url, RAW_DIR: rawDir }),
      sources: effectiveSources(rows, ["dns-permutation"], "development"),
      fetchImpl: async () => {
        throw new Error("network is not allowed in this test");
      },
      dns: {
        resolve4: async (name) => {
          queried.push(name);
          if (registered.has(name)) return ["203.0.113.10"];
          throw dnsError("ENOTFOUND");
        },
        resolve6: async () => [],
        resolveMx: async () => [],
        resolveTxt: async () => [],
      },
      sleep: async () => {},
      now: () => new Date(),
      mailer: new SinkMailer(),
      log: () => {},
      putRaw: async () => {},
      intel: new PostgresIntelStore(pool),
    };
    const run = () => runPermutations(ctx, { tenantIds: [tenantId], deps, resolve: { perSecond: 100_000 } });

    const first = await run();
    assert.equal(first.registered, 1);
    assert.equal(first.findings, 1);
    assert.equal(queried.includes(domain), false, "the tenant's own domain is never resolved");
    assert.ok(queried.length > 100 && queried.length <= 600);
    const finding = (await pool.query("select id, kind, dedupe_key, confidence, provenance, confidence_factors from findings where tenant_id = $1", [tenantId])).rows;
    assert.equal(finding.length, 1);
    assert.equal(finding[0]!.dedupe_key, `lookalike:${comAu}`);
    assert.equal(finding[0]!.confidence, 65);
    assert.ok((finding[0]!.confidence_factors as Array<{ code: string }>).some((item) => item.code === "tld_swap"));
    assert.equal((finding[0]!.provenance as Array<{ sourceId: string }>)[0]!.sourceId, "dns-permutation");
    const findingId = String(finding[0]!.id);
    const evidence = (await pool.query("select source_id, object_key from finding_evidence where finding_id = $1", [findingId])).rows;
    assert.deepEqual(evidence.map((row) => row.source_id), ["dns-permutation"]);
    const audits = (await pool.query("select action, actor_id from audit_log where tenant_id = $1 and target_id = $2", [tenantId, findingId])).rows;
    assert.deepEqual(audits.map((row) => [row.action, row.actor_id]), [["finding.created", null]]);

    const visibleTo = async (asTenant: string) => {
      const client = await pool.connect();
      try {
        await client.query("begin");
        await client.query("set local role cti_app");
        await client.query("select set_config('app.tenant_id', $1, true)", [asTenant]);
        const seen = await client.query("select id from findings where id = $1", [findingId]);
        const ev = await client.query("select id from finding_evidence where finding_id = $1", [findingId]);
        await client.query("rollback");
        return seen.rows.length + ev.rows.length;
      } finally {
        client.release();
      }
    };
    assert.equal(await visibleTo(tenantId), 2);
    assert.equal(await visibleTo(otherTenant), 0);

    queried.length = 0;
    const cached = await run();
    assert.equal(cached.cached, 1);
    assert.equal(cached.findings, 0);
    assert.equal(queried.length, 0, "DNS results are cached for a day");

    const observation = (await pool.query("select id, raw_key from observations where source_id = 'dns-permutation' and extracted_domain = $1", [comAu])).rows[0]!;
    const unreferencedKey = `raw/dns-permutation/test/${randomUUID()}.json`;
    await mkdir(join(rawDir, "raw/dns-permutation/test"), { recursive: true });
    await writeFile(join(rawDir, unreferencedKey), "{}");
    await pool.query(
      `insert into observations (id, tenant_id, source_id, collected_at, licence, tlp, raw_key, sha256, extracted_domain, payload)
       values ($1, null, 'dns-permutation', now() - interval '200 days', 'own DNS lookups', 'TLP:CLEAR', $2, $3, null, '{}'::jsonb)`,
      [randomUUID(), unreferencedKey, randomUUID()],
    );
    await pool.query("update observations set collected_at = now() - interval '200 days' where id = $1", [observation.id]);
    const retention = await runRetention(ctx);
    assert.ok((retention.observations ?? 0) >= 1);
    assert.equal(existsSync(join(rawDir, unreferencedKey)), false, "the raw blob is deleted with its observation");
    assert.equal((await pool.query("select count(*)::int as n from observations where raw_key = $1", [unreferencedKey])).rows[0]!.n, 0);
    assert.equal((await pool.query("select count(*)::int as n from observations where id = $1", [observation.id])).rows[0]!.n, 1, "evidence of an open finding is kept");
    assert.equal((await pool.query("select count(*)::int as n from findings where id = $1", [findingId])).rows[0]!.n, 1);

    await pool.query("update findings set status = 'dismissed' where id = $1", [findingId]);
    await pool.query("insert into legitimate_domains (id, tenant_id, domain) values ($1, $2, $3)", [randomUUID(), tenantId, netAu]);
    await pool.query("delete from collector_runs where key like $1 or key like $2", [`permutations:${domain}`, `enrich:${tenantId}:%`]);
    registered.add(netAu);
    queried.length = 0;
    const afterDismiss = await run();
    assert.equal(afterDismiss.findings, 0);
    assert.equal(afterDismiss.suppressed, 1, "a dismissed finding is not raised again");
    assert.equal(queried.includes(netAu), false, "a legitimate domain is never looked up");
    assert.equal((await pool.query("select count(*)::int as n from findings where tenant_id = $1", [tenantId])).rows[0]!.n, 1);
    assert.equal((await pool.query("select status from findings where id = $1", [findingId])).rows[0]!.status, "dismissed");
  } finally {
    await pool.end();
  }
});
