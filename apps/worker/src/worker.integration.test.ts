import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { migrate, PostgresIntelStore } from "@community-cti/db";
import { mmh3 } from "@community-cti/intel";
import { SinkMailer } from "@community-cti/notify";
import { runAlerts, runDigest } from "./alerts.js";
import { loadConfig } from "./config.js";
import type { WorkerContext } from "./context.js";
import { FEEDS, runFeed } from "./collect.js";
import { persistFinding } from "./findings.js";
import { effectiveSources, loadSourcesDoc, syncSources } from "./governance.js";
import { lookalikeDrafts, runLookalikes, type EnrichDeps } from "./lookalike.js";

test("worker integration: lookalike finding, dedupe and alerts in Postgres", async (t) => {
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
    const owner = randomUUID();
    const member = randomUUID();
    const label = `cti${randomUUID().slice(0, 8).replace(/[0-9]/g, "x")}council`;
    const domain = `${label}.org.au`;
    const lookalike = `${label.replace(/l(?!.*l)/, "1")}.org.au`;
    await pool.query("insert into tenants (id, name, org_type) values ($1, 'Worker Test Council', 'other')", [tenantId]);
    for (const id of [owner, member]) await pool.query("insert into users (id, email) values ($1, $2)", [id, `${id}@example.org.au`]);
    await pool.query("insert into memberships (id, tenant_id, user_id, role) values ($1, $2, $3, 'owner'), ($4, $2, $5, 'member')", [randomUUID(), tenantId, owner, randomUUID(), member]);
    await pool.query("insert into notification_preferences (id, tenant_id, user_id, mode) values ($1, $2, $3, 'immediate')", [randomUUID(), tenantId, owner]);
    await pool.query(
      "insert into verified_domains (id, tenant_id, domain, status, method, verify_token, verified_at) values ($1, $2, $3, 'verified', 'dns_txt', 'token', now())",
      [randomUUID(), tenantId, domain],
    );
    await pool.query(
      `insert into observations (id, tenant_id, source_id, collected_at, licence, tlp, raw_key, sha256, extracted_domain, payload)
       values ($1, null, 'openphish', now(), 'OpenPhish community feed terms', 'TLP:CLEAR', 'raw/openphish/test.json', $2, $3, '{}'::jsonb)`,
      [randomUUID(), randomUUID(), lookalike],
    );

    const deps: EnrichDeps = {
      lookupDns: async () => ({ a: ["203.0.113.10"], aaaa: [], mx: ["mx.example.org.au"] }),
      fetchRdap: async () => ({ registration: new Date(Date.now() - 5 * 86_400_000).toISOString() }),
      fetchPage: async (page) => page.endsWith("/favicon.ico")
        ? { ok: true, status: 200, body: "same-icon" }
        : { ok: true, status: 200, body: '<link rel="icon" href="/favicon.ico">' },
      tenantFaviconHash: async () => mmh3(new TextEncoder().encode("same-icon")),
    };
    const mailer = new SinkMailer();
    const ctx: WorkerContext = {
      pool,
      config: loadConfig({ DATABASE_URL: url, PORTAL_BASE_URL: "https://portal.example" }),
      sources: effectiveSources(rows, ["openphish"], "development"),
      fetchImpl: async () => {
        throw new Error("network is not allowed in this test");
      },
      dns: { resolve4: async () => [], resolve6: async () => [], resolveMx: async () => [], resolveTxt: async () => [] },
      sleep: async () => {},
      now: () => new Date(),
      mailer,
      log: () => {},
      putRaw: async () => {},
      intel: new PostgresIntelStore(pool),
    };

    const first = await runLookalikes(ctx, { tenantIds: [tenantId], deps });
    assert.equal(first.findings, 1);
    const findings = await pool.query("select id, kind, dedupe_key, provenance, confidence_factors from findings where tenant_id = $1", [tenantId]);
    assert.equal(findings.rows.length, 1);
    const finding = findings.rows[0]!;
    assert.equal(finding.kind, "lookalike_domain");
    assert.equal(finding.dedupe_key, `lookalike:${lookalike}`);
    assert.equal((finding.provenance as unknown[]).length, 1);
    assert.ok((finding.confidence_factors as unknown[]).length >= 1);
    const evidence = await pool.query("select source_id, object_key from finding_evidence where finding_id = $1", [finding.id]);
    assert.deepEqual(evidence.rows.map((row) => row.source_id), ["openphish"]);
    const audits = await pool.query("select action from audit_log where tenant_id = $1 and target_id = $2", [tenantId, String(finding.id)]);
    assert.deepEqual(audits.rows.map((row) => row.action), ["finding.created"]);

    const again = await runLookalikes(ctx, { tenantIds: [tenantId], deps });
    assert.equal(again.findings, 0);
    const [draft] = await lookalikeDrafts([{ tenantId, verified: [domain], legitimate: [] }], [{ domain: lookalike, origins: [{
      sourceId: "openphish", collectedAt: new Date().toISOString(), licence: "terms", tlp: "TLP:CLEAR", label: "x", url: null, objectKey: null, ref: "r",
    }] }], deps, new Date(), 40);
    assert.equal((await persistFinding(pool, ctx.intel, draft!)).outcome, "unchanged");
    assert.equal((await pool.query("select count(*)::int as n from findings where tenant_id = $1", [tenantId])).rows[0]!.n, 1);

    const limited = await runAlerts({ ...ctx, mailer: { send: async () => { throw Object.assign(new Error("rate limited"), { status: 429, retryAfterSeconds: 30 }); } } }, { tenantIds: [tenantId] });
    assert.equal(limited.rateLimited, 1);
    const untouched = await pool.query("select attempts from alert_deliveries where finding_id = $1 and delivery = 'immediate'", [finding.id]);
    assert.equal(untouched.rows[0]!.attempts, 0, "a 429 does not use up an attempt");
    assert.equal((await runAlerts(ctx, { tenantIds: [tenantId] })).paused, 1, "sending waits for Retry-After");
    await pool.query("delete from collector_runs where key = 'mail-pause'");

    const alerts = await runAlerts(ctx, { tenantIds: [tenantId] });
    assert.equal(alerts.sent, 1);
    assert.equal(mailer.sent.length, 1);
    assert.equal(mailer.sent[0]!.to, `${owner}@example.org.au`);
    assert.match(mailer.sent[0]!.text, new RegExp(`https://portal.example/findings/${finding.id}`));
    assert.equal((await runAlerts(ctx, { tenantIds: [tenantId] })).sent ?? 0, 0);

    const digest = await runDigest(ctx, { tenantIds: [tenantId] });
    assert.equal(digest.sent, 1);
    assert.equal(mailer.sent[1]!.to, `${member}@example.org.au`);
    assert.equal((await runDigest(ctx, { tenantIds: [tenantId] })).sent ?? 0, 0);
    assert.equal(mailer.sent.length, 2);

    const feedRun = randomUUID().slice(0, 8);
    const feed = Array.from({ length: 1200 }, (_, i) => `https://bulk-${feedRun}-${i}.example.org.au/login`).join("\n");
    const bulkCtx = { ...ctx, fetchImpl: async () => new Response(feed) };
    const openphish = FEEDS.find((def) => def.id === "openphish")!;
    const started = Date.now();
    const bulk = await runFeed(bulkCtx, openphish);
    assert.equal(bulk.inserted, 1200);
    assert.equal(bulk.stix, 2400);
    assert.ok(Date.now() - started < 30_000);
    const stored = await pool.query("select count(*)::int as n from observations where source_id = 'openphish' and payload->>'url' like $1", [`https://bulk-${feedRun}-%`]);
    assert.equal(stored.rows[0]!.n, 1200);
    const repeat = await runFeed(bulkCtx, openphish);
    assert.equal(repeat.inserted, 0);
    assert.equal(repeat.duplicates, 1200);
  } finally {
    await pool.end();
  }
});
