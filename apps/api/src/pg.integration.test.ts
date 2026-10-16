import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import type { Server } from "node:http";
import pg from "pg";
import { migrate } from "@community-cti/db";
import { SinkMailer } from "@community-cti/notify";
import { createApp } from "./app.js";
import { PgStore } from "./pg-store.js";

async function call(port: number, method: string, path: string, options: { cookie?: string; body?: unknown } = {}) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: {
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...(options.cookie ? { cookie: options.cookie } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const text = await response.text();
  return { status: response.status, json: text ? JSON.parse(text) : {}, cookie: response.headers.getSetCookie().join("; ") };
}

test("postgres: full tenant journey under row-level security", async (t) => {
  const ownerUrl = process.env.DATABASE_URL;
  const appUrl = process.env.DATABASE_URL_APP;
  if (!ownerUrl || !appUrl) {
    t.skip("DATABASE_URL and DATABASE_URL_APP are not set; Postgres integration skipped");
    return;
  }
  const owner = new pg.Pool({ connectionString: ownerUrl, connectionTimeoutMillis: 1500 });
  const app = new pg.Pool({ connectionString: appUrl, connectionTimeoutMillis: 1500 });
  try {
    await owner.query("select 1");
  } catch (error) {
    await owner.end();
    await app.end();
    t.skip(`Postgres unavailable: ${(error as Error).message}`);
    return;
  }
  await migrate(owner);
  const mailer = new SinkMailer();
  let txt: string[] = [];
  const server: Server = createApp({ store: new PgStore(app), mailer, now: () => new Date(), resolveTxt: async () => [txt] });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const port = (server.address() as { port: number }).port;
  const run = randomUUID().slice(0, 8);
  const login = async (email: string) => {
    assert.equal((await call(port, "POST", "/auth/magic-link", { body: { email } })).status, 202);
    const raw = mailer.sent.at(-1)!.text.match(/token=([a-f0-9]+)/)![1];
    const back = await call(port, "GET", `/auth/callback?token=${raw}`);
    assert.equal(back.status, 200);
    assert.equal((await call(port, "GET", `/auth/callback?token=${raw}`)).status, 400, "magic link is single use");
    assert.match(back.cookie, /Path=\//);
    return `cti_session=${back.cookie.match(/cti_session=([^;]+)/)![1]}`;
  };
  try {
    const cookieA = await login(`owner-${run}@a.example.org.au`);
    assert.equal((await call(port, "GET", "/me", { cookie: cookieA })).json.tenantId, null);
    const orgA = await call(port, "POST", "/orgs", { cookie: cookieA, body: { name: `Org A ${run}`, orgType: "ACCO" } });
    assert.equal(orgA.status, 201);
    assert.equal((await call(port, "POST", "/domains", { cookie: cookieA, body: { domain: `a-${run}.example.org.au` } })).status, 409);
    assert.equal((await call(port, "POST", `/orgs/${orgA.json.id}/consents`, {
      cookie: cookieA,
      body: { scope: "domain_monitoring", grantorName: "Alex", grantorRole: "CEO" },
    })).status, 201);
    const domain = await call(port, "POST", "/domains", { cookie: cookieA, body: { domain: `a-${run}.example.org.au` } });
    assert.equal(domain.status, 201);
    assert.equal((await call(port, "POST", `/domains/${domain.json.id}/check`, { cookie: cookieA, body: {} })).status, 409);
    txt = [domain.json.txt];
    assert.equal((await call(port, "POST", `/domains/${domain.json.id}/check`, { cookie: cookieA, body: {} })).status, 200);

    const second = await call(port, "POST", "/domains", { cookie: cookieA, body: { domain: `b-${run}.example.org.au` } });
    assert.equal((await call(port, "POST", `/domains/${second.json.id}/email`, { cookie: cookieA, body: { email: `admin@b-${run}.example.org.au` } })).status, 202);
    const emailToken = mailer.sent.at(-1)!.text.match(/token=([a-f0-9]+)/)![1];
    assert.equal((await call(port, "GET", `/domains/verify-email?token=${emailToken}`)).status, 200);
    const domains = (await call(port, "GET", "/domains", { cookie: cookieA })).json as Array<{ status: string }>;
    assert.deepEqual(domains.map((item) => item.status), ["verified", "verified"]);

    const findingId = randomUUID();
    await owner.query(
      `insert into findings (id, tenant_id, kind, title, plain_english_summary, confidence, status, confidence_factors, provenance)
       values ($1, $2, 'lookalike_domain', 'A site looks like yours', 'Summary', 55, 'open', $3::jsonb, $4::jsonb)`,
      [findingId, orgA.json.id,
        JSON.stringify([{ code: "edit_distance_1", points: 25, reason: "One change away." }]),
        JSON.stringify([{ sourceId: "crtsh", collectedAt: new Date().toISOString(), licence: "public", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }])],
    );
    await owner.query(
      `insert into finding_evidence (id, tenant_id, finding_id, label, url, collected_at, source_id, licence, tlp)
       values ($1, $2, $3, 'Certificate log', 'https://crt.sh/?id=1', now(), 'crtsh', 'public', 'TLP:CLEAR')`,
      [randomUUID(), orgA.json.id, findingId],
    );
    const list = await call(port, "GET", "/findings", { cookie: cookieA });
    assert.equal(list.json.length, 1);
    assert.equal(list.json[0].evidence[0].url, "https://crt.sh/?id=1");
    const dismissed = await call(port, "POST", `/findings/${findingId}/dismiss`, { cookie: cookieA, body: { reason: "not_ours" } });
    assert.equal(dismissed.status, 200);
    assert.equal(dismissed.json.status, "dismissed");
    assert.equal((await call(port, "POST", `/findings/${findingId}/dismiss`, { cookie: cookieA, body: { reason: "not_ours" } })).status, 409);

    const invited = `member-${run}@a.example.org.au`;
    assert.equal((await call(port, "POST", `/orgs/${orgA.json.id}/invites`, { cookie: cookieA, body: { email: invited } })).status, 201);
    const memberCookie = await login(invited);
    const me = await call(port, "GET", "/me", { cookie: memberCookie });
    assert.equal(me.json.tenantId, orgA.json.id);
    assert.equal(me.json.role, "member");

    const cookieB = await login(`owner-${run}@b.example.org.au`);
    await call(port, "POST", "/orgs", { cookie: cookieB, body: { name: `Org B ${run}`, orgType: "AMS" } });
    assert.equal((await call(port, "GET", `/findings/${findingId}`, { cookie: cookieB })).status, 404);
    assert.equal((await call(port, "GET", "/findings", { cookie: cookieB })).json.length, 0);
    assert.equal((await call(port, "GET", `/orgs/${orgA.json.id}`, { cookie: cookieB })).status, 404);
    assert.equal((await call(port, "GET", "/domains", { cookie: cookieB })).json.length, 0);

    assert.equal((await call(port, "PUT", "/notifications/preferences", { cookie: cookieA, body: { mode: "immediate" } })).json.mode, "immediate");
    const audit = await owner.query("select count(*)::int as n from audit_log where tenant_id = $1", [orgA.json.id]);
    assert.ok(audit.rows[0].n >= 5);

    assert.equal((await call(port, "POST", "/auth/logout", { cookie: cookieA })).status, 200);
    assert.equal((await call(port, "GET", "/me", { cookie: cookieA })).status, 401);
  } finally {
    server.close();
    await app.end();
    await owner.end();
  }
});
