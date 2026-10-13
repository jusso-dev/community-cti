import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { LOOKALIKE_WEIGHTS } from "@community-cti/intel";
import { SHARING_LAUNCH_APPROVED } from "./handle.js";
import { ROUTES } from "./routes.js";
import { FACTORS, PROVENANCE, call, createOrg, harness, login } from "./test-support.js";

test("openapi lists every route", () => {
  const yaml = readFileSync(fileURLToPath(new URL("../openapi.yaml", import.meta.url)), "utf8");
  for (const route of ROUTES) assert.match(yaml, new RegExp(`operationId: ${route.id}\\b`));
});

test("handler source does not start a port scan", () => {
  const source = readFileSync(fileURLToPath(new URL("./handle.js", import.meta.url)), "utf8");
  for (const word of ["nmap", "masscan", "zmap", "scanPorts"]) assert.equal(source.includes(word), false, word);
});

test("every route has an isolation case and other organisations stay hidden", async () => {
  assert.equal(SHARING_LAUNCH_APPROVED, false);
  let modelCalls = 0;
  const box = await harness({
    resolveHost: async () => ["1.1.1.1"],
    exposureProvider: { async lookupIp() { return [{ port: 443, product: "nginx", version: "1.25.0" }]; } },
    hibpFetch: async () => Response.json([{ email: "ada@a.example.org.au", breachName: "Example", Password: "hunter2-not-a-real-password" }]),
    model: {
      id: "scripted",
      async complete() {
        modelCalls += 1;
        return { text: "{\"confidenceDelta\":5}", toolCalls: [], tokensIn: 2, tokensOut: 2 };
      },
    },
  });
  try {
    const ownerA = await login(box, "owner-a@example.org.au");
    const ownerB = await login(box, "owner-b@example.org.au");
    const orgA = await createOrg(box, ownerA.token, "Org A", "acco");
    const orgB = await createOrg(box, ownerB.token, "Org B", "land_council");
    assert.equal((await call(box.deps, "POST", `/orgs/${orgA}/invites`, ownerA.token, { email: "member-a@example.org.au", role: "member" })).status, 200);
    const member = await login(box, "member-a@example.org.au");
    const findingA = "33333333-3333-4333-8333-333333333333";
    const findingB = "44444444-4444-4444-8444-444444444444";
    const evidenceA = "55555555-5555-4555-8555-555555555555";
    const evidenceAmber = "66666666-6666-4666-8666-666666666666";
    const evidenceB = "77777777-7777-4777-8777-777777777711";
    const credentialB = "77777777-7777-4777-8777-777777777722";
    const actionB = "77777777-7777-4777-8777-777777777733";
    await box.db.admin(
      `insert into findings (id, tenant_id, kind, title, plain_english_summary, confidence, confidence_factors, status, provenance)
       values ($1, $2, 'lookalike_domain', 'Alpha finding', 'A website name looks like yours.', 80, $4::jsonb, 'open', $5::jsonb),
              ($3, $6, 'lookalike_domain', 'Beta finding', 'A different organisation.', 80, $4::jsonb, 'open', $5::jsonb)`,
      [findingA, orgA, findingB, FACTORS, PROVENANCE, orgB],
    );
    await box.db.admin(
      `insert into finding_evidence (id, tenant_id, finding_id, label, object_key, collected_at, source_id, licence, tlp)
       values ($1, $2, $3, 'page', 'raw/a.txt', now(), 'crtsh', 'public', 'TLP:CLEAR'),
              ($4, $2, $3, 'restricted', 'raw/secret.txt', now(), 'crtsh', 'restricted', 'TLP:AMBER'),
              ($5, $6, $7, 'page', 'raw/b.txt', now(), 'crtsh', 'public', 'TLP:CLEAR')`,
      [evidenceA, orgA, findingA, evidenceAmber, evidenceB, orgB, findingB],
    );
    await box.db.admin(
      `insert into credential_exposures (id, tenant_id, domain_name, email_ciphertext, breach_name)
       values ($1, $2, 'b.example.org.au', 'cipher-b', 'BetaBreach')`,
      [credentialB, orgB],
    );
    await box.db.admin(
      `insert into actions (id, tenant_id, finding_id, kind, status, preview, preview_hash)
       values ($1, $2, $3, 'tell_helper', 'proposed', '{}'::jsonb, 'abc')`,
      [actionB, orgB, findingB],
    );
    await box.db.admin(
      "insert into cost_ledger (tenant_id, category, units, aud, at) values ($1, 'storage', 1, 50, $2)",
      [orgB, "2026-10-13T00:00:00.000Z"],
    );
    await box.db.admin(
      `insert into verified_domains (tenant_id, domain, status, token, method)
       values ($1, 'a.example.org.au', 'verified', 'cti-verify=aaa', 'dns'),
              ($2, 'b.example.org.au', 'verified', 'cti-verify=bbb', 'dns')`,
      [orgA, orgB],
    );
    const domainB = (await box.db.admin<{ id: string }>("select id from verified_domains where domain = 'b.example.org.au'")).rows[0]?.id ?? "";

    const cases: Record<string, () => Promise<void>> = {
      healthz: async () => {
        const result = await call(box.deps, "GET", "/healthz");
        assert.equal(result.status, 200);
        assert.equal(JSON.stringify(result.body).includes("owner-b"), false);
      },
      "magic-link": async () => {
        const before = box.inbox.length;
        const result = await call(box.deps, "POST", "/auth/magic-link", undefined, { email: "owner-a@example.org.au" });
        assert.equal(result.status, 200);
        assert.equal(box.inbox[before]?.to, "owner-a@example.org.au");
        assert.equal(JSON.stringify(result.body).includes("token"), false);
      },
      callback: async () => {
        const reused = await call(box.deps, "GET", "/auth/callback?token=not-a-real-token");
        assert.equal(reused.status, 400);
      },
      "create-org": async () => {
        const result = await call(box.deps, "POST", "/orgs", ownerA.token, { name: "Second", type: "other" });
        assert.equal(result.status, 200);
        assert.notEqual((result.body as { id: string }).id, orgB);
      },
      invite: async () => {
        assert.equal((await call(box.deps, "POST", `/orgs/${orgB}/invites`, ownerA.token, { email: "x@example.org.au", role: "member" })).status, 404);
        assert.equal((await call(box.deps, "POST", `/orgs/${orgA}/invites`, member.token, { email: "x@example.org.au", role: "owner" })).status, 403);
      },
      consent: async () => {
        assert.equal((await call(box.deps, "POST", `/orgs/${orgB}/consents`, ownerA.token, { scope: "domain_monitoring", grantorName: "A", grantorRole: "owner" })).status, 404);
      },
      "change-role": async () => {
        assert.equal((await call(box.deps, "POST", `/orgs/${orgA}/members/${member.userId}/role`, member.token, { role: "owner" })).status, 403);
        assert.equal((await call(box.deps, "POST", `/orgs/${orgB}/members/${ownerB.userId}/role`, ownerA.token, { role: "member" })).status, 404);
      },
      "add-domain": async () => {
        assert.equal((await call(box.deps, "POST", "/domains", ownerA.token, { domain: "new.example.org.au" })).status, 403);
      },
      "check-domain": async () => {
        assert.equal((await call(box.deps, "POST", `/domains/${domainB}/check`, ownerA.token, {})).status, 404);
      },
      "email-domain": async () => {
        assert.equal((await call(box.deps, "POST", `/domains/${domainB}/email`, ownerA.token, {})).status, 404);
      },
      "verify-email": async () => {
        const before = (await box.db.admin("select status from verified_domains where domain = 'b.example.org.au'")).rows[0];
        assert.equal((await call(box.deps, "GET", "/domains/verify-email?token=nope")).status, 400);
        const after = (await box.db.admin("select status from verified_domains where domain = 'b.example.org.au'")).rows[0];
        assert.deepEqual(after, before);
      },
      "list-findings": async () => {
        const result = await call(box.deps, "GET", "/findings", ownerA.token);
        assert.equal(result.status, 200);
        const body = JSON.stringify(result.body);
        assert.equal(body.includes(findingB), false);
        assert.equal(body.includes("Beta finding"), false);
        assert.equal(body.includes("Alpha finding"), true);
      },
      "get-finding": async () => {
        assert.equal((await call(box.deps, "GET", `/findings/${findingB}`, ownerA.token)).status, 404);
        assert.equal((await call(box.deps, "GET", `/findings/${findingA}`, ownerA.token)).status, 200);
      },
      evidence: async () => {
        assert.equal((await call(box.deps, "GET", `/findings/${findingB}/evidence/${evidenceB}`, ownerA.token)).status, 404);
        const amber = await call(box.deps, "GET", `/findings/${findingA}/evidence/${evidenceAmber}`, ownerA.token);
        assert.equal((amber.body as { redacted?: boolean }).redacted, true);
        assert.equal(JSON.stringify(amber.body).includes("https://"), false);
        const clear = await call(box.deps, "GET", `/findings/${findingA}/evidence/${evidenceA}`, ownerA.token);
        const exp = Math.floor(box.clock.now.getTime() / 1000) + 300;
        assert.match((clear.body as { url: string }).url, new RegExp(`exp=${exp}`));
      },
      dismiss: async () => {
        assert.equal((await call(box.deps, "POST", `/findings/${findingB}/dismiss`, ownerA.token, { reason: "not_relevant" })).status, 404);
      },
      challenge: async () => {
        assert.equal((await call(box.deps, "POST", `/findings/${findingB}/challenge`, ownerA.token, { reason: "not_relevant" })).status, 404);
      },
      reopen: async () => {
        assert.equal((await call(box.deps, "POST", `/findings/${findingB}/reopen`, ownerA.token, { reason: "not_relevant" })).status, 404);
      },
      notify: async () => {
        assert.equal((await call(box.deps, "POST", `/findings/${findingB}/notify`, ownerA.token, {})).status, 404);
        const sent = await call(box.deps, "POST", `/findings/${findingA}/notify`, ownerA.token, {});
        assert.equal((sent.body as { sent: boolean }).sent, true);
        assert.equal(box.inbox.at(-1)?.to, "owner-a@example.org.au");
      },
      credentials: async () => {
        assert.equal((await call(box.deps, "GET", "/credentials", member.token)).status, 403);
        const result = await call(box.deps, "GET", "/credentials", ownerA.token);
        assert.equal(JSON.stringify(result.body).includes(credentialB), false);
        const audit = await box.db.admin("select action from audit_log where action = 'credential_exposure_viewed'");
        assert.ok(audit.rows.length >= 1);
      },
      "credentials-sync": async () => {
        assert.equal((await call(box.deps, "POST", "/credentials/sync", ownerA.token, { domain: "b.example.org.au" })).status, 403);
        const synced = await call(box.deps, "POST", "/credentials/sync", ownerA.token, { domain: "a.example.org.au" });
        assert.equal(synced.status, 200, JSON.stringify(synced.body));
        const stored = await box.db.admin("select email_ciphertext, breach_name, data_classes::text as data_classes from credential_exposures where tenant_id = $1", [orgA]);
        assert.equal(JSON.stringify(stored.rows).includes("hunter2-not-a-real-password"), false);
        const foreign = await box.db.admin("select count(*)::int as count from credential_exposures where tenant_id = $1", [orgB]);
        assert.equal(foreign.rows[0]?.count, 1);
      },
      exposures: async () => {
        const result = await call(box.deps, "POST", "/exposures/correlate", ownerA.token, {
          domains: ["a.example.org.au", "b.example.org.au"],
          cves: [{ product: "nginx", cve: "CVE-2024-3000", kev: true, epss: 0.4, version: "1.25.0" }],
        });
        assert.equal(result.status, 200);
        const hosts = (result.body as { exposures: Array<{ host: string }> }).exposures.map((item) => item.host);
        assert.deepEqual(hosts, ["a.example.org.au"]);
      },
      "create-action": async () => {
        assert.equal((await call(box.deps, "POST", "/actions", ownerA.token, { findingId: findingB, kind: "tell_helper", preview: { step: "tell" } })).status, 404);
      },
      "approve-action": async () => {
        assert.equal((await call(box.deps, "POST", `/actions/${actionB}/approve`, ownerA.token, {})).status, 404);
        // A member is refused before the row is read, so another organisation's action stays hidden.
        assert.equal((await call(box.deps, "POST", `/actions/${actionB}/approve`, member.token, {})).status, 403);
      },
      "execute-action": async () => {
        assert.equal((await call(box.deps, "POST", `/actions/${actionB}/execute`, ownerA.token, {})).status, 404);
      },
      review: async () => {
        const result = await call(box.deps, "GET", "/review", ownerA.token);
        assert.equal(result.status, 200);
        assert.equal((result.body as { autoTune: boolean }).autoTune, false);
        assert.equal(JSON.stringify(result.body).includes("Beta finding"), false);
      },
      "review-weights": async () => {
        const result = await call(box.deps, "POST", "/review/weights", ownerA.token, { edit_distance: 99 });
        assert.equal(result.status, 403);
        assert.equal(LOOKALIKE_WEIGHTS.edit_distance, 25);
      },
      "m365-scopes": async () => {
        const result = await call(box.deps, "GET", "/integrations/m365/scopes");
        const body = JSON.stringify(result.body);
        assert.equal(body.includes("Mail.Read"), false);
        assert.equal(body.includes("Domain.Read.All"), true);
      },
      "m365-connect": async () => {
        const result = await call(box.deps, "POST", "/integrations/m365/connect", ownerA.token, { refreshToken: "token-not-real", scopes: ["Domain.Read.All"] });
        assert.equal(result.status, 200);
        assert.equal(JSON.stringify(result.body).includes("token-not-real"), false);
        const hidden = await box.db.admin("select count(*)::int as count from integration_tokens where tenant_id = $1", [orgB]);
        assert.equal(hidden.rows[0]?.count, 0);
        const stored = await box.db.admin<{ ciphertext: string }>("select ciphertext from integration_tokens where tenant_id = $1", [orgA]);
        assert.notEqual(stored.rows[0]?.ciphertext, "token-not-real");
      },
      share: async () => {
        const result = await call(box.deps, "POST", "/share", ownerA.token, { findingId: findingA });
        assert.equal(result.status, 403);
        assert.equal((result.body as { error: string }).error, "Sharing is blocked until the community governance group endorses the rules");
        const shared = await box.db.admin("select count(*)::int as count from shared_items");
        assert.equal(shared.rows[0]?.count, 0);
      },
      cost: async () => {
        const result = await call(box.deps, "POST", "/cost", ownerA.token, { category: "storage", units: 1, aud: 1 });
        assert.equal(result.status, 200);
        assert.equal((result.body as { spent: number }).spent, 1);
        assert.equal((result.body as { mode: string }).mode, "normal");
      },
      investigate: async () => {
        assert.equal((await call(box.deps, "POST", "/agents/investigate", ownerA.token, { findingId: findingB })).status, 404);
        const result = await call(box.deps, "POST", "/agents/investigate", ownerA.token, { findingId: findingA });
        assert.equal(result.status, 200, JSON.stringify(result.body));
        assert.equal((result.body as { findingStatus: string }).findingStatus, "open");
        assert.ok(modelCalls >= 1);
      },
    };

    assert.deepEqual(Object.keys(cases).sort(), ROUTES.map((route) => route.id).sort());
    for (const route of ROUTES) await cases[route.id]!();
  } finally {
    await box.db.close();
  }
});
