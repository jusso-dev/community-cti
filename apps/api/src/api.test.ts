import { test } from "node:test";
import assert from "node:assert/strict";
import { getStix } from "@community-cti/db";
import { call, createOrg, FACTORS, harness, login, PROVENANCE } from "./test-support.js";

test("onboarding, verification, findings and approvals", async () => {
  let modelCalls = 0;
  const box = await harness({
    hibpFetch: async () => Response.json([{
      email: "ada@a.example.org.au",
      breachName: "ExampleBreach",
      breachDate: "2024-01-02",
      dataClasses: ["Email addresses", "Passwords"],
      Password: "hunter2-not-a-real-password",
    }]),
    model: {
      id: "scripted",
      async complete() {
        modelCalls += 1;
        return { text: "{\"confidenceDelta\":50}", toolCalls: [], tokensIn: 4, tokensOut: 4 };
      },
    },
  });
  try {
    const before = box.inbox.length;
    assert.equal((await call(box.deps, "POST", "/auth/magic-link", undefined, { email: "owner@example.org.au" })).status, 200);
    const token = /token=([a-f0-9]+)/.exec(box.inbox[before]?.text ?? "")?.[1] ?? "";
    const session = await call(box.deps, "GET", `/auth/callback?token=${token}`);
    assert.equal(session.status, 200);
    assert.equal((await call(box.deps, "GET", `/auth/callback?token=${token}`)).status, 400);
    const owner = session.body as { token: string; userId: string };
    const expires = await box.db.admin<{ expires_at: string | Date }>("select expires_at from sessions");
    assert.equal(new Date(expires.rows[0]!.expires_at).getTime() - box.clock.now.getTime(), 12 * 60 * 60 * 1000);
    const orgA = await createOrg(box, owner.token, "River Council", "land_council");
    const other = await login(box, "other@example.org.au");
    const orgB = await createOrg(box, other.token, "Other Org", "ams");

    assert.equal((await call(box.deps, "POST", "/domains", owner.token, { domain: "a.example.org.au" })).status, 403);
    const consent = await call(box.deps, "POST", `/orgs/${orgA}/consents`, owner.token, {
      scope: "domain_monitoring", grantorName: "Riley Owner", grantorRole: "Coordinator",
    });
    assert.equal(consent.status, 200);
    const storedConsent = await box.db.admin<{ ip: string }>("select ip from consents");
    assert.equal(storedConsent.rows[0]?.ip, "203.0.113.10");

    const added = await call(box.deps, "POST", "/domains", owner.token, { domain: "a.example.org.au" });
    assert.equal(added.status, 200, JSON.stringify(added.body));
    const domain = added.body as { id: string; token: string; status: string };
    assert.equal(domain.status, "pending");
    assert.match(domain.token, /^cti-verify=/);
    assert.equal((await call(box.deps, "POST", `/domains/${domain.id}/check`, owner.token, {})).body && (await call(box.deps, "POST", `/domains/${domain.id}/check`, owner.token, {})).status, 200);
    const pending = await call(box.deps, "POST", `/domains/${domain.id}/check`, owner.token, {});
    assert.equal((pending.body as { verified: boolean }).verified, false);
    box.deps.resolveTxt = async () => [[domain.token]];
    const verified = await call(box.deps, "POST", `/domains/${domain.id}/check`, owner.token, {});
    assert.equal((verified.body as { verified: boolean }).verified, true);

    const emailDomain = await call(box.deps, "POST", "/domains", owner.token, { domain: "mail.example.org.au" });
    const emailId = (emailDomain.body as { id: string }).id;
    const mailed = await call(box.deps, "POST", `/domains/${emailId}/email`, owner.token, {});
    assert.deepEqual((mailed.body as { sent: string[] }).sent, [
      "admin@mail.example.org.au",
      "postmaster@mail.example.org.au",
      "webmaster@mail.example.org.au",
    ]);
    const emailToken = /token=([^\\s]+)/.exec(box.inbox.at(-1)?.text ?? "")?.[1] ?? "";
    assert.equal((await call(box.deps, "GET", `/domains/verify-email?token=${emailToken}`)).status, 200);
    assert.equal((await call(box.deps, "GET", `/domains/verify-email?token=${emailToken}`)).status, 400);

    const finding = "33333333-3333-4333-8333-333333333311";
    await box.db.admin(
      `insert into findings (id, tenant_id, kind, title, plain_english_summary, confidence, confidence_factors, status, provenance)
       values ($1, $2, 'lookalike_domain', 'A lookalike name', 'A website name looks like yours.', 30, $3::jsonb, 'open', $4::jsonb)`,
      [finding, orgA, FACTORS, PROVENANCE],
    );
    const quiet = await call(box.deps, "POST", `/findings/${finding}/notify`, owner.token, {});
    assert.equal((quiet.body as { channel: string }).channel, "none");
    await box.db.admin("update findings set confidence = 80 where id = $1", [finding]);
    const loud = await call(box.deps, "POST", `/findings/${finding}/notify`, owner.token, {});
    assert.equal((loud.body as { sent: boolean }).sent, true);

    const challenged = await call(box.deps, "POST", `/findings/${finding}/challenge`, owner.token, { reason: "not_ours", note: "This is not our name." });
    assert.equal((challenged.body as { status: string }).status, "challenged");
    const opinions = await box.db.admin("select count(*)::int as count from stix_objects where type = 'opinion'");
    assert.equal(opinions.rows[0]?.count, 1);
    assert.equal((await call(box.deps, "POST", `/findings/${finding}/reopen`, owner.token, {})).status, 200);
    const dismissed = await call(box.deps, "POST", `/findings/${finding}/dismiss`, owner.token, { reason: "legitimate_domain", domain: "sister.example.org.au" });
    assert.equal((dismissed.body as { status: string }).status, "dismissed");
    const allowed = await box.db.admin("select domain from legitimate_domains");
    assert.equal(allowed.rows[0]?.domain, "sister.example.org.au");
    assert.equal((await call(box.deps, "POST", `/findings/${finding}/dismiss`, owner.token, { reason: "not_relevant" })).status, 409);

    const evidence = "55555555-5555-4555-8555-555555555511";
    await box.db.admin(
      `insert into finding_evidence (id, tenant_id, finding_id, label, object_key, collected_at, source_id, licence, tlp)
       values ($1, $2, $3, 'page', 'raw/page.txt', now(), 'crtsh', 'public', 'TLP:GREEN')`,
      [evidence, orgA, finding],
    );
    const link = await call(box.deps, "GET", `/findings/${finding}/evidence/${evidence}`, owner.token);
    assert.equal((link.body as { expiresIn: number }).expiresIn, 300);

    const synced = await call(box.deps, "POST", "/credentials/sync", owner.token, { domain: "a.example.org.au" });
    assert.equal(synced.status, 200, JSON.stringify(synced.body));
    const blob = JSON.stringify((await box.db.admin("select * from credential_exposures")).rows);
    assert.equal(blob.includes("hunter2-not-a-real-password"), false);
    const viewed = await call(box.deps, "GET", "/credentials", owner.token);
    assert.equal(viewed.status, 200);
    const viewedAudit = await box.db.admin("select count(*)::int as count from audit_log where action = 'credential_exposure_viewed'");
    assert.ok(Number(viewedAudit.rows[0]?.count ?? 0) >= 1);

    assert.equal((await call(box.deps, "POST", `/orgs/${orgA}/invites`, owner.token, { email: "member@example.org.au", role: "member" })).status, 200);
    const member = await login(box, "member@example.org.au");
    assert.equal((await call(box.deps, "POST", `/orgs/${orgA}/invites`, member.token, { email: "nope@example.org.au", role: "member" })).status, 403);
    assert.equal((await call(box.deps, "GET", "/credentials", member.token)).status, 403);
    assert.equal((await call(box.deps, "POST", `/orgs/${orgA}/members/${member.userId}/role`, owner.token, { role: "analyst" })).status, 200);

    await box.db.admin("update findings set status = 'open', confidence = 50 where id = $1", [finding]);
    const proposed = await call(box.deps, "POST", "/actions", owner.token, { findingId: finding, kind: "tell_helper", preview: { text: "Tell your IT helper." } });
    const actionId = (proposed.body as { id: string }).id;
    assert.equal((await call(box.deps, "POST", `/actions/${actionId}/execute`, owner.token, {})).status, 409);
    assert.equal((await call(box.deps, "POST", `/actions/${actionId}/approve`, member.token, {})).status, 403);
    assert.equal((await call(box.deps, "POST", `/actions/${actionId}/approve`, owner.token, {})).status, 200);
    assert.equal((await call(box.deps, "POST", `/actions/${actionId}/execute`, owner.token, {})).status, 200);

    assert.equal((await call(box.deps, "POST", "/share", owner.token, { findingId: finding })).status, 403);
    box.deps.sharingLaunchOverrideForTests = true;
    const cultural = "33333333-3333-4333-8333-333333333322";
    await box.db.admin(
      `insert into findings (id, tenant_id, kind, title, plain_english_summary, confidence, confidence_factors, status, provenance, cultural)
       values ($1, $2, 'lookalike_domain', 'A cultural note', 'A private story.', 50, $3::jsonb, 'open', $4::jsonb, true)`,
      [cultural, orgA, FACTORS, PROVENANCE],
    );
    assert.equal((await call(box.deps, "POST", "/share", owner.token, { findingId: cultural })).status, 403);
    await box.db.admin("insert into sharing_preferences (tenant_id, category, enabled) values ($1, 'lookalike_domain', true)", [orgA]);
    const shared = await call(box.deps, "POST", "/share", owner.token, { findingId: finding });
    assert.equal(shared.status, 200, JSON.stringify(shared.body));
    const stixId = (shared.body as { stixId: string }).stixId;
    const row = await box.db.admin<{ tenant_id: string | null }>("select tenant_id from stix_objects where id = $1", [stixId]);
    assert.equal(row.rows[0]?.tenant_id ?? null, null);
    assert.ok(await getStix(box.db, stixId, orgB));

    const investigated = await call(box.deps, "POST", "/agents/investigate", owner.token, { findingId: finding });
    assert.equal(investigated.status, 200, JSON.stringify(investigated.body));
    assert.equal((investigated.body as { findingStatus: string }).findingStatus, "open");
    assert.equal((investigated.body as { confidence: number }).confidence, 80);
    const blocked = await call(box.deps, "POST", "/cost", owner.token, { category: "agent", units: 1, aud: 15 });
    assert.equal((blocked.body as { mode: string }).mode, "deterministic");
    const callsBefore = modelCalls;
    const stopped = await call(box.deps, "POST", "/agents/investigate", owner.token, { findingId: finding });
    assert.equal(stopped.status, 409);
    assert.equal(modelCalls, callsBefore);
    assert.equal((await call(box.deps, "POST", "/integrations/m365/connect", owner.token, { refreshToken: "x", scopes: ["Mail.Read"] })).status, 400);
  } finally {
    await box.db.close();
  }
});
