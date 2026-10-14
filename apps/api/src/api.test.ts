import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import type { Server } from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createApp, ROUTES, type AppDeps } from "./app.js";
import { hashToken, MemoryStore, type StoredFinding } from "./store.js";
import { assertPlainCopy, onboardingCopy } from "./copy.js";
import { applyWeightChanges, proposeWeightChanges } from "./weights.js";

async function listen(deps: AppDeps): Promise<{ server: Server; port: number }> {
  const server = createApp(deps);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  return { server, port: (server.address() as { port: number }).port };
}

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
  const setCookies = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : [response.headers.get("set-cookie") ?? ""];
  return { status: response.status, json: text ? JSON.parse(text) : {}, cookie: setCookies.join("; ") };
}

function deps(resolveTxt?: AppDeps["resolveTxt"]): AppDeps {
  return {
    store: new MemoryStore(),
    mailer: { sent: [] },
    now: () => new Date("2026-10-14T00:00:00.000Z"),
    resolveTxt: resolveTxt ?? (async () => []),
  };
}

async function login(port: number, app: AppDeps, email: string): Promise<string> {
  const sent = await call(port, "POST", "/auth/magic-link", { body: { email } });
  assert.equal(sent.status, 202);
  const raw = app.mailer.sent.at(-1)?.text.match(/token=([a-f0-9]+)/)?.[1];
  assert.ok(raw);
  const back = await call(port, "GET", `/auth/callback?token=${raw}`);
  const token = back.cookie.match(/cti_session=([^;]+)/)?.[1];
  assert.ok(token);
  assert.equal(app.store.sessions.has(token), false);
  assert.equal(app.store.sessions.has(hashToken(decodeURIComponent(token))), true);
  const session = app.store.sessions.get(hashToken(decodeURIComponent(token)))!;
  assert.equal(session.expiresAt - app.now().getTime(), 12 * 60 * 60 * 1000);
  return `cti_session=${token}`;
}

function finding(tenantId: string, id: string): StoredFinding {
  return {
    id,
    tenantId,
    kind: "lookalike_domain",
    title: "Lookalike",
    plainEnglishSummary: "A site looks like your domain.",
    confidence: 55,
    status: "open",
    stixRefs: [],
    createdAt: "2026-10-14T00:00:00Z",
    provenance: [{ sourceId: "crtsh", collectedAt: "2026-10-14T00:00:00Z", licence: "public", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }],
    confidenceFactors: [{ code: "edit_distance_1", points: 25, reason: "One change from your domain." }],
    evidence: [{
      id: `${id}-ev`,
      label: "Certificate",
      objectKey: `raw/${id}`,
      url: null,
      collectedAt: "2026-10-14T00:00:00Z",
      sourceId: "crtsh",
      licence: "public",
      tlp: "TLP:CLEAR",
    }],
  };
}

test("domain verification requires consent, a TXT record and an audit row", async () => {
  let txt: string[] = [];
  const app = deps(async () => [txt]);
  const live = await listen(app);
  try {
    const cookie = await login(live.port, app, "owner@example.org.au");
    const org = await call(live.port, "POST", "/orgs", { cookie, body: { name: "Example Land Council", orgType: "Land Council" } });
    assert.equal(org.status, 201);
    assert.equal(org.json.role, "owner");
    const blocked = await call(live.port, "POST", "/domains", { cookie, body: { domain: "example.org.au" } });
    assert.equal(blocked.status, 409);
    const consent = await call(live.port, "POST", `/orgs/${org.json.id}/consents`, {
      cookie,
      body: { scope: "domain_monitoring", grantorName: "Alex Example", grantorRole: "owner" },
    });
    assert.equal(consent.status, 201);
    const created = await call(live.port, "POST", "/domains", { cookie, body: { domain: "example.org.au" } });
    assert.match(created.json.txt, /^cti-verify=/);
    txt = [created.json.txt];
    const checked = await call(live.port, "POST", `/domains/${created.json.id}/check`, { cookie, body: {} });
    assert.equal(checked.status, 200);
    assert.ok(app.store.audit.some((row) => row.action === "domain.verified"));
    assert.ok(app.store.audit.some((row) => row.action === "org.created"));
    const memberCookie = await login(live.port, app, "member@example.org.au");
    const member = [...app.store.users.values()].find((user) => user.email === "member@example.org.au")!;
    app.store.memberships.push({ tenantId: org.json.id, userId: member.id, role: "member" });
    const memberSession = [...app.store.sessions.values()].find((value) => value.userId === member.id)!;
    memberSession.tenantId = org.json.id;
    const asMember = await call(live.port, "POST", `/orgs/${org.json.id}/invites`, { cookie: memberCookie, body: { email: "new@example.org.au" } });
    assert.equal(asMember.status, 403);
  } finally {
    live.server.close();
  }
});

test("dismiss and challenge are audited and legitimate domains are not re-alerted", async () => {
  const app = deps();
  const live = await listen(app);
  try {
    const cookie = await login(live.port, app, "owner@example.org.au");
    const org = await call(live.port, "POST", "/orgs", { cookie, body: { name: "Example", orgType: "ACCO" } });
    const id = randomUUID();
    app.store.findings.push(finding(org.json.id, id));
    const dismissed = await call(live.port, "POST", `/findings/${id}/dismiss`, { cookie, body: { reason: "legitimate_domain", domain: "partner.org.au" } });
    assert.equal(dismissed.status, 200);
    assert.equal(app.store.allow.some((item) => item.domain === "partner.org.au"), true);
    assert.ok(app.store.opinions.length === 0);
    const again = await call(live.port, "POST", `/findings/${id}/dismiss`, { cookie, body: { reason: "not_ours" } });
    assert.equal(again.status, 409);
    const reopened = await call(live.port, "POST", `/findings/${id}/reopen`, { cookie, body: {} });
    assert.equal(reopened.status, 200);
    const challenged = await call(live.port, "POST", `/findings/${id}/challenge`, { cookie, body: { comment: "Please check" } });
    assert.equal(challenged.status, 200);
    assert.equal(challenged.json.status, "challenged");
    assert.ok(app.store.audit.some((row) => row.action === "finding.dismissed"));
    const notOurs = await call(live.port, "POST", `/findings/${id}/reopen`, { cookie, body: {} });
    assert.equal(notOurs.status, 200);
    const opinion = await call(live.port, "POST", `/findings/${id}/dismiss`, { cookie, body: { reason: "not_ours" } });
    assert.equal(opinion.status, 200);
    assert.equal(app.store.opinions.at(-1)?.opinion, "strongly-disagree");
  } finally {
    live.server.close();
  }
});

test("actions approval stores the preview that is executed", async () => {
  const app = deps();
  const live = await listen(app);
  try {
    const cookie = await login(live.port, app, "owner@example.org.au");
    await call(live.port, "POST", "/orgs", { cookie, body: { name: "Example", orgType: "other" } });
    const preview = { domain: "lookalike.example", list: "block" };
    const created = await call(live.port, "POST", "/actions", { cookie, body: { kind: "m365_block_domain", preview } });
    const approved = await call(live.port, "POST", `/actions/${created.json.id}/approve`, { cookie, body: {} });
    assert.equal(approved.status, 200);
    assert.deepEqual(approved.json.preview, preview);
    assert.deepEqual(approved.json.applied, preview);
    assert.ok(app.store.audit.some((row) => row.action === "action.approved"));
    assert.ok(app.store.audit.some((row) => row.action === "action.executed"));
  } finally {
    live.server.close();
  }
});

test("review resolution requires a reason and stays inside the tenant", async () => {
  const app = deps();
  const live = await listen(app);
  try {
    const cookie = await login(live.port, app, "analyst@example.org.au");
    const org = await call(live.port, "POST", "/orgs", { cookie, body: { name: "Example", orgType: "AMS" } });
    const id = randomUUID();
    const row = finding(org.json.id, id);
    row.status = "challenged";
    app.store.findings.push(row);
    const queue = await call(live.port, "GET", "/review", { cookie });
    assert.equal(queue.json.length, 1);
    const missing = await call(live.port, "POST", `/review/${id}/resolve`, { cookie, body: { outcome: "uphold" } });
    assert.equal(missing.status, 400);
    const resolved = await call(live.port, "POST", `/review/${id}/resolve`, { cookie, body: { outcome: "uphold", reason: "The evidence still holds." } });
    assert.equal(resolved.status, 200);
    assert.equal(proposeWeightChanges([{ factor: "homoglyph", upheld: false }]).homoglyph, -1);
    assert.throws(() => applyWeightChanges());
  } finally {
    live.server.close();
  }
});

test("credential views are audited and m365 tokens stay encrypted", async () => {
  const app = deps();
  const live = await listen(app);
  try {
    const cookie = await login(live.port, app, "owner@example.org.au");
    const org = await call(live.port, "POST", "/orgs", { cookie, body: { name: "Example", orgType: "other" } });
    const exposureId = randomUUID();
    app.store.exposures.push({ id: exposureId, tenantId: org.json.id, emailCiphertext: "cipher", breachName: "ExampleBreach" });
    const viewed = await call(live.port, "GET", `/credential-exposures/${exposureId}`, { cookie });
    assert.equal(viewed.status, 200);
    assert.ok(app.store.audit.some((row) => row.action === "credential_exposure.view"));
    const connected = await call(live.port, "POST", "/integrations/m365/connect", { cookie, body: { accessToken: "plain-token" } });
    assert.equal(connected.json.ciphertextStored, true);
    assert.notEqual(app.store.tokens[0]?.ciphertext, "plain-token");
    app.store.cachedUsers.push({ tenantId: org.json.id, upn: "person@example.org.au" });
    const disconnected = await call(live.port, "POST", "/integrations/m365/disconnect", { cookie, body: {} });
    assert.equal(disconnected.status, 200);
    assert.equal(app.store.tokens.length, 0);
    assert.equal(app.store.cachedUsers.length, 0);
    assert.ok(app.store.audit.some((row) => row.action === "m365.connected"));
  } finally {
    live.server.close();
  }
});

test("findings API redacts restricted evidence and always returns provenance", async () => {
  const app = deps();
  const live = await listen(app);
  try {
    const cookie = await login(live.port, app, "owner@example.org.au");
    const org = await call(live.port, "POST", "/orgs", { cookie, body: { name: "Example", orgType: "other" } });
    const id = randomUUID();
    const row = finding(org.json.id, id);
    row.evidence.push({
      id: "amber",
      label: "Restricted feed",
      objectKey: "raw/secret",
      url: "https://secret.example/evidence",
      collectedAt: "2026-10-14T00:00:00Z",
      sourceId: "restricted",
      licence: "restricted",
      tlp: "TLP:AMBER",
    });
    app.store.findings.push(row);
    const body = await call(live.port, "GET", `/findings/${id}`, { cookie });
    assert.equal(body.json.provenance[0].sourceId, "crtsh");
    assert.ok(body.json.confidenceFactors.length > 0);
    assert.ok(body.json.links.dismiss);
    const amber = body.json.evidence.find((item: { label: string }) => item.label === "Restricted feed");
    assert.equal(amber.redacted, true);
    assert.equal(amber.url, undefined);
    const clear = await call(live.port, "GET", `/findings/${id}/evidence/${id}-ev`, { cookie });
    assert.match(clear.json.url, /expires=/);
  } finally {
    live.server.close();
  }
});

test("onboarding copy is plain Australian English", () => {
  assert.doesNotThrow(() => assertPlainCopy(Object.values(onboardingCopy).join(" ")));
});

test("openapi lists findings and auth", () => {
  const yaml = readFileSync(fileURLToPath(new URL("../openapi.yaml", import.meta.url)), "utf8");
  assert.match(yaml, /\/findings/);
  assert.match(yaml, /\/auth\/magic-link/);
});

test("isolation: every route is covered and tenant A cannot read tenant B", async () => {
  const app = deps();
  const live = await listen(app);
  try {
    const cookieA = await login(live.port, app, "a@example.org.au");
    const cookieB = await login(live.port, app, "b@example.org.au");
    const orgA = (await call(live.port, "POST", "/orgs", { cookie: cookieA, body: { name: "Org A", orgType: "ACCO" } })).json;
    const orgB = (await call(live.port, "POST", "/orgs", { cookie: cookieB, body: { name: "Org B", orgType: "AMS" } })).json;
    const userB = [...app.store.users.values()].find((user) => user.email === "b@example.org.au")!;
    const findingA = randomUUID();
    const findingB = randomUUID();
    const domainB = randomUUID();
    const actionB = randomUUID();
    const exposureB = randomUUID();
    const shareB = randomUUID();
    app.store.findings.push(finding(orgA.id, findingA), finding(orgB.id, findingB));
    app.store.domains.push({ id: domainB, tenantId: orgB.id, domain: "b.example.org.au", status: "pending", token: "tok", verifiedAt: null, emailTokenHash: null });
    app.store.actions.push({ id: actionB, tenantId: orgB.id, findingId: findingB, kind: "manual_steps", status: "proposed", preview: { domain: "b.example" }, approvedBy: null, approvedAt: null });
    app.store.exposures.push({ id: exposureB, tenantId: orgB.id, emailCiphertext: "cipher-b", breachName: "Breach B" });
    app.store.shares.push({ id: shareB, tenantId: orgB.id, cultural: false, approvedBy: null, sanitised: "warning" });
    app.store.costs.push({ tenantId: orgB.id, aud: 424242 });
    const cases: Record<string, { method: string; path: string; body?: unknown; status: number; absent?: string }> = {
      healthz: { method: "GET", path: "/healthz", status: 200 },
      "magic-link": { method: "POST", path: "/auth/magic-link", body: { email: "c@example.org.au" }, status: 202 },
      callback: { method: "GET", path: "/auth/callback?token=missing", status: 400 },
      logout: { method: "POST", path: "/auth/logout", status: 200 },
      "verify-email": { method: "GET", path: "/domains/verify-email?token=missing", status: 404 },
      "create-org": { method: "POST", path: "/orgs", body: { name: "Org C", orgType: "other" }, status: 201, absent: orgB.id },
      "get-org": { method: "GET", path: `/orgs/${orgB.id}`, status: 404 },
      invite: { method: "POST", path: `/orgs/${orgB.id}/invites`, body: { email: "x@example.org.au" }, status: 404 },
      consent: { method: "POST", path: `/orgs/${orgB.id}/consents`, body: { scope: "domain_monitoring", grantorName: "A", grantorRole: "owner" }, status: 404 },
      "set-role": { method: "POST", path: `/orgs/${orgB.id}/members/${userB.id}/role`, body: { role: "member" }, status: 404 },
      "list-domains": { method: "GET", path: "/domains", status: 200, absent: domainB },
      "create-domain": { method: "POST", path: "/domains", body: { domain: "a.example.org.au" }, status: 409, absent: domainB },
      "get-domain": { method: "GET", path: `/domains/${domainB}`, status: 404 },
      "check-domain": { method: "POST", path: `/domains/${domainB}/check`, body: {}, status: 404 },
      "email-domain": { method: "POST", path: `/domains/${domainB}/email`, body: { email: "admin@b.example.org.au" }, status: 404 },
      "list-findings": { method: "GET", path: "/findings", status: 200, absent: findingB },
      "get-finding": { method: "GET", path: `/findings/${findingB}`, status: 404 },
      dismiss: { method: "POST", path: `/findings/${findingB}/dismiss`, body: { reason: "not_ours" }, status: 404 },
      challenge: { method: "POST", path: `/findings/${findingB}/challenge`, body: {}, status: 404 },
      reopen: { method: "POST", path: `/findings/${findingB}/reopen`, body: {}, status: 404 },
      evidence: { method: "GET", path: `/findings/${findingB}/evidence/${findingB}-ev`, status: 404 },
      "create-action": { method: "POST", path: "/actions", body: { kind: "manual_steps", preview: { domain: "a.example" } }, status: 201, absent: actionB },
      "get-action": { method: "GET", path: `/actions/${actionB}`, status: 404 },
      "approve-action": { method: "POST", path: `/actions/${actionB}/approve`, body: {}, status: 404 },
      "cancel-action": { method: "POST", path: `/actions/${actionB}/cancel`, body: {}, status: 404 },
      review: { method: "GET", path: "/review", status: 200, absent: findingB },
      "resolve-review": { method: "POST", path: `/review/${findingB}/resolve`, body: { outcome: "uphold", reason: "no" }, status: 404 },
      "list-exposures": { method: "GET", path: "/credential-exposures", status: 200, absent: exposureB },
      "get-exposure": { method: "GET", path: `/credential-exposures/${exposureB}`, status: 404 },
      "m365-connect": { method: "POST", path: "/integrations/m365/connect", body: { accessToken: "tok" }, status: 201, absent: "cipher-b" },
      "m365-disconnect": { method: "POST", path: "/integrations/m365/disconnect", body: {}, status: 200, absent: "cipher-b" },
      "share-get": { method: "GET", path: "/sharing/preferences", status: 200, absent: shareB },
      "share-put": { method: "PUT", path: "/sharing/preferences", body: { category: "phishing", enabled: true }, status: 200, absent: shareB },
      "share-preview": { method: "POST", path: "/sharing/preview", body: { text: "A public warning" }, status: 200, absent: shareB },
      "share-approve": { method: "POST", path: `/sharing/${shareB}/approve`, body: { category: "phishing" }, status: 404 },
      "notif-get": { method: "GET", path: "/notifications/preferences", status: 200, absent: orgB.id },
      "notif-put": { method: "PUT", path: "/notifications/preferences", body: { mode: "off" }, status: 200, absent: orgB.id },
      cost: { method: "GET", path: "/cost", status: 200, absent: "424242" },
    };
    for (const route of ROUTES) {
      assert.ok(cases[route.id], `missing isolation test for ${route.id}`);
    }
    for (const route of ROUTES) {
      const item = cases[route.id]!;
      const response = await call(live.port, item.method, item.path, {
        cookie: route.isolation === "public" ? undefined : cookieA,
        body: item.body,
      });
      assert.equal(response.status, item.status, route.id);
      if (item.absent) assert.equal(JSON.stringify(response.json).includes(item.absent), false, route.id);
    }
  } finally {
    live.server.close();
  }
});
