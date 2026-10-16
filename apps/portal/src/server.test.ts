import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createPortal } from "./server.js";

interface Call { method: string; path: string; body: Record<string, unknown> | null; cookie?: string }
interface Reply { status: number; body?: unknown; headers?: Record<string, string> }
type Routes = Record<string, Reply | ((call: Call) => Reply)>;

const finding = {
  id: "f1",
  tenantId: "t1",
  kind: "lookalike_domain",
  title: "A website looks like your domain",
  plainEnglishSummary: "The name is close to a domain you checked.",
  confidence: 72,
  status: "open",
  stixRefs: [],
  createdAt: "2026-10-14T00:00:00Z",
  provenance: [{ sourceId: "crtsh", collectedAt: "2026-10-14T00:00:00Z", licence: "public logs", accessRestriction: "TLP:CLEAR", evidenceRefs: [] }],
  confidenceFactors: [{ code: "edit_distance_1", points: 25, reason: "One change away." }],
  evidence: [],
};
const me = { user: { id: "u1", email: "a@example.org.au" }, tenantId: "t1", role: "owner", org: { id: "t1", name: "Org", orgType: "ACCO" } };

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

function close(server: Server): Promise<void> {
  server.closeAllConnections();
  return new Promise((resolve) => server.close(() => resolve()));
}

async function withPortal(routes: Routes, run: (portal: string, calls: Call[]) => Promise<void>, apiUrl?: string): Promise<void> {
  const calls: Call[] = [];
  const api = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const text = Buffer.concat(chunks).toString("utf8");
    const call: Call = { method: req.method ?? "GET", path: req.url ?? "/", body: text ? JSON.parse(text) : null, cookie: req.headers.cookie };
    calls.push(call);
    const route = routes[`${call.method} ${call.path}`];
    const reply = typeof route === "function" ? route(call) : route ?? { status: 404, body: { error: "not found" } };
    res.writeHead(reply.status, { "content-type": "application/json", ...reply.headers });
    res.end(reply.body === undefined ? "" : JSON.stringify(reply.body));
  });
  const apiBase = await listen(api);
  const portal = createPortal({ apiUrl: apiUrl ?? apiBase });
  const portalBase = await listen(portal);
  try {
    await run(portalBase, calls);
  } finally {
    await close(portal);
    await close(api);
  }
}

function post(url: string, form: Record<string, string>, headers: Record<string, string> = {}): Promise<Response> {
  return fetch(url, { method: "POST", body: new URLSearchParams(form), redirect: "manual", headers: { cookie: "cti_session=s1", ...headers } });
}

function get(url: string): Promise<Response> {
  return fetch(url, { redirect: "manual", headers: { cookie: "cti_session=s1" } });
}

test("login flow emails a link and relays the session cookie", async () => {
  await withPortal({
    "POST /auth/magic-link": { status: 202, body: { ok: true } },
    "GET /auth/callback?token=abc": { status: 200, body: { ok: true }, headers: { "set-cookie": "cti_session=s2; HttpOnly; SameSite=Lax; Max-Age=43200" } },
    "GET /auth/callback?token=old": { status: 400, body: { error: "link expired" } },
  }, async (portal, calls) => {
    const page = await fetch(`${portal}/login`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /<label for="email">/);
    const sent = await post(`${portal}/login`, { email: "a@example.org.au" });
    assert.equal(sent.status, 200);
    assert.match(await sent.text(), /Check your email/);
    assert.deepEqual(calls[0]?.body, { email: "a@example.org.au" });
    const callback = await fetch(`${portal}/auth/callback?token=abc`, { redirect: "manual" });
    assert.equal(callback.status, 303);
    assert.equal(callback.headers.get("location"), "/");
    assert.equal(callback.headers.get("set-cookie"), "cti_session=s2; HttpOnly; SameSite=Lax; Max-Age=43200; Path=/");
    const expired = await fetch(`${portal}/auth/callback?token=old`, { redirect: "manual" });
    assert.equal(expired.status, 400);
    assert.match(await expired.text(), /href="\/login"/);
  });
});

test("logout clears the cookie", async () => {
  await withPortal({ "POST /auth/logout": { status: 200, body: { ok: true } } }, async (portal, calls) => {
    const response = await post(`${portal}/logout`, {});
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/login");
    assert.match(response.headers.get("set-cookie") ?? "", /^cti_session=; Path=\/; Max-Age=0/);
    assert.equal(calls[0]?.cookie, "cti_session=s1");
  });
});

test("home sends people to sign in, onboarding or their findings", async () => {
  await withPortal({ "GET /me": { status: 401, body: { error: "sign in required" } } }, async (portal) => {
    const response = await get(`${portal}/`);
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/login");
  });
  await withPortal({ "GET /me": { status: 200, body: { ...me, tenantId: null, org: null } } }, async (portal) => {
    const response = await get(`${portal}/`);
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/onboarding");
  });
  await withPortal({ "GET /me": { status: 200, body: me }, "GET /findings": { status: 200, body: [finding] } }, async (portal, calls) => {
    const response = await get(`${portal}/`);
    assert.equal(response.status, 200);
    assert.match(await response.text(), /A website looks like your domain/);
    assert.ok(calls.every((call) => call.cookie === "cti_session=s1"));
  });
});

test("onboarding creates the org then records consent", async () => {
  await withPortal({
    "GET /me": { status: 200, body: { ...me, tenantId: null, org: null } },
    "POST /orgs": { status: 201, body: { id: "org-1", name: "Mob Corp", role: "owner" } },
    "POST /orgs/org-1/consents": { status: 201, body: { ok: true } },
  }, async (portal, calls) => {
    const form = { name: "Mob Corp", orgType: "ACCO", grantorName: "Aunty Example", grantorRole: "CEO" };
    const missing = await post(`${portal}/onboarding`, form);
    assert.equal(missing.status, 400);
    assert.match(await missing.text(), /Tick the box/);
    assert.ok(!calls.some((call) => call.path === "/orgs"));
    const response = await post(`${portal}/onboarding`, { ...form, consent: "yes" });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/domains");
    const writes = calls.filter((call) => call.method === "POST");
    assert.deepEqual(writes.map((call) => call.path), ["/orgs", "/orgs/org-1/consents"]);
    assert.deepEqual(writes[0]?.body, { name: "Mob Corp", orgType: "ACCO" });
    assert.deepEqual(writes[1]?.body, { scope: "domain_monitoring", grantorName: "Aunty Example", grantorRole: "CEO" });
  });
});

test("dismiss with reason other and no comment shows the API error", async () => {
  await withPortal({
    "POST /findings/f1/dismiss": { status: 400, body: { error: "add a short note" } },
    "GET /findings/f1": { status: 200, body: finding },
    "POST /findings/f1/challenge": { status: 200, body: { ...finding, status: "challenged" } },
  }, async (portal, calls) => {
    const response = await post(`${portal}/findings/f1/dismiss`, { reason: "other", comment: "" });
    assert.equal(response.status, 400);
    assert.match(await response.text(), /role="alert">add a short note/);
    assert.deepEqual(calls[0]?.body, { reason: "other" });
    const challenged = await post(`${portal}/findings/f1/challenge`, { comment: "We own this one" });
    assert.equal(challenged.status, 303);
    assert.equal(challenged.headers.get("location"), "/findings/f1");
  });
});

test("domain check failures show on the domains page", async () => {
  await withPortal({
    "POST /domains/d1/check": { status: 409, body: { error: "TXT record not found yet" } },
    "GET /domains": { status: 200, body: [{ id: "d1", domain: "example.org.au", status: "pending", token: "abc", verifiedAt: null }] },
  }, async (portal) => {
    const response = await post(`${portal}/domains/d1/check`, {});
    assert.equal(response.status, 400);
    const html = await response.text();
    assert.match(html, /TXT record not found yet/);
    assert.match(html, /cti-verify=abc/);
  });
});

test("notification settings are saved with PUT", async () => {
  await withPortal({ "GET /me": { status: 200, body: me }, "PUT /notifications/preferences": { status: 200, body: { mode: "off" } } }, async (portal, calls) => {
    const response = await post(`${portal}/settings/notifications`, { mode: "off" });
    assert.equal(response.status, 303);
    assert.deepEqual(calls.find((call) => call.method === "PUT")?.body, { mode: "off" });
    const bad = await post(`${portal}/settings/notifications`, { mode: "loud" });
    assert.equal(bad.status, 400);
  });
});

test("an org without consent is sent back to the consent form", async () => {
  await withPortal({ "GET /me": { status: 200, body: { ...me, consented: false } } }, async (portal) => {
    for (const path of ["/", "/domains"]) {
      const response = await get(`${portal}${path}`);
      assert.equal(response.status, 303);
      assert.equal(response.headers.get("location"), "/onboarding");
    }
    const page = await get(`${portal}/onboarding?notice=stopped`);
    assert.equal(page.status, 200);
    const html = await page.text();
    assert.match(html, /role="status">We have stopped watching your domains/);
    assert.match(html, /id="grantor-name"/);
    assert.doesNotMatch(html, /id="org-name"/);
  });
});

test("owners can stop monitoring after confirming", async () => {
  const routes = {
    "GET /me": { status: 200, body: { ...me, consented: true } },
    "GET /notifications/preferences": { status: 200, body: { mode: "digest" } },
    "POST /orgs/t1/consents/revoke": { status: 200, body: { ok: true } },
  };
  await withPortal(routes, async (portal, calls) => {
    assert.match(await (await get(`${portal}/settings/notifications`)).text(), /Stop watching our domains/);
    const unconfirmed = await post(`${portal}/settings/stop-monitoring`, {});
    assert.equal(unconfirmed.status, 400);
    assert.match(await unconfirmed.text(), /Tick the box/);
    assert.ok(!calls.some((call) => call.path.endsWith("/revoke")));
    const response = await post(`${portal}/settings/stop-monitoring`, { confirm: "yes" });
    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), "/onboarding?notice=stopped");
    assert.equal(calls.filter((call) => call.path === "/orgs/t1/consents/revoke").length, 1);
  });
  await withPortal({ ...routes, "GET /me": { status: 200, body: { ...me, role: "member", consented: true } } }, async (portal, calls) => {
    assert.doesNotMatch(await (await get(`${portal}/settings/notifications`)).text(), /Stop watching our domains/);
    const response = await post(`${portal}/settings/stop-monitoring`, { confirm: "yes" });
    assert.equal(response.status, 403);
    assert.ok(!calls.some((call) => call.path.endsWith("/revoke")));
  });
});

test("Australian alerts show ransomware sectors and ranked advisories safely", async () => {
  const ransomware = { days: 90, total: 12, similarSectors: 3, sectors: [{ name: "Health", count: 5 }, { name: "Education", count: 2 }], groups: [{ name: "GroupA", count: 4 }], summary: "12 Australian organisations were listed by ransomware groups in the last 90 days." };
  const advisory = {
    id: "a1", sourceId: "acsc-alerts", title: "<b>Patch now</b>", url: "https://www.cyber.gov.au/alert/1", summary: "word ".repeat(200),
    publishedAt: "2026-10-14T00:00:00Z", cves: ["CVE-2026-0001"], tags: [], attackTechniques: [], licence: "CC BY 4.0", relevance: 80,
    reasons: ["It affects software many small organisations use."],
  };
  const hostile = { ...advisory, id: "a2", sourceId: "cisa-advisories", title: "Other", url: "javascript:alert(1)", cves: [] };
  await withPortal({
    "GET /me": { status: 200, body: me },
    "GET /advisories": { status: 200, body: [advisory, hostile] },
    "GET /ransomware/au": { status: 200, body: ransomware },
  }, async (portal) => {
    const response = await get(`${portal}/alerts`);
    assert.equal(response.status, 200);
    const html = await response.text();
    assert.match(html, /<th scope="col">Sector<\/th>/);
    assert.match(html, /<td>Health<\/td><td>5<\/td>/);
    assert.match(html, /href="https:\/\/www.cyber.gov.au\/alert\/1" rel="noopener noreferrer">&lt;b&gt;Patch now&lt;\/b&gt;/);
    assert.match(html, /Australian Cyber Security Centre/);
    assert.match(html, /US CISA/);
    assert.match(html, /14 October 2026/);
    assert.match(html, /CVE-2026-0001/);
    assert.match(html, /Licence: CC BY 4.0/);
    assert.ok(!html.includes("javascript:"));
    assert.ok(!html.includes("word ".repeat(100)));
  });
  await withPortal({
    "GET /me": { status: 200, body: me },
    "GET /advisories": { status: 200, body: [] },
    "GET /ransomware/au": { status: 200, body: { ...ransomware, sectors: [] } },
  }, async (portal) => {
    assert.match(await (await get(`${portal}/alerts`)).text(), /No Australian alerts yet\. We check the Australian Cyber Security Centre every hour\./);
  });
});

test("cross-origin posts are refused and oversized bodies are rejected", async () => {
  await withPortal({ "POST /auth/magic-link": { status: 202, body: { ok: true } } }, async (portal, calls) => {
    const cross = await post(`${portal}/login`, { email: "a@example.org.au" }, { origin: "https://evil.example" });
    assert.equal(cross.status, 403);
    const same = await post(`${portal}/login`, { email: "a@example.org.au" }, { origin: portal });
    assert.equal(same.status, 200);
    const big = await post(`${portal}/login`, { email: "a".repeat(20 * 1024) });
    assert.equal(big.status, 413);
    assert.equal(calls.length, 1);
  });
});

test("security headers are sent on every page", async () => {
  await withPortal({}, async (portal) => {
    for (const path of ["/login", "/nowhere"]) {
      const response = await fetch(`${portal}${path}`);
      assert.equal(response.headers.get("content-security-policy"), "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'");
      assert.equal(response.headers.get("x-content-type-options"), "nosniff");
      assert.equal(response.headers.get("referrer-policy"), "no-referrer");
      assert.equal(response.headers.get("x-frame-options"), "DENY");
    }
    assert.equal((await fetch(`${portal}/nowhere`)).status, 404);
  });
});

test("hostile finding content is escaped and bad ids never reach the API", async () => {
  const hostile = {
    ...finding,
    title: "<script>alert('x')</script>",
    evidence: [{ label: "<img src=x onerror=alert(1)>", url: "javascript:alert(1)", sourceId: "crtsh", licence: "public", collectedAt: "2026-10-14", redacted: false }],
  };
  await withPortal({ "GET /findings/f1": { status: 200, body: hostile } }, async (portal, calls) => {
    const html = await (await get(`${portal}/findings/f1`)).text();
    assert.ok(!html.includes("<script>alert"));
    assert.ok(!html.includes("<img src=x"));
    assert.ok(!html.includes("javascript:"));
    assert.match(html, /&lt;script&gt;alert\(&#39;x&#39;\)&lt;\/script&gt;/);
    const bad = await get(`${portal}/findings/..%2Fme`);
    assert.equal(bad.status, 404);
    assert.equal(calls.length, 1);
  });
});

test("an unreachable API shows a friendly 502 page", async () => {
  const dead = createServer();
  const deadUrl = await listen(dead);
  await close(dead);
  await withPortal({}, async (portal) => {
    const response = await get(`${portal}/`);
    assert.equal(response.status, 502);
    assert.match(await response.text(), /not answering/);
  }, deadUrl);
});

test("health check and client script are served", async () => {
  await withPortal({}, async (portal) => {
    assert.deepEqual(await (await fetch(`${portal}/healthz`)).json(), { ok: true });
    const script = await fetch(`${portal}/app.js`);
    assert.equal(script.status, 200);
    assert.match(script.headers.get("content-type") ?? "", /javascript/);
  });
});
