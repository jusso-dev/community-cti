// End-to-end smoke test against a running stack, driven like a browser.
// Reads sign-in and verification emails from Mailpit.
//   PORTAL=http://192.168.1.19:3330 MAILPIT=http://192.168.1.19:18084 node scripts/smoke-homelab.mjs
// Prints one line per check and exits 1 if any fail. Creates throwaway users
// under the example.org.au test domain; it never touches real organisations.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

const PORTAL = (process.env.PORTAL ?? "http://192.168.1.19:3330").replace(/\/$/, "");
const MAILPIT = (process.env.MAILPIT ?? "http://192.168.1.19:18084").replace(/\/$/, "");
const run = randomUUID().slice(0, 8);
let failures = 0;

async function check(name, fn) {
  try {
    await fn();
    console.log(`ok   ${name}`);
  } catch (error) {
    failures += 1;
    console.log(`FAIL ${name}: ${error instanceof Error ? error.message.split("\n")[0] : error}`);
  }
}

class Browser {
  cookie = "";
  async go(method, path, form, headers = {}) {
    const response = await fetch(`${PORTAL}${path}`, {
      method,
      redirect: "manual",
      headers: {
        ...(this.cookie ? { cookie: this.cookie } : {}),
        ...(form ? { "content-type": "application/x-www-form-urlencoded", origin: PORTAL } : {}),
        ...headers,
      },
      body: form ? new URLSearchParams(form).toString() : undefined,
    });
    for (const value of response.headers.getSetCookie()) {
      const match = value.match(/cti_session=([^;]*)/);
      if (match) this.cookie = match[1] ? `cti_session=${match[1]}` : "";
    }
    return { status: response.status, location: response.headers.get("location"), headers: response.headers, html: await response.text() };
  }
}

async function mailTo(address, pattern) {
  for (let attempt = 0; attempt < 20; attempt++) {
    const list = await (await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:"${address}"`)}`)).json();
    for (const message of list.messages ?? []) {
      const full = await (await fetch(`${MAILPIT}/api/v1/message/${message.ID}`)).json();
      const link = full.Text?.match(pattern)?.[0];
      if (link) return link;
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`no email to ${address} matching ${pattern}`);
}

async function signIn(browser, email) {
  const sent = await browser.go("POST", "/login", { email });
  assert.equal(sent.status, 200);
  const link = await mailTo(email, /https?:\/\/\S+\/auth\/callback\?token=[a-f0-9]+/);
  const back = await browser.go("GET", new URL(link).pathname + new URL(link).search);
  assert.equal(back.status, 303, `callback status ${back.status}`);
  assert.ok(browser.cookie, "session cookie set");
  return link;
}

const owner = new Browser();
const ownerEmail = `owner-${run}@smoke.example.org.au`;
const domain = `smoke-${run}.example.org.au`;
let link = "";
let domainId = "";

await check("anonymous visitor is sent to sign in", async () => {
  const page = await new Browser().go("GET", "/");
  assert.equal(page.status, 303);
  assert.equal(page.location, "/login");
});

await check("security headers on pages", async () => {
  const page = await new Browser().go("GET", "/login");
  assert.match(page.headers.get("content-security-policy") ?? "", /default-src 'self'/);
  assert.equal(page.headers.get("x-content-type-options"), "nosniff");
  assert.equal(page.headers.get("referrer-policy"), "no-referrer");
});

await check("magic link sign-in through Mailpit", async () => {
  link = await signIn(owner, ownerEmail);
  assert.match(link, new RegExp(`^${PORTAL}/auth/callback`), "email link uses PORTAL_BASE_URL");
});

await check("magic link works only once", async () => {
  const again = await new Browser().go("GET", new URL(link).pathname + new URL(link).search);
  assert.notEqual(again.status, 303);
});

await check("new user goes to onboarding", async () => {
  const page = await owner.go("GET", "/");
  assert.equal(page.location, "/onboarding");
});

await check("onboarding needs consent ticked", async () => {
  const page = await owner.go("POST", "/onboarding", { name: `Smoke AMS ${run}`, orgType: "AMS", grantorName: "Smoke Tester", grantorRole: "CEO" });
  assert.equal(page.status, 400);
});

await check("onboarding creates the organisation and consent", async () => {
  const page = await owner.go("POST", "/onboarding", { name: `Smoke AMS ${run}`, orgType: "AMS", grantorName: "Smoke Tester", grantorRole: "CEO", consent: "yes" });
  assert.equal(page.status, 303);
  assert.equal(page.location, "/domains");
});

await check("add a domain and see the TXT value", async () => {
  const added = await owner.go("POST", "/domains", { domain });
  assert.equal(added.status, 303);
  const page = await owner.go("GET", "/domains");
  assert.ok(page.html.includes(domain));
  assert.match(page.html, /cti-verify=[a-f0-9]{32}/);
  domainId = page.html.match(/\/domains\/([0-9a-f-]{36})\/email/)?.[1] ?? "";
  assert.ok(domainId, "domain id in page");
});

await check("bad domain is refused politely", async () => {
  const page = await owner.go("POST", "/domains", { domain: "not a domain" });
  assert.equal(page.status, 400);
});

await check("DNS check fails without the TXT record", async () => {
  const page = await owner.go("POST", `/domains/${domainId}/check`, {});
  assert.equal(page.status, 400);
});

await check("email verification through admin@ address", async () => {
  const asked = await owner.go("POST", `/domains/${domainId}/email`, { email: `admin@${domain}` });
  assert.ok([200, 303].includes(asked.status), `status ${asked.status}`);
  const verify = await mailTo(`admin@${domain}`, /https?:\/\/\S+\/domains\/verify-email\?token=[a-f0-9]+/);
  const page = await new Browser().go("GET", new URL(verify).pathname + new URL(verify).search);
  assert.equal(page.status, 200);
  const domains = await owner.go("GET", "/domains");
  const section = domains.html.slice(domains.html.indexOf(`<h2>${domain}</h2>`));
  assert.match(section.slice(0, 400), /verified\. We are watching it/);
});

await check("Australian alerts page renders", async () => {
  const page = await owner.go("GET", "/alerts");
  assert.equal(page.status, 200);
  assert.ok(page.html.includes("Australian cyber alerts"));
});

await check("findings page renders", async () => {
  const page = await owner.go("GET", "/");
  assert.equal(page.status, 200);
});

await check("alert settings save", async () => {
  const saved = await owner.go("POST", "/settings/notifications", { mode: "immediate" });
  assert.equal(saved.status, 303);
  const page = await owner.go("GET", "/settings/notifications");
  assert.match(page.html, /value="immediate"[^>]*checked/);
});

await check("cross-site form post is refused", async () => {
  const page = await owner.go("POST", "/settings/notifications", { mode: "off" }, { origin: "http://evil.example" });
  assert.equal(page.status, 403);
});

await check("oversized form is refused", async () => {
  const page = await owner.go("POST", "/domains", { domain: "a".repeat(20_000) });
  assert.equal(page.status, 413);
});

await check("hostile org name is escaped", async () => {
  const other = new Browser();
  await signIn(other, `xss-${run}@smoke.example.org.au`);
  await other.go("POST", "/onboarding", { name: `<script>alert(1)</script> ${run}`, orgType: "other", grantorName: "<b>x</b>", grantorRole: "CEO", consent: "yes" });
  const page = await other.go("GET", "/domains");
  assert.ok(!page.html.includes("<script>alert(1)</script>"));
});

await check("other tenant cannot see this tenant's domain", async () => {
  const other = new Browser();
  await signIn(other, `other-${run}@smoke.example.org.au`);
  await other.go("POST", "/onboarding", { name: `Other ${run}`, orgType: "ACCO", grantorName: "Other", grantorRole: "CEO", consent: "yes" });
  const page = await other.go("GET", "/domains");
  assert.ok(!page.html.includes(domain));
  const poke = await other.go("POST", `/domains/${domainId}/check`, {});
  assert.ok([404, 400].includes(poke.status), `status ${poke.status}`);
});

await check("sign-in emails are rate limited", async () => {
  const email = `limit-${run}@smoke.example.org.au`;
  const statuses = [];
  for (let i = 0; i < 7; i++) statuses.push((await new Browser().go("POST", "/login", { email })).status);
  assert.ok(statuses.slice(5).some((status) => status !== 200), `statuses ${statuses.join(",")}`);
});

await check("sign out ends the session", async () => {
  const out = await owner.go("POST", "/logout", {});
  assert.equal(out.status, 303);
  const page = await owner.go("GET", "/");
  assert.equal(page.location, "/login");
});

console.log(failures === 0 ? "\nall checks passed" : `\n${failures} check(s) failed`);
process.exit(failures === 0 ? 0 : 1);
