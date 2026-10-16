import { test } from "node:test";
import assert from "node:assert/strict";
import { createPaperboyMailer, mailerFromEnv, MailSendError } from "./mail.js";

function fakeFetch(respond: (url: string, init: RequestInit) => Response) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return respond(url, init);
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const KEY = "pb_test_abc123";

test("paperboy mailer posts a Resend-shaped message with bearer key and idempotency", async () => {
  const fake = fakeFetch(() => Response.json({ id: "00000000-0000-4000-8000-000000000001" }));
  const mailer = createPaperboyMailer({ baseUrl: "http://paperboy.local:3238/", apiKey: KEY, from: "Community CTI <alerts@example.org.au>", fetchImpl: fake.impl });
  const sent = await mailer.send({ to: "owner@example.org.au", subject: "A website looks like your domain", text: "Hello", idempotencyKey: "alert:f1:u1", category: "alert" });
  assert.equal(sent.messageId, "00000000-0000-4000-8000-000000000001");
  const call = fake.calls[0]!;
  assert.equal(call.url, "http://paperboy.local:3238/api/v1/emails");
  const headers = call.init.headers as Record<string, string>;
  assert.equal(headers.authorization, `Bearer ${KEY}`);
  assert.equal(headers["idempotency-key"], "alert:f1:u1");
  const body = JSON.parse(String(call.init.body));
  assert.deepEqual(body.to, ["owner@example.org.au"]);
  assert.equal(body.from, "Community CTI <alerts@example.org.au>");
  assert.deepEqual(body.tags, [{ name: "app", value: "community-cti" }, { name: "category", value: "alert" }]);
  assert.equal(JSON.stringify(body).includes(KEY), false, "key never goes in the body");
});

test("paperboy errors are typed and say whether to retry", async () => {
  const limited = createPaperboyMailer({
    baseUrl: "http://paperboy.local",
    apiKey: KEY,
    from: "a@example.org.au",
    fetchImpl: fakeFetch(() => Response.json({ error: { message: "rate limited" } }, { status: 429, headers: { "retry-after": "12" } })).impl,
  });
  await assert.rejects(limited.send({ to: "x@example.org.au", subject: "s", text: "t" }), (error: unknown) => {
    assert.ok(error instanceof MailSendError);
    assert.equal(error.retryable, true);
    assert.equal(error.retryAfterSeconds, 12);
    assert.equal(error.message.includes(KEY), false);
    return true;
  });
  const invalid = createPaperboyMailer({ baseUrl: "http://paperboy.local", apiKey: KEY, from: "a@example.org.au", fetchImpl: fakeFetch(() => Response.json({ error: "bad from" }, { status: 422 })).impl });
  await assert.rejects(invalid.send({ to: "x@example.org.au", subject: "s", text: "t" }), (error: unknown) => error instanceof MailSendError && !error.retryable);
  const down = createPaperboyMailer({ baseUrl: "http://paperboy.local", apiKey: KEY, from: "a@example.org.au", fetchImpl: (async () => { throw new TypeError("fetch failed"); }) as unknown as typeof fetch });
  await assert.rejects(down.send({ to: "x@example.org.au", subject: "s", text: "t" }), (error: unknown) => error instanceof MailSendError && error.retryable);
});

test("unsafe tag and idempotency values are dropped, bad keys refused", async () => {
  const fake = fakeFetch(() => Response.json({ id: "id-1" }));
  const mailer = createPaperboyMailer({ baseUrl: "http://paperboy.local", apiKey: KEY, from: "a@example.org.au", fetchImpl: fake.impl });
  await mailer.send({ to: "x@example.org.au", subject: "s", text: "t", category: "has space", idempotencyKey: "bad key with spaces" });
  const headers = fake.calls[0]!.init.headers as Record<string, string>;
  assert.equal(headers["idempotency-key"], undefined);
  assert.equal(JSON.parse(String(fake.calls[0]!.init.body)).tags.length, 1);
  assert.throws(() => createPaperboyMailer({ baseUrl: "http://p", apiKey: "re_live_x", from: "a@b.au" }));
  assert.throws(() => createPaperboyMailer({ baseUrl: "http://p", apiKey: KEY, from: "a@b.au", region: "us-east-1" }));
});

test("mailer is chosen from the environment", () => {
  assert.equal(mailerFromEnv({ PAPERBOY_URL: "http://p", PAPERBOY_API_KEY: KEY, SMTP_URL: "smtp://m:1025" }).kind, "paperboy");
  assert.equal(mailerFromEnv({ SMTP_URL: "smtp://m:1025" }).kind, "smtp");
  assert.equal(mailerFromEnv({ PAPERBOY_URL: "http://p" }).kind, "sink");
});
