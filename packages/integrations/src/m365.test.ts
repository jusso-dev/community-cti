import { test } from "node:test";
import assert from "node:assert/strict";
import { decryptField, encryptField } from "./crypto.js";
import { assertReadOnlyScopes, consentUrl, graphClient, M365_READ_SCOPES } from "./m365.js";

const key = Buffer.alloc(32, 1);

test("m365 requests only read scopes and stores ciphertext", async () => {
  assert.doesNotThrow(() => assertReadOnlyScopes(M365_READ_SCOPES));
  const url = new URL(consentUrl({ clientId: "client", redirectUri: "http://localhost/callback" }));
  const scope = url.searchParams.get("scope") ?? "";
  assert.equal(/write|mail\.|files\./i.test(scope), false);
  const remediation = new URL(consentUrl({ clientId: "client", redirectUri: "http://localhost/callback", remediation: true }));
  assert.match(remediation.searchParams.get("scope") ?? "", /ReadWrite/);
  const token = "secret-token-value";
  const stored = encryptField(token, key);
  assert.equal(stored.includes(token), false);
  assert.equal(decryptField(stored, key), token);
  const calls: string[] = [];
  const client = graphClient({
    token: "fixture",
    fetchImpl: async (requestUrl) => {
      calls.push(requestUrl);
      if (requestUrl.includes("/users")) {
        return { async json() { return { value: [{ id: "u1", userPrincipalName: "person@example.org.au", displayName: "Do not store" }] }; } };
      }
      return { async json() { return { value: [{ id: "example.org.au" }] }; } };
    },
  });
  const users = await client.listUsers();
  assert.deepEqual(users, [{ id: "u1", userPrincipalName: "person@example.org.au" }]);
  assert.equal(JSON.stringify(users).includes("Do not store"), false);
  assert.deepEqual(await client.listDomains(), ["example.org.au"]);
  assert.equal(calls.every((item) => item.startsWith("https://graph.microsoft.com/")), true);
});
