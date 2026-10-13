import { test } from "node:test";
import assert from "node:assert/strict";
import { assertM365Scopes, devKey, openIntegrationToken, sealIntegrationToken } from "./m365.js";

test("microsoft scopes stay read only and tokens round trip", () => {
  assert.doesNotThrow(() => assertM365Scopes(["Domain.Read.All", "User.ReadBasic.All", "IdentityRiskyUser.Read.All"]));
  assert.throws(() => assertM365Scopes(["Mail.Read"]), /Mailbox/);
  assert.throws(() => assertM365Scopes(["User.ReadWrite.All"]), /Write/);
  assert.throws(() => assertM365Scopes(["Directory.ReadWrite.All"]), /Write|allow list/);
  const sealed = sealIntegrationToken("token-not-real", ["Domain.Read.All"], devKey());
  assert.notEqual(sealed.ciphertext, "token-not-real");
  assert.equal(openIntegrationToken(sealed.ciphertext, devKey()), "token-not-real");
});
