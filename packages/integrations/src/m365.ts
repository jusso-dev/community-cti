import { decodeKey, decryptField, encryptField } from "@community-cti/db";

/** Read-only Microsoft Graph scopes. This repo does not register an Entra application. */
export const M365_SCOPES = ["Domain.Read.All", "User.ReadBasic.All"] as const;
export const M365_OPTIONAL_SCOPES = ["IdentityRiskyUser.Read.All"] as const;

const ALLOWED = new Set<string>([...M365_SCOPES, ...M365_OPTIONAL_SCOPES]);

export function assertM365Scopes(scopes: string[]): void {
  if (scopes.length === 0) throw new Error("Choose at least one Microsoft scope.");
  for (const scope of scopes) {
    if (scope.startsWith("Mail.") || /mail/i.test(scope)) throw new Error(`Mailbox scope is not allowed: ${scope}`);
    if (/write|send|export/i.test(scope)) throw new Error(`Write scope is not allowed: ${scope}`);
    if (!ALLOWED.has(scope)) throw new Error(`Scope is not on the allow list: ${scope}`);
  }
}

export function sealIntegrationToken(token: string, scopes: string[], key: Buffer): { ciphertext: string; scopes: string[] } {
  assertM365Scopes(scopes);
  return { ciphertext: encryptField(token, key), scopes: [...scopes] };
}

export function openIntegrationToken(ciphertext: string, key: Buffer): string {
  return decryptField(ciphertext, key);
}

export function devKey(): Buffer {
  return decodeKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
}
