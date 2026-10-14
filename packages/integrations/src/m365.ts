export const M365_READ_SCOPES = ["Domain.Read.All", "User.ReadBasic.All", "IdentityRiskyUser.Read.All"] as const;

export const M365_BLOCKLIST_SCOPE = "Policy.ReadWrite.TenantAllowBlockList";

const WRITE_PATTERN = /write|mail\.|files\.|sites\.|mailbox/i;

export function assertReadOnlyScopes(scopes: readonly string[]): void {
  for (const scope of scopes) {
    if (WRITE_PATTERN.test(scope)) throw new Error(`scope ${scope} is not read-only`);
  }
}

export function consentUrl(options: { clientId: string; redirectUri: string; remediation?: boolean }): string {
  const scopes = options.remediation ? [...M365_READ_SCOPES, M365_BLOCKLIST_SCOPE] : [...M365_READ_SCOPES];
  if (!options.remediation) assertReadOnlyScopes(scopes);
  const url = new URL("https://login.microsoftonline.com/organizations/v2.0/adminconsent");
  url.searchParams.set("client_id", options.clientId);
  url.searchParams.set("redirect_uri", options.redirectUri);
  url.searchParams.set("scope", scopes.join(" "));
  return url.toString();
}

export interface GraphUser {
  id: string;
  userPrincipalName: string;
}

export interface GraphClient {
  listUsers(): Promise<GraphUser[]>;
  listDomains(): Promise<string[]>;
}

export function graphClient(options: {
  fetchImpl: (url: string, init: { headers: Record<string, string> }) => Promise<{ json(): Promise<unknown> }>;
  token: string;
}): GraphClient {
  const headers = { authorization: `Bearer ${options.token}` };
  return {
    async listUsers() {
      const body = await (await options.fetchImpl("https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName", { headers })).json() as { value?: Array<{ id: string; userPrincipalName: string; displayName?: string }> };
      return (body.value ?? []).map((user) => ({ id: user.id, userPrincipalName: user.userPrincipalName }));
    },
    async listDomains() {
      const body = await (await options.fetchImpl("https://graph.microsoft.com/v1.0/domains?$select=id", { headers })).json() as { value?: Array<{ id: string }> };
      return (body.value ?? []).map((domain) => domain.id);
    },
  };
}
