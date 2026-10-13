export interface RouteDef {
  id: string;
  method: string;
  pattern: string;
}

export const ROUTES: RouteDef[] = [
  { id: "healthz", method: "GET", pattern: "/healthz" },
  { id: "magic-link", method: "POST", pattern: "/auth/magic-link" },
  { id: "callback", method: "GET", pattern: "/auth/callback" },
  { id: "create-org", method: "POST", pattern: "/orgs" },
  { id: "invite", method: "POST", pattern: "/orgs/:id/invites" },
  { id: "consent", method: "POST", pattern: "/orgs/:id/consents" },
  { id: "change-role", method: "POST", pattern: "/orgs/:id/members/:userId/role" },
  { id: "add-domain", method: "POST", pattern: "/domains" },
  { id: "check-domain", method: "POST", pattern: "/domains/:id/check" },
  { id: "email-domain", method: "POST", pattern: "/domains/:id/email" },
  { id: "verify-email", method: "GET", pattern: "/domains/verify-email" },
  { id: "list-findings", method: "GET", pattern: "/findings" },
  { id: "get-finding", method: "GET", pattern: "/findings/:id" },
  { id: "evidence", method: "GET", pattern: "/findings/:id/evidence/:evidenceId" },
  { id: "dismiss", method: "POST", pattern: "/findings/:id/dismiss" },
  { id: "challenge", method: "POST", pattern: "/findings/:id/challenge" },
  { id: "reopen", method: "POST", pattern: "/findings/:id/reopen" },
  { id: "notify", method: "POST", pattern: "/findings/:id/notify" },
  { id: "credentials", method: "GET", pattern: "/credentials" },
  { id: "credentials-sync", method: "POST", pattern: "/credentials/sync" },
  { id: "exposures", method: "POST", pattern: "/exposures/correlate" },
  { id: "create-action", method: "POST", pattern: "/actions" },
  { id: "approve-action", method: "POST", pattern: "/actions/:id/approve" },
  { id: "execute-action", method: "POST", pattern: "/actions/:id/execute" },
  { id: "review", method: "GET", pattern: "/review" },
  { id: "review-weights", method: "POST", pattern: "/review/weights" },
  { id: "m365-scopes", method: "GET", pattern: "/integrations/m365/scopes" },
  { id: "m365-connect", method: "POST", pattern: "/integrations/m365/connect" },
  { id: "share", method: "POST", pattern: "/share" },
  { id: "cost", method: "POST", pattern: "/cost" },
  { id: "investigate", method: "POST", pattern: "/agents/investigate" },
];

export function matchRoute(method: string, pathname: string): { id: string; params: Record<string, string> } | null {
  for (const route of ROUTES) {
    if (route.method !== method) continue;
    const expected = route.pattern.split("/").filter(Boolean);
    const actual = pathname.split("/").filter(Boolean);
    if (expected.length !== actual.length) continue;
    const params: Record<string, string> = {};
    let ok = true;
    for (let i = 0; i < expected.length; i += 1) {
      const token = expected[i] ?? "";
      const value = actual[i] ?? "";
      if (token.startsWith(":")) params[token.slice(1)] = decodeURIComponent(value);
      else if (token !== value) ok = false;
    }
    if (ok) return { id: route.id, params };
  }
  return null;
}
