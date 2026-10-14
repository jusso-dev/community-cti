import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import { isDismissReason, type Finding } from "@community-cti/schema";
import { encryptField, executeAction } from "@community-cti/integrations";
import { decideShare, sanitiseWarning } from "@community-cti/intel";
import { hashToken, MemoryStore, transitionFinding, type Evidence, type StoredFinding } from "./store.js";

export interface RouteDef {
  id: string;
  method: string;
  path: string;
  isolation: "public" | "tenant";
}

export const ROUTES: RouteDef[] = [
  { id: "healthz", method: "GET", path: "/healthz", isolation: "public" },
  { id: "magic-link", method: "POST", path: "/auth/magic-link", isolation: "public" },
  { id: "callback", method: "GET", path: "/auth/callback", isolation: "public" },
  { id: "logout", method: "POST", path: "/auth/logout", isolation: "public" },
  { id: "create-org", method: "POST", path: "/orgs", isolation: "tenant" },
  { id: "get-org", method: "GET", path: "/orgs/:id", isolation: "tenant" },
  { id: "invite", method: "POST", path: "/orgs/:id/invites", isolation: "tenant" },
  { id: "consent", method: "POST", path: "/orgs/:id/consents", isolation: "tenant" },
  { id: "set-role", method: "POST", path: "/orgs/:id/members/:userId/role", isolation: "tenant" },
  { id: "list-domains", method: "GET", path: "/domains", isolation: "tenant" },
  { id: "create-domain", method: "POST", path: "/domains", isolation: "tenant" },
  { id: "verify-email", method: "GET", path: "/domains/verify-email", isolation: "public" },
  { id: "get-domain", method: "GET", path: "/domains/:id", isolation: "tenant" },
  { id: "check-domain", method: "POST", path: "/domains/:id/check", isolation: "tenant" },
  { id: "email-domain", method: "POST", path: "/domains/:id/email", isolation: "tenant" },
  { id: "list-findings", method: "GET", path: "/findings", isolation: "tenant" },
  { id: "get-finding", method: "GET", path: "/findings/:id", isolation: "tenant" },
  { id: "dismiss", method: "POST", path: "/findings/:id/dismiss", isolation: "tenant" },
  { id: "challenge", method: "POST", path: "/findings/:id/challenge", isolation: "tenant" },
  { id: "reopen", method: "POST", path: "/findings/:id/reopen", isolation: "tenant" },
  { id: "evidence", method: "GET", path: "/findings/:id/evidence/:evidenceId", isolation: "tenant" },
  { id: "create-action", method: "POST", path: "/actions", isolation: "tenant" },
  { id: "get-action", method: "GET", path: "/actions/:id", isolation: "tenant" },
  { id: "approve-action", method: "POST", path: "/actions/:id/approve", isolation: "tenant" },
  { id: "cancel-action", method: "POST", path: "/actions/:id/cancel", isolation: "tenant" },
  { id: "review", method: "GET", path: "/review", isolation: "tenant" },
  { id: "resolve-review", method: "POST", path: "/review/:id/resolve", isolation: "tenant" },
  { id: "list-exposures", method: "GET", path: "/credential-exposures", isolation: "tenant" },
  { id: "get-exposure", method: "GET", path: "/credential-exposures/:id", isolation: "tenant" },
  { id: "m365-connect", method: "POST", path: "/integrations/m365/connect", isolation: "tenant" },
  { id: "m365-disconnect", method: "POST", path: "/integrations/m365/disconnect", isolation: "tenant" },
  { id: "share-get", method: "GET", path: "/sharing/preferences", isolation: "tenant" },
  { id: "share-put", method: "PUT", path: "/sharing/preferences", isolation: "tenant" },
  { id: "share-preview", method: "POST", path: "/sharing/preview", isolation: "tenant" },
  { id: "share-approve", method: "POST", path: "/sharing/:id/approve", isolation: "tenant" },
  { id: "notif-get", method: "GET", path: "/notifications/preferences", isolation: "tenant" },
  { id: "notif-put", method: "PUT", path: "/notifications/preferences", isolation: "tenant" },
  { id: "cost", method: "GET", path: "/cost", isolation: "tenant" },
];

const SESSION_MS = 12 * 60 * 60 * 1000;
const FIELD_KEY = Buffer.alloc(32, 7);

export interface MailSink {
  sent: Array<{ to: string; text: string }>;
}

export interface AppDeps {
  store: MemoryStore;
  mailer: MailSink;
  now: () => Date;
  resolveTxt: (domain: string) => Promise<string[][]>;
}

function matchRoute(method: string, path: string): { route: RouteDef; params: Record<string, string> } | null {
  for (const route of ROUTES) {
    if (route.method !== method) continue;
    const routeParts = route.path.split("/").filter(Boolean);
    const pathParts = path.split("/").filter(Boolean);
    if (routeParts.length !== pathParts.length) continue;
    const params: Record<string, string> = {};
    let ok = true;
    for (let i = 0; i < routeParts.length; i++) {
      const part = routeParts[i]!;
      if (part.startsWith(":")) params[part.slice(1)] = decodeURIComponent(pathParts[i]!);
      else if (part !== pathParts[i]) ok = false;
    }
    if (ok) return { route, params };
  }
  return null;
}

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
}

function cookie(req: IncomingMessage): string | null {
  const header = req.headers.cookie ?? "";
  const match = header.match(/(?:^|;\s*)cti_session=([^;]+)/);
  return match?.[1] ? decodeURIComponent(match[1]) : null;
}

function presign(key: string, now: Date): string {
  const expires = new Date(now.getTime() + 5 * 60 * 1000).toISOString();
  return `http://localhost:9000/evidence/${encodeURIComponent(key)}?expires=${encodeURIComponent(expires)}`;
}

function presentEvidence(evidence: Evidence, now: Date) {
  const restricted = evidence.tlp === "TLP:AMBER" || evidence.tlp === "TLP:AMBER+STRICT" || evidence.tlp === "TLP:RED";
  if (restricted) {
    return {
      label: evidence.label,
      collectedAt: evidence.collectedAt,
      sourceId: evidence.sourceId,
      licence: evidence.licence,
      accessRestriction: evidence.tlp,
      redacted: true,
      note: "This source cannot be shown in full.",
    };
  }
  return {
    label: evidence.label,
    url: evidence.objectKey ? presign(evidence.objectKey, now) : evidence.url,
    collectedAt: evidence.collectedAt,
    sourceId: evidence.sourceId,
    licence: evidence.licence,
    accessRestriction: evidence.tlp,
    redacted: false,
  };
}

function presentFinding(finding: StoredFinding, now: Date) {
  if (!finding.provenance?.length || !finding.confidenceFactors?.length) {
    throw new Error("finding is missing provenance or confidence factors");
  }
  return {
    ...finding,
    evidence: finding.evidence.map((item) => presentEvidence(item, now)),
    links: {
      dismiss: `/findings/${finding.id}/dismiss`,
      challenge: `/findings/${finding.id}/challenge`,
      reopen: `/findings/${finding.id}/reopen`,
    },
  };
}

function httpError(status: number, message: string): Error {
  const error = new Error(message) as Error & { statusCode: number };
  error.statusCode = status;
  return error;
}

export function createApp(deps: AppDeps) {
  const { store, mailer, now } = deps;
  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const match = matchRoute(req.method ?? "GET", url.pathname);
      if (!match) return send(res, 404, { error: "not found" });
      const body = req.method === "GET" ? {} : await readBody(req);
      const token = cookie(req);
      const session = token ? store.sessions.get(hashToken(token)) : undefined;
      if (session && session.expiresAt <= now().getTime()) {
        store.sessions.delete(hashToken(token!));
      }
      const live = session && session.expiresAt > now().getTime() ? session : undefined;
      const user = live ? store.users.get(live.userId) : undefined;
      const requireUser = () => {
        if (!user || !live) throw httpError(401, "sign in required");
        return user;
      };
      const tenantFrom = (tenantId: string) => {
        const current = requireUser();
        const membership = store.membership(tenantId, current.id);
        if (!membership) throw httpError(404, "not found");
        return { user: current, membership, tenantId };
      };
      const activeTenant = () => {
        const current = requireUser();
        if (!live?.tenantId) throw httpError(404, "not found");
        return tenantFrom(live.tenantId);
      };

      if (match.route.id === "healthz") return send(res, 200, { ok: true });

      if (match.route.id === "magic-link") {
        const email = String(body.email ?? "").toLowerCase();
        const raw = randomBytes(16).toString("hex");
        store.magic.set(hashToken(raw), { email, expiresAt: now().getTime() + SESSION_MS });
        mailer.sent.push({ to: email, text: `Sign in: /auth/callback?token=${raw}` });
        store.writeAudit({ tenantId: null, actorId: null, action: "auth.magic_link", targetType: "user", targetId: email });
        return send(res, 202, { ok: true });
      }

      if (match.route.id === "callback") {
        const raw = url.searchParams.get("token") ?? "";
        const link = store.magic.get(hashToken(raw));
        if (!link || link.expiresAt <= now().getTime()) return send(res, 400, { error: "link expired" });
        store.magic.delete(hashToken(raw));
        let userId = [...store.users.values()].find((item) => item.email === link.email)?.id;
        if (!userId) {
          userId = randomUUID();
          store.users.set(userId, { id: userId, email: link.email });
        }
        const sessionToken = randomBytes(16).toString("hex");
        const expiresAt = now().getTime() + SESSION_MS;
        store.sessions.set(hashToken(sessionToken), { userId, expiresAt, tenantId: null });
        store.writeAudit({ tenantId: null, actorId: userId, action: "auth.session", targetType: "user", targetId: userId });
        return send(res, 200, { ok: true, expiresInHours: 12 }, {
          "set-cookie": `cti_session=${encodeURIComponent(sessionToken)}; HttpOnly; SameSite=Lax; Max-Age=43200`,
        });
      }

      if (match.route.id === "logout") {
        if (token) store.sessions.delete(hashToken(token));
        return send(res, 200, { ok: true });
      }

      if (match.route.id === "create-org") {
        const current = requireUser();
        const id = randomUUID();
        const name = String(body.name ?? "");
        const orgType = String(body.orgType ?? "other");
        store.tenants.set(id, { id, name, orgType });
        store.memberships.push({ tenantId: id, userId: current.id, role: "owner" });
        live!.tenantId = id;
        store.writeAudit({ tenantId: id, actorId: current.id, action: "org.created", targetType: "tenant", targetId: id });
        return send(res, 201, { id, name, role: "owner" });
      }

      if (match.route.id === "get-org") {
        const ctx = tenantFrom(match.params.id!);
        const tenant = store.tenants.get(ctx.tenantId);
        if (!tenant) return send(res, 404, { error: "not found" });
        return send(res, 200, tenant);
      }

      if (match.route.id === "invite") {
        const ctx = tenantFrom(match.params.id!);
        if (ctx.membership.role !== "owner") return send(res, 403, { error: "only an owner can invite people" });
        store.invites.push({ tenantId: ctx.tenantId, email: String(body.email ?? ""), role: String(body.role ?? "member") });
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "org.invite", targetType: "invite", targetId: String(body.email ?? "") });
        return send(res, 201, { ok: true });
      }

      if (match.route.id === "consent") {
        const ctx = tenantFrom(match.params.id!);
        store.consents.push({
          tenantId: ctx.tenantId,
          scope: String(body.scope ?? ""),
          grantorName: String(body.grantorName ?? ""),
          grantorRole: String(body.grantorRole ?? ""),
          ip: req.socket.remoteAddress ?? "",
          revokedAt: null,
        });
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "consent.recorded", targetType: "consent", targetId: String(body.scope ?? "") });
        return send(res, 201, { ok: true });
      }

      if (match.route.id === "set-role") {
        const ctx = tenantFrom(match.params.id!);
        if (ctx.membership.role !== "owner") return send(res, 403, { error: "only an owner can change roles" });
        const member = store.membership(ctx.tenantId, match.params.userId!);
        if (!member) return send(res, 404, { error: "not found" });
        member.role = String(body.role ?? member.role);
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "org.role", targetType: "membership", targetId: member.userId });
        return send(res, 200, { ok: true, role: member.role });
      }

      if (match.route.id === "list-domains") {
        const ctx = activeTenant();
        return send(res, 200, store.domains.filter((item) => item.tenantId === ctx.tenantId));
      }

      if (match.route.id === "create-domain") {
        const ctx = activeTenant();
        if (!store.hasConsent(ctx.tenantId)) return send(res, 409, { error: "Record consent before monitoring starts." });
        const id = randomUUID();
        const token = randomBytes(8).toString("hex");
        const domain = String(body.domain ?? "").toLowerCase();
        store.domains.push({ id, tenantId: ctx.tenantId, domain, status: "pending", token, verifiedAt: null, emailTokenHash: null });
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "domain.created", targetType: "domain", targetId: id });
        return send(res, 201, { id, domain, txt: `cti-verify=${token}` });
      }

      if (match.route.id === "get-domain") {
        const ctx = activeTenant();
        const domain = store.domains.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        if (!domain) return send(res, 404, { error: "not found" });
        return send(res, 200, domain);
      }

      if (match.route.id === "check-domain") {
        const ctx = activeTenant();
        const domain = store.domains.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        if (!domain) return send(res, 404, { error: "not found" });
        const records = await deps.resolveTxt(domain.domain);
        const flat = records.map((parts) => parts.join(""));
        if (!flat.some((value) => value.includes(`cti-verify=${domain.token}`))) return send(res, 409, { error: "TXT record not found yet" });
        domain.status = "verified";
        domain.verifiedAt = now().toISOString();
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "domain.verified", targetType: "domain", targetId: domain.id });
        return send(res, 200, { status: domain.status, verifiedAt: domain.verifiedAt });
      }

      if (match.route.id === "email-domain") {
        const ctx = activeTenant();
        const domain = store.domains.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        if (!domain) return send(res, 404, { error: "not found" });
        const email = String(body.email ?? "").toLowerCase();
        const [local, host] = email.split("@");
        if (host !== domain.domain || !["admin", "postmaster", "webmaster"].includes(local ?? "")) {
          return send(res, 400, { error: "use admin, postmaster or webmaster at that domain" });
        }
        const raw = randomBytes(8).toString("hex");
        domain.emailTokenHash = hashToken(raw);
        domain.status = "email_pending";
        mailer.sent.push({ to: email, text: `/domains/verify-email?token=${raw}` });
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "domain.email_sent", targetType: "domain", targetId: domain.id });
        return send(res, 202, { ok: true });
      }

      if (match.route.id === "verify-email") {
        const raw = url.searchParams.get("token") ?? "";
        const domain = store.domains.find((item) => item.emailTokenHash === hashToken(raw));
        if (!domain) return send(res, 404, { error: "not found" });
        domain.status = "verified";
        domain.verifiedAt = now().toISOString();
        store.writeAudit({ tenantId: domain.tenantId, actorId: null, action: "domain.verified", targetType: "domain", targetId: domain.id });
        return send(res, 200, { status: "verified" });
      }

      if (match.route.id === "list-findings") {
        const ctx = activeTenant();
        const rows = store.findings.filter((item) => item.tenantId === ctx.tenantId);
        return send(res, 200, rows.map((item) => presentFinding(item, now())));
      }

      if (match.route.id === "get-finding") {
        const ctx = activeTenant();
        const finding = store.findings.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        if (!finding) return send(res, 404, { error: "not found" });
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "finding.viewed", targetType: "finding", targetId: finding.id });
        return send(res, 200, presentFinding(finding, now()));
      }

      if (match.route.id === "dismiss" || match.route.id === "challenge" || match.route.id === "reopen") {
        const ctx = activeTenant();
        const finding = store.findings.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        if (!finding) return send(res, 404, { error: "not found" });
        const next: Finding["status"] = match.route.id === "dismiss" ? "dismissed" : match.route.id === "challenge" ? "challenged" : "open";
        if (match.route.id === "dismiss") {
          const reason = String(body.reason ?? "");
          if (!isDismissReason(reason)) return send(res, 400, { error: "choose a reason" });
          if (reason === "other" && !String(body.comment ?? "").trim()) return send(res, 400, { error: "add a short note" });
          transitionFinding(finding, "dismissed");
          store.feedback.push({ tenantId: ctx.tenantId, findingId: finding.id, action: "dismiss", reason });
          if (reason === "legitimate_domain" && body.domain) store.allow.push({ tenantId: ctx.tenantId, domain: String(body.domain).toLowerCase() });
          if (reason === "not_ours") store.opinions.push({ tenantId: ctx.tenantId, findingId: finding.id, opinion: "strongly-disagree" });
        } else if (match.route.id === "challenge") {
          transitionFinding(finding, "challenged");
          store.feedback.push({ tenantId: ctx.tenantId, findingId: finding.id, action: "challenge", reason: String(body.comment ?? "") });
        } else {
          transitionFinding(finding, "open");
          store.feedback.push({ tenantId: ctx.tenantId, findingId: finding.id, action: "reopen" });
        }
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: `finding.${next === "open" ? "reopen" : next}`, targetType: "finding", targetId: finding.id });
        return send(res, 200, presentFinding(finding, now()));
      }

      if (match.route.id === "evidence") {
        const ctx = activeTenant();
        const finding = store.findings.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        const evidence = finding?.evidence.find((item) => item.id === match.params.evidenceId);
        if (!finding || !evidence) return send(res, 404, { error: "not found" });
        return send(res, 200, presentEvidence(evidence, now()));
      }

      if (match.route.id === "create-action") {
        const ctx = activeTenant();
        const action = {
          id: randomUUID(),
          tenantId: ctx.tenantId,
          findingId: body.findingId ? String(body.findingId) : null,
          kind: String(body.kind ?? "manual_steps"),
          status: "proposed" as const,
          preview: (body.preview as Record<string, unknown>) ?? {},
          approvedBy: null,
          approvedAt: null,
        };
        store.actions.push(action);
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "action.proposed", targetType: "action", targetId: action.id });
        return send(res, 201, action);
      }

      if (match.route.id === "get-action") {
        const ctx = activeTenant();
        const action = store.actions.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        if (!action) return send(res, 404, { error: "not found" });
        return send(res, 200, action);
      }

      if (match.route.id === "approve-action") {
        const ctx = activeTenant();
        const action = store.actions.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        if (!action) return send(res, 404, { error: "not found" });
        if (ctx.membership.role !== "owner") return send(res, 403, { error: "only an owner can approve" });
        if (action.status !== "proposed") return send(res, 409, { error: "invalid transition" });
        action.status = "approved";
        action.approvedBy = ctx.user.id;
        action.approvedAt = now().toISOString();
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "action.approved", targetType: "action", targetId: action.id });
        const executed = executeAction({
          id: action.id,
          tenantId: action.tenantId,
          status: "approved",
          preview: action.preview,
          approvedBy: action.approvedBy,
          approvedAt: action.approvedAt,
        }, () => undefined);
        action.status = "executed";
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "action.executed", targetType: "action", targetId: action.id });
        return send(res, 200, { preview: action.preview, applied: executed.applied, status: action.status });
      }

      if (match.route.id === "cancel-action") {
        const ctx = activeTenant();
        const action = store.actions.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        if (!action) return send(res, 404, { error: "not found" });
        if (action.status !== "proposed" && action.status !== "approved") return send(res, 409, { error: "invalid transition" });
        action.status = "cancelled";
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "action.cancelled", targetType: "action", targetId: action.id });
        return send(res, 200, action);
      }

      if (match.route.id === "review") {
        const ctx = activeTenant();
        if (ctx.membership.role !== "analyst" && ctx.membership.role !== "owner") return send(res, 403, { error: "analyst role required" });
        const rows = store.findings.filter((item) => item.tenantId === ctx.tenantId && (item.status === "challenged" || Math.abs((item.confidenceFactors?.[0]?.points ?? item.confidence) - item.confidence) > 30));
        return send(res, 200, rows.map((item) => presentFinding(item, now())));
      }

      if (match.route.id === "resolve-review") {
        const ctx = activeTenant();
        if (ctx.membership.role !== "analyst" && ctx.membership.role !== "owner") return send(res, 403, { error: "analyst role required" });
        const finding = store.findings.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        if (!finding) return send(res, 404, { error: "not found" });
        const reason = String(body.reason ?? "").trim();
        if (!reason) return send(res, 400, { error: "a reason is required" });
        const outcome = String(body.outcome ?? "");
        if (outcome === "withdraw") transitionFinding(finding, "dismissed");
        if (outcome === "adjust") finding.confidence = Number(body.confidence ?? finding.confidence);
        store.opinions.push({ tenantId: ctx.tenantId, findingId: finding.id, opinion: outcome === "uphold" ? "agree" : "disagree" });
        store.feedback.push({ tenantId: ctx.tenantId, findingId: finding.id, action: "resolve", reason });
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "review.resolved", targetType: "finding", targetId: finding.id });
        return send(res, 200, { ok: true, reason });
      }

      if (match.route.id === "list-exposures" || match.route.id === "get-exposure") {
        const ctx = activeTenant();
        if (ctx.membership.role !== "owner" && ctx.membership.role !== "credential_viewer") return send(res, 403, { error: "not allowed" });
        if (match.route.id === "list-exposures") {
          return send(res, 200, store.exposures.filter((item) => item.tenantId === ctx.tenantId).map((item) => ({ id: item.id, breachName: item.breachName })));
        }
        const row = store.exposures.find((item) => item.id === match.params.id && item.tenantId === ctx.tenantId);
        if (!row) return send(res, 404, { error: "not found" });
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "credential_exposure.view", targetType: "credential_exposure", targetId: row.id });
        return send(res, 200, { id: row.id, breachName: row.breachName, emailStoredAs: "ciphertext" });
      }

      if (match.route.id === "m365-connect") {
        const ctx = activeTenant();
        const ciphertext = encryptField(String(body.accessToken ?? "pending"), FIELD_KEY);
        store.tokens = store.tokens.filter((item) => !(item.tenantId === ctx.tenantId && item.provider === "m365"));
        store.tokens.push({ tenantId: ctx.tenantId, provider: "m365", ciphertext });
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "m365.connected", targetType: "integration", targetId: "m365" });
        return send(res, 201, { connected: true, ciphertextStored: ciphertext !== body.accessToken });
      }

      if (match.route.id === "m365-disconnect") {
        const ctx = activeTenant();
        store.tokens = store.tokens.filter((item) => !(item.tenantId === ctx.tenantId && item.provider === "m365"));
        store.cachedUsers = store.cachedUsers.filter((item) => item.tenantId !== ctx.tenantId);
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "m365.disconnected", targetType: "integration", targetId: "m365" });
        return send(res, 200, { connected: false });
      }

      if (match.route.id === "share-get") {
        const ctx = activeTenant();
        const rows = store.sharePrefs.filter((item) => item.tenantId === ctx.tenantId);
        return send(res, 200, rows.length ? rows : [{ category: "phishing", enabled: false }]);
      }

      if (match.route.id === "share-put") {
        const ctx = activeTenant();
        if (ctx.membership.role !== "owner") return send(res, 403, { error: "only an owner can change sharing" });
        const category = String(body.category ?? "phishing");
        const enabled = Boolean(body.enabled);
        store.sharePrefs = store.sharePrefs.filter((item) => !(item.tenantId === ctx.tenantId && item.category === category));
        store.sharePrefs.push({ tenantId: ctx.tenantId, category, enabled });
        return send(res, 200, { category, enabled });
      }

      if (match.route.id === "share-preview") {
        const ctx = activeTenant();
        const tenant = store.tenants.get(ctx.tenantId);
        const cleaned = sanitiseWarning({
          text: String(body.text ?? ""),
          tenantName: tenant?.name ?? "",
          people: Array.isArray(body.people) ? body.people.map(String) : [],
          internalHosts: Array.isArray(body.internalHosts) ? body.internalHosts.map(String) : [],
        });
        const id = randomUUID();
        store.shares.push({ id, tenantId: ctx.tenantId, cultural: Boolean(body.cultural), approvedBy: null, sanitised: cleaned.text });
        return send(res, 200, { id, text: cleaned.text });
      }

      if (match.route.id === "share-approve") {
        const ctx = activeTenant();
        const item = store.shares.find((share) => share.id === match.params.id && share.tenantId === ctx.tenantId);
        if (!item) return send(res, 404, { error: "not found" });
        const category = String(body.category ?? "phishing");
        const enabled = store.sharePrefs.some((pref) => pref.tenantId === ctx.tenantId && pref.category === category && pref.enabled);
        const decision = decideShare({ categoryEnabled: enabled, itemApproved: true, approverId: ctx.user.id, cultural: item.cultural });
        if (!decision.ok) return send(res, 409, { error: decision.reason });
        item.approvedBy = ctx.user.id;
        store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "share.approved", targetType: "shared_item", targetId: item.id });
        return send(res, 200, { ok: true, approverId: ctx.user.id });
      }

      if (match.route.id === "notif-get" || match.route.id === "notif-put") {
        const ctx = activeTenant();
        if (match.route.id === "notif-put") {
          const mode = String(body.mode ?? "digest") as "immediate" | "digest" | "off";
          store.notif = store.notif.filter((item) => !(item.tenantId === ctx.tenantId && item.userId === ctx.user.id));
          store.notif.push({ tenantId: ctx.tenantId, userId: ctx.user.id, mode });
        }
        const pref = store.notif.find((item) => item.tenantId === ctx.tenantId && item.userId === ctx.user.id);
        return send(res, 200, { mode: pref?.mode ?? "digest" });
      }

      if (match.route.id === "cost") {
        const ctx = activeTenant();
        const aud = store.costs.filter((item) => item.tenantId === ctx.tenantId).reduce((sum, item) => sum + item.aud, 0);
        return send(res, 200, { tenantId: ctx.tenantId, aud, hypotheses: true });
      }

      return send(res, 404, { error: "not found" });
    } catch (error) {
      const status = (error as { statusCode?: number }).statusCode ?? 500;
      send(res, status, { error: error instanceof Error ? error.message : "error" });
    }
  });
}

export function defaultDeps(): AppDeps {
  return {
    store: new MemoryStore(),
    mailer: { sent: [] },
    now: () => new Date(),
    resolveTxt: async () => [],
  };
}
