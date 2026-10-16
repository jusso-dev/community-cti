import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import { isDismissReason, type Finding } from "@community-cti/schema";
import { encryptField, executeAction } from "@community-cti/integrations";
import { decideShare, sanitiseWarning } from "@community-cti/intel";
import { SinkMailer, type Mailer } from "@community-cti/notify";
import { rankAdvisories, summariseRansomware, watchedTags } from "./advisories.js";
import { assertTransition, hashToken, MemoryStore, type DomainRecord, type Evidence, type NotifyMode, type Repo, type StoredFinding } from "./store.js";

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
  { id: "me", method: "GET", path: "/me", isolation: "tenant" },
  { id: "create-org", method: "POST", path: "/orgs", isolation: "tenant" },
  { id: "get-org", method: "GET", path: "/orgs/:id", isolation: "tenant" },
  { id: "invite", method: "POST", path: "/orgs/:id/invites", isolation: "tenant" },
  { id: "consent", method: "POST", path: "/orgs/:id/consents", isolation: "tenant" },
  { id: "revoke-consent", method: "POST", path: "/orgs/:id/consents/revoke", isolation: "tenant" },
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
  { id: "advisories", method: "GET", path: "/advisories", isolation: "tenant" },
  { id: "au-ransomware", method: "GET", path: "/ransomware/au", isolation: "tenant" },
];

const SESSION_MS = 12 * 60 * 60 * 1000;
const MAGIC_LINK_MS = 30 * 60 * 1000;
const MAX_BODY_BYTES = 64 * 1024;
const ORG_TYPES = ["ACCO", "Land Council", "AMS", "Indigenous corporation", "other"];
const ROLES = ["owner", "member", "credential_viewer", "analyst"];
const NOTIFY_MODES: NotifyMode[] = ["immediate", "digest", "off"];
const EMAIL = /^[^\s@]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,}$/;
const DOMAIN = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface AppConfig {
  /** Links in emails point here, for example https://cti.example.org.au */
  portalBaseUrl: string;
  /** 32-byte key for field encryption of integration tokens. */
  fieldKey: Buffer;
  /** Adds Secure to the session cookie. Set when the portal is served over HTTPS. */
  secureCookies: boolean;
  /** Base for short-lived evidence links. Null when no evidence store is configured. */
  evidenceBaseUrl: string | null;
  /** Magic-link requests allowed per email address per 15 minutes. */
  magicLinkLimit: number;
}

export interface AppDeps<S extends Repo = Repo> {
  store: S;
  mailer: Mailer;
  now: () => Date;
  resolveTxt: (domain: string) => Promise<string[][]>;
  config?: Partial<AppConfig>;
}

const DEFAULT_CONFIG: AppConfig = {
  portalBaseUrl: "http://localhost:3000",
  fieldKey: Buffer.alloc(32, 7),
  secureCookies: false,
  evidenceBaseUrl: "http://localhost:9000/evidence",
  magicLinkLimit: 5,
};

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
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY_BYTES) throw httpError(413, "request is too large");
    chunks.push(chunk as Buffer);
  }
  if (chunks.length === 0) return {};
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    return parsed as Record<string, unknown>;
  } catch {
    throw httpError(400, "send a JSON object");
  }
}

function cookie(req: IncomingMessage): string | null {
  const header = req.headers.cookie ?? "";
  const match = header.match(/(?:^|;\s*)cti_session=([^;]+)/);
  return match?.[1] ? decodeURIComponent(match[1]) : null;
}

function presentEvidence(evidence: Evidence, now: Date, evidenceBaseUrl: string | null) {
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
  const expires = new Date(now.getTime() + 5 * 60 * 1000).toISOString();
  const stored = evidence.objectKey && evidenceBaseUrl
    ? `${evidenceBaseUrl}/${encodeURIComponent(evidence.objectKey)}?expires=${encodeURIComponent(expires)}`
    : null;
  return {
    label: evidence.label,
    url: evidence.url ?? stored ?? undefined,
    collectedAt: evidence.collectedAt,
    sourceId: evidence.sourceId,
    licence: evidence.licence,
    accessRestriction: evidence.tlp,
    redacted: false,
  };
}

function presentFinding(finding: StoredFinding, now: Date, evidenceBaseUrl: string | null) {
  if (!finding.provenance?.length || !finding.confidenceFactors?.length) {
    throw new Error("finding is missing provenance or confidence factors");
  }
  return {
    ...finding,
    evidence: finding.evidence.map((item) => presentEvidence(item, now, evidenceBaseUrl)),
    links: {
      dismiss: `/findings/${finding.id}/dismiss`,
      challenge: `/findings/${finding.id}/challenge`,
      reopen: `/findings/${finding.id}/reopen`,
    },
  };
}

function publicDomain(row: DomainRecord) {
  return { id: row.id, domain: row.domain, status: row.status, token: row.token, verifiedAt: row.verifiedAt };
}

function httpError(status: number, message: string): Error {
  const error = new Error(message) as Error & { statusCode: number };
  error.statusCode = status;
  return error;
}

function sessionCookie(value: string, maxAge: number, secure: boolean): string {
  return `cti_session=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}

export function createApp<S extends Repo>(deps: AppDeps<S>) {
  const { store, mailer, now } = deps;
  const config: AppConfig = { ...DEFAULT_CONFIG, ...deps.config };
  const magicRequests = new Map<string, number[]>();

  const allowMagicLink = (email: string): boolean => {
    const cutoff = now().getTime() - 15 * 60 * 1000;
    const recent = (magicRequests.get(email) ?? []).filter((at) => at > cutoff);
    if (recent.length >= config.magicLinkLimit) return false;
    recent.push(now().getTime());
    magicRequests.set(email, recent);
    if (magicRequests.size > 10_000) magicRequests.clear();
    return true;
  };

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const match = matchRoute(req.method ?? "GET", url.pathname);
      if (!match) return send(res, 404, { error: "not found" });
      for (const [name, value] of Object.entries(match.params)) {
        if ((name === "id" || name === "userId") && !UUID.test(value)) return send(res, 404, { error: "not found" });
      }
      const body = req.method === "GET" ? {} : await readBody(req);
      const token = cookie(req);
      const tokenHash = token ? hashToken(token) : null;
      const session = tokenHash ? await store.getSession(tokenHash) : null;
      if (session && tokenHash && session.expiresAt <= now().getTime()) await store.deleteSession(tokenHash);
      const live = session && session.expiresAt > now().getTime() ? session : null;
      const user = live ? await store.getUser(live.userId) : null;
      const requireUser = () => {
        if (!user || !live) throw httpError(401, "sign in required");
        return user;
      };
      const tenantFrom = async (tenantId: string) => {
        const current = requireUser();
        if (!UUID.test(tenantId)) throw httpError(404, "not found");
        const membership = await store.membership(tenantId, current.id);
        if (!membership) throw httpError(404, "not found");
        return { user: current, membership, tenantId };
      };
      const activeTenant = async () => {
        requireUser();
        if (!live?.tenantId) throw httpError(404, "not found");
        return tenantFrom(live.tenantId);
      };
      const loadFinding = async (tenantId: string, id: string) => {
        const finding = await store.getFinding(tenantId, id);
        if (!finding) throw httpError(404, "not found");
        return finding;
      };

      if (match.route.id === "healthz") return send(res, 200, { ok: true });

      if (match.route.id === "magic-link") {
        const email = String(body.email ?? "").trim().toLowerCase();
        if (!EMAIL.test(email)) return send(res, 400, { error: "enter a valid email address" });
        if (!allowMagicLink(email)) return send(res, 429, { error: "too many sign-in emails, try again in 15 minutes" });
        const raw = randomBytes(32).toString("hex");
        await store.createMagicLink(email, hashToken(raw), now().getTime() + MAGIC_LINK_MS);
        await mailer.send({
          to: email,
          subject: "Your Community CTI sign-in link",
          category: "sign_in",
          text: [
            "Use this link to sign in. It works once and stops working in 30 minutes.",
            "",
            `Sign in: ${config.portalBaseUrl}/auth/callback?token=${raw}`,
            "",
            "If you did not ask for this, you can ignore this email.",
          ].join("\n"),
        });
        await store.writeAudit({ tenantId: null, actorId: null, action: "auth.magic_link", targetType: "user", targetId: email });
        return send(res, 202, { ok: true });
      }

      if (match.route.id === "callback") {
        const raw = url.searchParams.get("token") ?? "";
        const email = raw ? await store.consumeMagicLink(hashToken(raw), now().getTime()) : null;
        if (!email) return send(res, 400, { error: "link expired" });
        const account = await store.findOrCreateUser(email);
        await store.acceptInvites(account.id, email);
        const tenants = await store.userTenants(account.id);
        const sessionToken = randomBytes(32).toString("hex");
        await store.createSession(hashToken(sessionToken), {
          userId: account.id,
          expiresAt: now().getTime() + SESSION_MS,
          tenantId: tenants[0]?.tenantId ?? null,
        });
        await store.writeAudit({ tenantId: null, actorId: account.id, action: "auth.session", targetType: "user", targetId: account.id });
        return send(res, 200, { ok: true, expiresInHours: 12 }, {
          "set-cookie": sessionCookie(sessionToken, SESSION_MS / 1000, config.secureCookies),
        });
      }

      if (match.route.id === "logout") {
        if (tokenHash) await store.deleteSession(tokenHash);
        return send(res, 200, { ok: true }, { "set-cookie": sessionCookie("", 0, config.secureCookies) });
      }

      if (match.route.id === "me") {
        const current = requireUser();
        const tenantId = live!.tenantId;
        const membership = tenantId ? await store.membership(tenantId, current.id) : null;
        const org = tenantId && membership ? await store.getTenant(tenantId) : null;
        return send(res, 200, {
          user: { id: current.id, email: current.email },
          tenantId: org ? tenantId : null,
          role: membership?.role ?? null,
          org,
          consented: org ? await store.hasConsent(org.id) : false,
        });
      }

      if (match.route.id === "create-org") {
        const current = requireUser();
        const id = randomUUID();
        const name = String(body.name ?? "").trim();
        const orgType = String(body.orgType ?? "other");
        if (!name || name.length > 200) return send(res, 400, { error: "enter your organisation's name" });
        if (!ORG_TYPES.includes(orgType)) return send(res, 400, { error: "choose an organisation type" });
        await store.createTenant({ id, name, orgType }, current.id);
        await store.setSessionTenant(tokenHash!, id);
        await store.writeAudit({ tenantId: id, actorId: current.id, action: "org.created", targetType: "tenant", targetId: id });
        return send(res, 201, { id, name, role: "owner" });
      }

      if (match.route.id === "get-org") {
        const ctx = await tenantFrom(match.params.id!);
        const tenant = await store.getTenant(ctx.tenantId);
        if (!tenant) return send(res, 404, { error: "not found" });
        return send(res, 200, tenant);
      }

      if (match.route.id === "invite") {
        const ctx = await tenantFrom(match.params.id!);
        if (ctx.membership.role !== "owner") return send(res, 403, { error: "only an owner can invite people" });
        const email = String(body.email ?? "").trim().toLowerCase();
        const role = String(body.role ?? "member");
        if (!EMAIL.test(email)) return send(res, 400, { error: "enter a valid email address" });
        if (!ROLES.includes(role)) return send(res, 400, { error: "choose a role" });
        await store.addInvite(ctx.tenantId, { email, role, invitedBy: ctx.user.id });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "org.invite", targetType: "invite", targetId: email });
        return send(res, 201, { ok: true });
      }

      if (match.route.id === "consent") {
        const ctx = await tenantFrom(match.params.id!);
        const scope = String(body.scope ?? "");
        const grantorName = String(body.grantorName ?? "").trim();
        const grantorRole = String(body.grantorRole ?? "").trim();
        if (!scope || !grantorName || !grantorRole) return send(res, 400, { error: "add the name and role of the person giving consent" });
        await store.addConsent(ctx.tenantId, { scope, grantorName, grantorRole, ip: req.socket.remoteAddress ?? "" });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "consent.recorded", targetType: "consent", targetId: scope });
        return send(res, 201, { ok: true });
      }

      if (match.route.id === "revoke-consent") {
        const ctx = await tenantFrom(match.params.id!);
        if (ctx.membership.role !== "owner") return send(res, 403, { error: "only an owner can stop monitoring" });
        await store.revokeConsent(ctx.tenantId, now().toISOString());
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "consent.revoked", targetType: "consent", targetId: "domain_monitoring" });
        return send(res, 200, { ok: true });
      }

      if (match.route.id === "set-role") {
        const ctx = await tenantFrom(match.params.id!);
        if (ctx.membership.role !== "owner") return send(res, 403, { error: "only an owner can change roles" });
        const role = String(body.role ?? "");
        if (!ROLES.includes(role)) return send(res, 400, { error: "choose a role" });
        if (!(await store.setRole(ctx.tenantId, match.params.userId!, role))) return send(res, 404, { error: "not found" });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "org.role", targetType: "membership", targetId: match.params.userId! });
        return send(res, 200, { ok: true, role });
      }

      if (match.route.id === "list-domains") {
        const ctx = await activeTenant();
        return send(res, 200, (await store.listDomains(ctx.tenantId)).map(publicDomain));
      }

      if (match.route.id === "create-domain") {
        const ctx = await activeTenant();
        if (!(await store.hasConsent(ctx.tenantId))) return send(res, 409, { error: "Record consent before monitoring starts." });
        const domain = String(body.domain ?? "").trim().toLowerCase().replace(/\.$/, "");
        if (!DOMAIN.test(domain)) return send(res, 400, { error: "enter a domain like example.org.au" });
        if ((await store.listDomains(ctx.tenantId)).some((item) => item.domain === domain)) {
          return send(res, 409, { error: "you have already added that domain" });
        }
        const id = randomUUID();
        const verifyToken = randomBytes(16).toString("hex");
        await store.addDomain({ id, tenantId: ctx.tenantId, domain, status: "pending", token: verifyToken, verifiedAt: null, emailTokenHash: null });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "domain.created", targetType: "domain", targetId: id });
        return send(res, 201, { id, domain, txt: `cti-verify=${verifyToken}` });
      }

      if (match.route.id === "get-domain") {
        const ctx = await activeTenant();
        const domain = await store.getDomain(ctx.tenantId, match.params.id!);
        if (!domain) return send(res, 404, { error: "not found" });
        return send(res, 200, publicDomain(domain));
      }

      if (match.route.id === "check-domain") {
        const ctx = await activeTenant();
        const domain = await store.getDomain(ctx.tenantId, match.params.id!);
        if (!domain) return send(res, 404, { error: "not found" });
        let records: string[][] = [];
        try {
          records = await deps.resolveTxt(domain.domain);
        } catch {
          records = [];
        }
        const flat = records.map((parts) => parts.join(""));
        if (!flat.some((value) => value.trim() === `cti-verify=${domain.token}`)) return send(res, 409, { error: "TXT record not found yet" });
        const verifiedAt = now().toISOString();
        await store.updateDomain(ctx.tenantId, domain.id, { status: "verified", verifiedAt, method: "dns_txt" });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "domain.verified", targetType: "domain", targetId: domain.id });
        return send(res, 200, { status: "verified", verifiedAt });
      }

      if (match.route.id === "email-domain") {
        const ctx = await activeTenant();
        const domain = await store.getDomain(ctx.tenantId, match.params.id!);
        if (!domain) return send(res, 404, { error: "not found" });
        const email = String(body.email ?? "").trim().toLowerCase();
        const [local, host] = email.split("@");
        if (host !== domain.domain || !["admin", "postmaster", "webmaster"].includes(local ?? "")) {
          return send(res, 400, { error: "use admin, postmaster or webmaster at that domain" });
        }
        const raw = randomBytes(32).toString("hex");
        await store.updateDomain(ctx.tenantId, domain.id, { status: "email_pending", emailTokenHash: hashToken(raw) });
        await mailer.send({
          to: email,
          subject: `Confirm ${domain.domain} for Community CTI`,
          category: "domain_verify",
          text: [
            `Someone asked to watch ${domain.domain} for scams and lookalike websites.`,
            "If that was your organisation, open this link to confirm:",
            "",
            `${config.portalBaseUrl}/domains/verify-email?token=${raw}`,
            "",
            "If you do not know about this, ignore this email and nothing will happen.",
          ].join("\n"),
        });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "domain.email_sent", targetType: "domain", targetId: domain.id });
        return send(res, 202, { ok: true });
      }

      if (match.route.id === "verify-email") {
        const raw = url.searchParams.get("token") ?? "";
        const found = raw ? await store.domainByEmailToken(hashToken(raw)) : null;
        if (!found) return send(res, 404, { error: "not found" });
        await store.updateDomain(found.tenantId, found.id, { status: "verified", verifiedAt: now().toISOString(), emailTokenHash: null, method: "email" });
        await store.writeAudit({ tenantId: found.tenantId, actorId: null, action: "domain.verified", targetType: "domain", targetId: found.id });
        return send(res, 200, { status: "verified" });
      }

      if (match.route.id === "list-findings") {
        const ctx = await activeTenant();
        const rows = await store.listFindings(ctx.tenantId);
        return send(res, 200, rows.map((item) => presentFinding(item, now(), config.evidenceBaseUrl)));
      }

      if (match.route.id === "get-finding") {
        const ctx = await activeTenant();
        const finding = await loadFinding(ctx.tenantId, match.params.id!);
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "finding.viewed", targetType: "finding", targetId: finding.id });
        return send(res, 200, presentFinding(finding, now(), config.evidenceBaseUrl));
      }

      if (match.route.id === "dismiss" || match.route.id === "challenge" || match.route.id === "reopen") {
        const ctx = await activeTenant();
        const finding = await loadFinding(ctx.tenantId, match.params.id!);
        const next: Finding["status"] = match.route.id === "dismiss" ? "dismissed" : match.route.id === "challenge" ? "challenged" : "open";
        const comment = String(body.comment ?? "").trim().slice(0, 2000);
        if (match.route.id === "dismiss") {
          const reason = String(body.reason ?? "");
          if (!isDismissReason(reason)) return send(res, 400, { error: "choose a reason" });
          if (reason === "other" && !comment) return send(res, 400, { error: "add a short note" });
          assertTransition(finding, "dismissed");
          await store.addFeedback(ctx.tenantId, { findingId: finding.id, actorId: ctx.user.id, action: "dismiss", reason, comment: comment || undefined });
          const legitimate = String(body.domain ?? "").trim().toLowerCase();
          if (reason === "legitimate_domain" && DOMAIN.test(legitimate)) await store.addLegitimateDomain(ctx.tenantId, legitimate, finding.id);
          if (reason === "not_ours") await store.addOpinion(ctx.tenantId, finding.id, "strongly-disagree");
        } else if (match.route.id === "challenge") {
          assertTransition(finding, "challenged");
          await store.addFeedback(ctx.tenantId, { findingId: finding.id, actorId: ctx.user.id, action: "challenge", comment });
        } else {
          assertTransition(finding, "open");
          await store.addFeedback(ctx.tenantId, { findingId: finding.id, actorId: ctx.user.id, action: "reopen" });
        }
        await store.updateFinding(ctx.tenantId, finding.id, { status: next });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: `finding.${next === "open" ? "reopen" : next}`, targetType: "finding", targetId: finding.id });
        return send(res, 200, presentFinding({ ...finding, status: next }, now(), config.evidenceBaseUrl));
      }

      if (match.route.id === "evidence") {
        const ctx = await activeTenant();
        const finding = await store.getFinding(ctx.tenantId, match.params.id!);
        const evidence = finding?.evidence.find((item) => item.id === match.params.evidenceId);
        if (!finding || !evidence) return send(res, 404, { error: "not found" });
        return send(res, 200, presentEvidence(evidence, now(), config.evidenceBaseUrl));
      }

      if (match.route.id === "create-action") {
        const ctx = await activeTenant();
        const findingId = body.findingId ? String(body.findingId) : null;
        if (findingId && (!UUID.test(findingId) || !(await store.getFinding(ctx.tenantId, findingId)))) return send(res, 404, { error: "not found" });
        const preview = body.preview && typeof body.preview === "object" && !Array.isArray(body.preview) ? body.preview as Record<string, unknown> : {};
        const action = {
          id: randomUUID(),
          tenantId: ctx.tenantId,
          findingId,
          kind: String(body.kind ?? "manual_steps"),
          status: "proposed" as const,
          preview,
          approvedBy: null,
          approvedAt: null,
        };
        await store.addAction({ ...action, proposedBy: ctx.user.id });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "action.proposed", targetType: "action", targetId: action.id });
        return send(res, 201, action);
      }

      if (match.route.id === "get-action") {
        const ctx = await activeTenant();
        const action = await store.getAction(ctx.tenantId, match.params.id!);
        if (!action) return send(res, 404, { error: "not found" });
        return send(res, 200, action);
      }

      if (match.route.id === "approve-action") {
        const ctx = await activeTenant();
        const action = await store.getAction(ctx.tenantId, match.params.id!);
        if (!action) return send(res, 404, { error: "not found" });
        if (ctx.membership.role !== "owner") return send(res, 403, { error: "only an owner can approve" });
        if (action.status !== "proposed") return send(res, 409, { error: "invalid transition" });
        const approvedAt = now().toISOString();
        await store.updateAction(ctx.tenantId, action.id, { status: "approved", approvedBy: ctx.user.id, approvedAt });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "action.approved", targetType: "action", targetId: action.id });
        const executed = executeAction({
          id: action.id,
          tenantId: action.tenantId,
          status: "approved",
          preview: action.preview,
          approvedBy: ctx.user.id,
          approvedAt,
        }, () => undefined);
        await store.updateAction(ctx.tenantId, action.id, { status: "executed" });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "action.executed", targetType: "action", targetId: action.id });
        return send(res, 200, { preview: action.preview, applied: executed.applied, status: "executed" });
      }

      if (match.route.id === "cancel-action") {
        const ctx = await activeTenant();
        const action = await store.getAction(ctx.tenantId, match.params.id!);
        if (!action) return send(res, 404, { error: "not found" });
        if (action.status !== "proposed" && action.status !== "approved") return send(res, 409, { error: "invalid transition" });
        await store.updateAction(ctx.tenantId, action.id, { status: "cancelled" });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "action.cancelled", targetType: "action", targetId: action.id });
        return send(res, 200, { ...action, status: "cancelled" });
      }

      if (match.route.id === "review") {
        const ctx = await activeTenant();
        if (ctx.membership.role !== "analyst" && ctx.membership.role !== "owner") return send(res, 403, { error: "analyst role required" });
        const rows = (await store.listFindings(ctx.tenantId)).filter((item) => item.status === "challenged" || Math.abs((item.confidenceFactors?.[0]?.points ?? item.confidence) - item.confidence) > 30);
        return send(res, 200, rows.map((item) => presentFinding(item, now(), config.evidenceBaseUrl)));
      }

      if (match.route.id === "resolve-review") {
        const ctx = await activeTenant();
        if (ctx.membership.role !== "analyst" && ctx.membership.role !== "owner") return send(res, 403, { error: "analyst role required" });
        const finding = await loadFinding(ctx.tenantId, match.params.id!);
        const reason = String(body.reason ?? "").trim();
        if (!reason) return send(res, 400, { error: "a reason is required" });
        const outcome = String(body.outcome ?? "");
        if (!["uphold", "withdraw", "adjust"].includes(outcome)) return send(res, 400, { error: "choose uphold, withdraw or adjust" });
        if (outcome === "withdraw") {
          assertTransition(finding, "dismissed");
          await store.updateFinding(ctx.tenantId, finding.id, { status: "dismissed" });
        }
        if (outcome === "adjust") {
          const confidence = Number(body.confidence);
          if (!Number.isInteger(confidence) || confidence < 0 || confidence > 100) return send(res, 400, { error: "confidence must be a whole number from 0 to 100" });
          await store.updateFinding(ctx.tenantId, finding.id, { confidence });
        }
        await store.addOpinion(ctx.tenantId, finding.id, outcome === "uphold" ? "agree" : "disagree");
        await store.addFeedback(ctx.tenantId, { findingId: finding.id, actorId: ctx.user.id, action: "resolve", reason });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "review.resolved", targetType: "finding", targetId: finding.id });
        return send(res, 200, { ok: true, reason });
      }

      if (match.route.id === "list-exposures" || match.route.id === "get-exposure") {
        const ctx = await activeTenant();
        if (ctx.membership.role !== "owner" && ctx.membership.role !== "credential_viewer") return send(res, 403, { error: "not allowed" });
        if (match.route.id === "list-exposures") return send(res, 200, await store.listExposures(ctx.tenantId));
        const row = await store.getExposure(ctx.tenantId, match.params.id!);
        if (!row) return send(res, 404, { error: "not found" });
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "credential_exposure.view", targetType: "credential_exposure", targetId: row.id });
        return send(res, 200, { id: row.id, breachName: row.breachName, emailStoredAs: "ciphertext" });
      }

      if (match.route.id === "m365-connect") {
        const ctx = await activeTenant();
        if (ctx.membership.role !== "owner") return send(res, 403, { error: "only an owner can connect Microsoft 365" });
        const ciphertext = encryptField(String(body.accessToken ?? "pending"), config.fieldKey);
        await store.setIntegrationToken(ctx.tenantId, "m365", ciphertext);
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "m365.connected", targetType: "integration", targetId: "m365" });
        return send(res, 201, { connected: true, ciphertextStored: ciphertext !== body.accessToken });
      }

      if (match.route.id === "m365-disconnect") {
        const ctx = await activeTenant();
        await store.clearM365(ctx.tenantId);
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "m365.disconnected", targetType: "integration", targetId: "m365" });
        return send(res, 200, { connected: false });
      }

      if (match.route.id === "share-get") {
        const ctx = await activeTenant();
        const rows = await store.listSharePrefs(ctx.tenantId);
        return send(res, 200, rows.length ? rows : [{ category: "phishing", enabled: false }]);
      }

      if (match.route.id === "share-put") {
        const ctx = await activeTenant();
        if (ctx.membership.role !== "owner") return send(res, 403, { error: "only an owner can change sharing" });
        const category = String(body.category ?? "phishing");
        const enabled = Boolean(body.enabled);
        await store.setSharePref(ctx.tenantId, category, enabled);
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "share.preference", targetType: "sharing", targetId: category });
        return send(res, 200, { category, enabled });
      }

      if (match.route.id === "share-preview") {
        const ctx = await activeTenant();
        const tenant = await store.getTenant(ctx.tenantId);
        const findingId = body.findingId ? String(body.findingId) : null;
        if (findingId && (!UUID.test(findingId) || !(await store.getFinding(ctx.tenantId, findingId)))) return send(res, 404, { error: "not found" });
        const cleaned = sanitiseWarning({
          text: String(body.text ?? ""),
          tenantName: tenant?.name ?? "",
          people: Array.isArray(body.people) ? body.people.map(String) : [],
          internalHosts: Array.isArray(body.internalHosts) ? body.internalHosts.map(String) : [],
        });
        const id = randomUUID();
        await store.addShare({ id, tenantId: ctx.tenantId, findingId, category: String(body.category ?? "phishing"), cultural: Boolean(body.cultural), approvedBy: null, sanitised: cleaned.text });
        return send(res, 200, { id, text: cleaned.text });
      }

      if (match.route.id === "share-approve") {
        const ctx = await activeTenant();
        const item = await store.getShare(ctx.tenantId, match.params.id!);
        if (!item) return send(res, 404, { error: "not found" });
        const category = String(body.category ?? "phishing");
        const enabled = (await store.listSharePrefs(ctx.tenantId)).some((pref) => pref.category === category && pref.enabled);
        const decision = decideShare({ categoryEnabled: enabled, itemApproved: true, approverId: ctx.user.id, cultural: item.cultural });
        if (!decision.ok) return send(res, 409, { error: decision.reason });
        await store.approveShare(ctx.tenantId, item.id, ctx.user.id, now().toISOString());
        await store.writeAudit({ tenantId: ctx.tenantId, actorId: ctx.user.id, action: "share.approved", targetType: "shared_item", targetId: item.id });
        return send(res, 200, { ok: true, approverId: ctx.user.id });
      }

      if (match.route.id === "notif-get" || match.route.id === "notif-put") {
        const ctx = await activeTenant();
        if (match.route.id === "notif-put") {
          const mode = String(body.mode ?? "digest") as NotifyMode;
          if (!NOTIFY_MODES.includes(mode)) return send(res, 400, { error: "choose how we should email you" });
          await store.setNotify(ctx.tenantId, ctx.user.id, mode);
        }
        return send(res, 200, { mode: (await store.getNotify(ctx.tenantId, ctx.user.id)) ?? "digest" });
      }

      if (match.route.id === "cost") {
        const ctx = await activeTenant();
        return send(res, 200, { tenantId: ctx.tenantId, aud: await store.costTotal(ctx.tenantId), hypotheses: true });
      }

      if (match.route.id === "advisories" || match.route.id === "au-ransomware") {
        const ctx = await activeTenant();
        const tenant = await store.getTenant(ctx.tenantId);
        const orgType = tenant?.orgType ?? "other";
        if (match.route.id === "advisories") {
          const since = new Date(now().getTime() - 90 * 86_400_000).toISOString();
          const rows = await store.listAdvisories(watchedTags(orgType), since, 200);
          return send(res, 200, rankAdvisories(rows, orgType).slice(0, 50));
        }
        const since = new Date(now().getTime() - 90 * 86_400_000).toISOString();
        return send(res, 200, summariseRansomware(await store.listAuVictims(since), orgType, now()));
      }

      return send(res, 404, { error: "not found" });
    } catch (error) {
      const status = (error as { statusCode?: number }).statusCode ?? 500;
      if (status >= 500) console.error(JSON.stringify({ level: "error", msg: "request failed", path: req.url?.split("?")[0], error: error instanceof Error ? error.message : String(error) }));
      if (!res.headersSent) send(res, status, { error: status >= 500 ? "something went wrong" : error instanceof Error ? error.message : "error" });
    }
  });
}

export function defaultDeps(): AppDeps<MemoryStore> {
  return {
    store: new MemoryStore(),
    mailer: new SinkMailer(),
    now: () => new Date(),
    resolveTxt: async () => [],
  };
}
