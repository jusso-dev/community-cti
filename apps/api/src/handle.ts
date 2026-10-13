import { randomUUID } from "node:crypto";
import {
  applyInvestigation,
  runAgent,
  scriptedModel,
  type Model,
} from "@community-cti/agents";
import { lookupHibpDomain, assertNoPasswordMaterial } from "@community-cti/collectors";
import {
  asRole,
  audit,
  decodeKey,
  encryptField,
  isVerified,
  processingMode,
  sha256,
  TIERS,
  upsertStix,
  withTenant,
  type Db,
} from "@community-cti/db";
import { assertM365Scopes, M365_OPTIONAL_SCOPES, M365_SCOPES, sealIntegrationToken } from "@community-cti/integrations";
import { correlateExposures, prepareShare, type ExposureProvider } from "@community-cti/intel";
import { LOOKALIKE_WEIGHTS } from "@community-cti/intel";
import { alertCopy, channelFor, type Preference } from "@community-cti/notify";
import {
  canTransition,
  evidenceIsRestricted,
  type FindingStatus,
  type TlpMarking,
} from "@community-cti/schema";
import { buildIndicator, buildInfrastructure, buildOpinion, buildReport } from "@community-cti/schema/stix";
import { matchRoute } from "./routes.js";

/** Sharing stays off until the governance group endorses the rules. Tests may pass an override. */
export const SHARING_LAUNCH_APPROVED = false;

const ORG_TYPES = ["acco", "land_council", "ams", "indigenous_corporation", "other"];
const ROLES = ["owner", "member", "credential_viewer", "analyst"];
const REASONS = ["not_ours", "already_handled", "legitimate_domain", "not_relevant", "other"];
const SESSION_MS = 12 * 60 * 60 * 1000;
const LINK_MS = 15 * 60 * 1000;
const PRESIGN_SECONDS = 300;

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
}

export interface ObjectStore {
  put(key: string, body: Uint8Array): Promise<void>;
  presign(key: string, expEpoch: number): string;
}

export class MemoryObjects implements ObjectStore {
  items = new Map<string, Uint8Array>();
  async put(key: string, body: Uint8Array): Promise<void> {
    this.items.set(key, body);
  }
  presign(key: string, expEpoch: number): string {
    return `https://evidence.local/${encodeURIComponent(key)}?exp=${expEpoch}`;
  }
}

export interface ApiDeps {
  db: Db;
  now: () => Date;
  mail: (message: MailMessage) => Promise<void>;
  resolveTxt: (domain: string) => Promise<string[][]>;
  encryptionKey: Buffer;
  objects: ObjectStore;
  model?: Model;
  exposureProvider?: ExposureProvider;
  resolveHost?: (host: string) => Promise<string[]>;
  hibpFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  /** Test-only. Production leaves this unset, and the constant above stays false. */
  sharingLaunchOverrideForTests?: boolean;
}

export interface ApiRequest {
  method: string;
  url: string;
  headers?: Record<string, string | undefined>;
  body?: unknown;
  ip?: string;
}

export interface ApiResult {
  status: number;
  body: unknown;
}

interface Actor {
  userId: string;
  tenantId: string | null;
  email: string;
}

export function devEncryptionKey(): Buffer {
  return decodeKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
}

export async function handle(deps: ApiDeps, req: ApiRequest): Promise<ApiResult> {
  try {
    const url = new URL(req.url, "http://localhost");
    const matched = matchRoute(req.method.toUpperCase(), url.pathname);
    if (!matched) return { status: 404, body: { error: "That page was not found." } };
    return await dispatch(deps, req, url, matched.id, matched.params);
  } catch (error) {
    const code = typeof error === "object" && error && "code" in error ? String((error as { code: string }).code) : "";
    if (code === "23505") return { status: 409, body: { error: "That record already exists." } };
    if (code) return { status: 500, body: { error: "The request could not be completed." } };
    if (error instanceof Error) return { status: 400, body: { error: error.message } };
    return { status: 500, body: { error: "The request could not be completed." } };
  }
}

async function dispatch(deps: ApiDeps, req: ApiRequest, url: URL, id: string, params: Record<string, string>): Promise<ApiResult> {
  const body = objectBody(req.body);
  if (id === "healthz") return { status: 200, body: { ok: true } };
  if (id === "magic-link") return sendMagicLink(deps, str(body.email));
  if (id === "callback") return consumeMagicLink(deps, url.searchParams.get("token") ?? "");
  if (id === "verify-email") return verifyEmail(deps, url.searchParams.get("token") ?? "", req.ip);
  if (id === "m365-scopes") {
    return { status: 200, body: { scopes: [...M365_SCOPES], optional: [...M365_OPTIONAL_SCOPES] } };
  }

  const current = await actor(deps, req);
  if (!current) return { status: 401, body: { error: "You need to sign in." } };
  if (id === "create-org") return createOrg(deps, current, str(body.name), str(body.type), req.ip);

  if (!current.tenantId) return { status: 403, body: { error: "Create an organisation before continuing." } };
  if ((id === "invite" || id === "consent" || id === "change-role") && params.id !== current.tenantId) {
    return { status: 404, body: { error: "That record was not found." } };
  }
  const role = await roleIn(deps, current.tenantId, current.userId);
  if (!role) return { status: 403, body: { error: "You do not have permission to do that." } };

  switch (id) {
    case "invite":
      return invite(deps, current, role, str(body.email), str(body.role));
    case "consent":
      return consent(deps, current, str(body.scope), str(body.grantorName), str(body.grantorRole), req.ip ?? "");
    case "change-role":
      return changeRole(deps, current, role, params.userId ?? "", str(body.role));
    case "add-domain":
      return addDomain(deps, current, str(body.domain));
    case "check-domain":
      return checkDomain(deps, current, params.id ?? "");
    case "email-domain":
      return emailDomain(deps, current, params.id ?? "");
    case "list-findings":
      return listFindings(deps, current.tenantId);
    case "get-finding":
      return getFinding(deps, current, params.id ?? "");
    case "evidence":
      return evidence(deps, current, params.id ?? "", params.evidenceId ?? "");
    case "dismiss":
      return transition(deps, current, params.id ?? "", "dismissed", "dismiss", body);
    case "challenge":
      return transition(deps, current, params.id ?? "", "challenged", "challenge", body);
    case "reopen":
      return transition(deps, current, params.id ?? "", "open", "reopen", body);
    case "notify":
      return notify(deps, current, params.id ?? "");
    case "credentials":
      return listCredentials(deps, current, role);
    case "credentials-sync":
      return syncCredentials(deps, current, role, str(body.domain));
    case "exposures":
      return exposures(deps, current, body);
    case "create-action":
      return createAction(deps, current, str(body.findingId), str(body.kind), body.preview ?? {});
    case "approve-action":
      return approveAction(deps, current, role, params.id ?? "");
    case "execute-action":
      return executeAction(deps, current, params.id ?? "");
    case "review":
      return { status: 200, body: { weights: LOOKALIKE_WEIGHTS, autoTune: false } };
    case "review-weights":
      return { status: 403, body: { error: "Weights are not changed automatically.", weights: LOOKALIKE_WEIGHTS, autoTune: false } };
    case "m365-connect":
      return connectM365(deps, current, role, body);
    case "share":
      return share(deps, current, str(body.findingId));
    case "cost":
      return recordCost(deps, current, str(body.category), Number(body.units ?? 0), Number(body.aud ?? 0));
    case "investigate":
      return investigate(deps, current, str(body.findingId));
    default:
      return { status: 404, body: { error: "That page was not found." } };
  }
}

function objectBody(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) return {};
  return body as Record<string, unknown>;
}

function str(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

async function actor(deps: ApiDeps, req: ApiRequest): Promise<Actor | null> {
  const header = req.headers?.authorization ?? req.headers?.Authorization ?? "";
  const raw = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!raw) return null;
  const rows = await asRole(deps.db, "cti_app", (tx) => tx.query<{ user_id: string; tenant_id: string | null; email: string }>(
    `select s.user_id, s.tenant_id, u.email
     from sessions s join users u on u.id = s.user_id
     where s.token_hash = $1 and s.expires_at > $2`,
    [sha256(raw), deps.now().toISOString()],
  ));
  const row = rows.rows[0];
  if (!row) return null;
  return { userId: row.user_id, tenantId: row.tenant_id, email: row.email };
}

async function roleIn(deps: ApiDeps, tenantId: string, userId: string): Promise<string | null> {
  const rows = await withTenant(deps.db, tenantId, (tx) =>
    tx.query<{ role: string }>("select role from memberships where user_id = $1", [userId]),
  );
  return rows.rows[0]?.role ?? null;
}

async function sendMagicLink(deps: ApiDeps, email: string): Promise<ApiResult> {
  if (!email.includes("@")) return { status: 400, body: { error: "Enter a valid email address." } };
  const token = randomToken();
  const expires = new Date(deps.now().getTime() + LINK_MS).toISOString();
  await asRole(deps.db, "cti_app", async (tx) => {
    await tx.query(
      `insert into users (email) values (lower($1))
       on conflict (email) do update set email = excluded.email`,
      [email],
    );
    await tx.query(
      "insert into magic_links (email, token_hash, expires_at) values (lower($1), $2, $3)",
      [email, sha256(token), expires],
    );
  });
  await deps.mail({
    to: email,
    subject: "Your sign-in link",
    text: `Use this link to sign in. It expires soon.\nhttp://localhost:8080/auth/callback?token=${token}`,
  });
  await audit(deps.db, { tenantId: null, action: "magic_link_requested", metadata: { email: email.toLowerCase() } });
  return { status: 200, body: { ok: true } };
}

async function consumeMagicLink(deps: ApiDeps, token: string): Promise<ApiResult> {
  if (!token) return { status: 400, body: { error: "That sign-in link is not valid." } };
  const sessionToken = randomToken();
  const expires = new Date(deps.now().getTime() + SESSION_MS).toISOString();
  const created = await asRole(deps.db, "cti_app", async (tx) => {
    const links = await tx.query<{ id: string; email: string }>(
      "select id, email from magic_links where token_hash = $1 and consumed_at is null and expires_at > $2",
      [sha256(token), deps.now().toISOString()],
    );
    const link = links.rows[0];
    if (!link) return null;
    await tx.query("update magic_links set consumed_at = $2 where id = $1", [link.id, deps.now().toISOString()]);
    const users = await tx.query<{ id: string }>("select id from users where email = $1", [link.email]);
    const userId = users.rows[0]?.id;
    if (!userId) return null;
    await tx.query(
      "insert into sessions (user_id, token_hash, expires_at) values ($1, $2, $3)",
      [userId, sha256(sessionToken), expires],
    );
    const invited = await tx.query<{ tenant_id: string | null }>("select accept_invites($1::uuid, $2) as tenant_id", [userId, link.email]);
    const tenantId = invited.rows[0]?.tenant_id ?? null;
    if (tenantId) {
      await tx.query("update sessions set tenant_id = $2 where token_hash = $1", [sha256(sessionToken), tenantId]);
    }
    return { userId, tenantId };
  });
  if (!created) return { status: 400, body: { error: "That sign-in link is not valid." } };
  await audit(deps.db, { tenantId: created.tenantId, actorId: created.userId, action: "session_started" });
  return { status: 200, body: { token: sessionToken, userId: created.userId, expiresAt: expires } };
}

async function createOrg(deps: ApiDeps, current: Actor, name: string, type: string, ip?: string): Promise<ApiResult> {
  if (!name) return { status: 400, body: { error: "Enter the organisation name." } };
  if (!ORG_TYPES.includes(type)) return { status: 400, body: { error: "Choose a valid organisation type." } };
  const created = await asRole(deps.db, "cti_app", (tx) =>
    tx.query<{ id: string }>("select create_organisation($1::uuid, $2, $3) as id", [current.userId, name, type]),
  );
  const id = created.rows[0]?.id;
  if (!id) return { status: 500, body: { error: "The request could not be completed." } };
  await audit(deps.db, { tenantId: id, actorId: current.userId, action: "organisation_created", targetType: "tenant", targetId: id, metadata: { type, ip: ip ?? "" } });
  return { status: 200, body: { id, name, type } };
}

async function invite(deps: ApiDeps, current: Actor, role: string, email: string, nextRole: string): Promise<ApiResult> {
  if (role !== "owner") return { status: 403, body: { error: "Only an owner can invite people." } };
  if (!email.includes("@") || !ROLES.includes(nextRole)) return { status: 400, body: { error: "Enter an email and a valid role." } };
  const inserted = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ id: string }>(
    "insert into invites (tenant_id, email, role, created_by) values ($1, lower($2), $3, $4) returning id",
    [current.tenantId, email, nextRole, current.userId],
  ));
  const id = inserted.rows[0]?.id ?? "";
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "invite_created", targetType: "invite", targetId: id, metadata: { role: nextRole } });
  return { status: 200, body: { id, email: email.toLowerCase(), role: nextRole } };
}

async function consent(deps: ApiDeps, current: Actor, scope: string, grantorName: string, grantorRole: string, ip: string): Promise<ApiResult> {
  if (scope !== "domain_monitoring") return { status: 400, body: { error: "That consent scope is not recognised." } };
  if (!grantorName || !grantorRole) return { status: 400, body: { error: "Enter the name and role of the person giving consent." } };
  const inserted = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ id: string; granted_at: string }>(
    `insert into consents (tenant_id, scope, grantor_name, grantor_role, ip)
     values ($1, $2, $3, $4, $5) returning id, granted_at`,
    [current.tenantId, scope, grantorName, grantorRole, ip],
  ));
  const row = inserted.rows[0];
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "consent_granted", targetType: "consent", targetId: row?.id, metadata: { scope, ip } });
  return { status: 200, body: { id: row?.id, grantedAt: row?.granted_at, scope } };
}

async function changeRole(deps: ApiDeps, current: Actor, role: string, userId: string, nextRole: string): Promise<ApiResult> {
  if (role !== "owner") return { status: 403, body: { error: "Only an owner can change roles." } };
  if (!ROLES.includes(nextRole)) return { status: 400, body: { error: "Choose a valid role." } };
  const updated = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ id: string }>(
    "update memberships set role = $2 where user_id = $1 returning id",
    [userId, nextRole],
  ));
  if (!updated.rows[0]) return { status: 404, body: { error: "That record was not found." } };
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "role_changed", targetType: "membership", targetId: userId, metadata: { role: nextRole } });
  return { status: 200, body: { userId, role: nextRole } };
}

async function hasMonitoringConsent(deps: ApiDeps, tenantId: string): Promise<boolean> {
  const rows = await withTenant(deps.db, tenantId, (tx) => tx.query(
    "select 1 from consents where scope = 'domain_monitoring' and revoked_at is null",
  ));
  return rows.rows.length > 0;
}

async function addDomain(deps: ApiDeps, current: Actor, domain: string): Promise<ApiResult> {
  const name = domain.toLowerCase();
  if (!name.includes(".")) return { status: 400, body: { error: "Enter a domain name." } };
  if (!(await hasMonitoringConsent(deps, current.tenantId!))) {
    return { status: 403, body: { error: "Monitoring does not start until consent is recorded." } };
  }
  const token = `cti-verify=${randomToken()}`;
  const inserted = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ id: string }>(
    "insert into verified_domains (tenant_id, domain, status, token) values ($1, $2, 'pending', $3) returning id",
    [current.tenantId, name, token],
  ));
  const id = inserted.rows[0]?.id ?? "";
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "domain_added", targetType: "verified_domain", targetId: id, metadata: { domain: name } });
  return { status: 200, body: { id, domain: name, status: "pending", token } };
}

async function checkDomain(deps: ApiDeps, current: Actor, id: string): Promise<ApiResult> {
  const rows = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ domain: string; token: string }>(
    "select domain, token from verified_domains where id = $1",
    [id],
  ));
  const row = rows.rows[0];
  if (!row) return { status: 404, body: { error: "That record was not found." } };
  const txt = (await deps.resolveTxt(row.domain)).flat().join(" ");
  if (!txt.includes(row.token)) {
    await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "domain_check_failed", targetType: "verified_domain", targetId: id });
    return { status: 200, body: { id, status: "pending", verified: false } };
  }
  await withTenant(deps.db, current.tenantId!, (tx) => tx.query(
    "update verified_domains set status = 'verified', method = 'dns', verified_at = $2, txt_missing_since = null where id = $1",
    [id, deps.now().toISOString()],
  ));
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "domain_verified", targetType: "verified_domain", targetId: id, metadata: { method: "dns" } });
  return { status: 200, body: { id, status: "verified", verified: true } };
}

async function emailDomain(deps: ApiDeps, current: Actor, id: string): Promise<ApiResult> {
  const rows = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ domain: string; token: string; status: string }>(
    "select domain, token, status from verified_domains where id = $1",
    [id],
  ));
  const row = rows.rows[0];
  if (!row) return { status: 404, body: { error: "That record was not found." } };
  if (row.status !== "pending") return { status: 409, body: { error: "That domain is not waiting for a check." } };
  const addresses = ["admin", "postmaster", "webmaster"].map((local) => `${local}@${row.domain}`);
  for (const to of addresses) {
    await deps.mail({
      to,
      subject: "Confirm this domain",
      text: `Confirm ${row.domain} once, then the link stops working.\nhttp://localhost:8080/domains/verify-email?token=${encodeURIComponent(row.token)}`,
    });
  }
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "domain_email_sent", targetType: "verified_domain", targetId: id });
  return { status: 200, body: { id, sent: addresses } };
}

async function verifyEmail(deps: ApiDeps, token: string, ip?: string): Promise<ApiResult> {
  if (!token) return { status: 400, body: { error: "That link is not valid." } };
  const rows = await asRole(deps.db, "cti_app", (tx) => tx.query<{ id: string; tenant_id: string }>(
    "select * from verify_domain_email($1)",
    [token],
  ));
  const row = rows.rows[0];
  if (!row) return { status: 400, body: { error: "That link is not valid." } };
  await audit(deps.db, { tenantId: row.tenant_id, action: "domain_verified", targetType: "verified_domain", targetId: row.id, metadata: { method: "email", ip: ip ?? "" } });
  return { status: 200, body: { id: row.id, status: "verified" } };
}

interface FindingRow {
  id: string;
  kind: string;
  title: string;
  plain_english_summary: string;
  confidence: number;
  confidence_factors: unknown;
  status: FindingStatus;
  provenance: unknown;
  stix_refs: unknown;
  cultural: boolean;
}

function presentFinding(row: FindingRow): Record<string, unknown> {
  return {
    id: row.id,
    kind: row.kind,
    title: row.title,
    plainEnglishSummary: row.plain_english_summary,
    confidence: Number(row.confidence),
    confidenceFactors: row.confidence_factors,
    status: row.status,
    provenance: publicProvenance(row.provenance),
    stixRefs: row.stix_refs,
    cultural: row.cultural,
  };
}

function publicProvenance(raw: unknown): unknown {
  if (!Array.isArray(raw)) return [];
  return raw.map((item) => {
    if (!item || typeof item !== "object") return item;
    const row = { ...(item as Record<string, unknown>) };
    const tlp = row.accessRestriction;
    if (typeof tlp === "string" && evidenceIsRestricted(tlp as TlpMarking)) {
      delete row.sourceUrl;
      row.note = "Source detail is restricted.";
    }
    return row;
  });
}

async function listFindings(deps: ApiDeps, tenantId: string): Promise<ApiResult> {
  const rows = await withTenant(deps.db, tenantId, (tx) => tx.query<FindingRow>(
    "select id, kind, title, plain_english_summary, confidence, confidence_factors, status, provenance, stix_refs, cultural from findings order by created_at",
  ));
  return { status: 200, body: { findings: rows.rows.map(presentFinding) } };
}

async function loadFinding(deps: ApiDeps, tenantId: string, id: string): Promise<FindingRow | null> {
  const rows = await withTenant(deps.db, tenantId, (tx) => tx.query<FindingRow>(
    "select id, kind, title, plain_english_summary, confidence, confidence_factors, status, provenance, stix_refs, cultural from findings where id = $1",
    [id],
  ));
  return rows.rows[0] ?? null;
}

async function getFinding(deps: ApiDeps, current: Actor, id: string): Promise<ApiResult> {
  const row = await loadFinding(deps, current.tenantId!, id);
  if (!row) return { status: 404, body: { error: "That record was not found." } };
  await withTenant(deps.db, current.tenantId!, (tx) => tx.query(
    "insert into product_events (tenant_id, user_id, name, finding_id) values ($1, $2, 'finding_viewed', $3)",
    [current.tenantId, current.userId, id],
  ));
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "finding_viewed", targetType: "finding", targetId: id });
  return { status: 200, body: presentFinding(row) };
}

async function evidence(deps: ApiDeps, current: Actor, findingId: string, evidenceId: string): Promise<ApiResult> {
  const rows = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{
    id: string; label: string; object_key: string | null; source_id: string; tlp: string; licence: string;
  }>(
    "select id, label, object_key, source_id, tlp, licence from finding_evidence where id = $1 and finding_id = $2",
    [evidenceId, findingId],
  ));
  const row = rows.rows[0];
  if (!row) return { status: 404, body: { error: "That record was not found." } };
  if (evidenceIsRestricted(row.tlp as TlpMarking)) {
    return { status: 200, body: { redacted: true, sourceId: row.source_id, note: "This evidence is restricted." } };
  }
  if (!row.object_key) return { status: 404, body: { error: "That record was not found." } };
  const exp = Math.floor(deps.now().getTime() / 1000) + PRESIGN_SECONDS;
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "evidence_viewed", targetType: "finding_evidence", targetId: evidenceId });
  return { status: 200, body: { url: deps.objects.presign(row.object_key, exp), expiresIn: PRESIGN_SECONDS } };
}

async function transition(deps: ApiDeps, current: Actor, id: string, next: FindingStatus, kind: string, body: Record<string, unknown>): Promise<ApiResult> {
  const reason = str(body.reason);
  const note = str(body.note);
  if (!REASONS.includes(reason) && kind !== "reopen") return { status: 400, body: { error: "Choose a reason." } };
  if (reason === "other" && !note) return { status: 400, body: { error: "Add a short note for this reason." } };
  const currentRow = await loadFinding(deps, current.tenantId!, id);
  if (!currentRow) return { status: 404, body: { error: "That record was not found." } };
  if (!canTransition(currentRow.status, next)) return { status: 409, body: { error: "That status change is not allowed." } };
  if (reason === "legitimate_domain" && !str(body.domain)) return { status: 400, body: { error: "Enter the domain to allow." } };
  await withTenant(deps.db, current.tenantId!, async (tx) => {
    await tx.query("update findings set status = $2 where id = $1", [id, next]);
    await tx.query(
      "insert into finding_feedback (tenant_id, finding_id, actor_id, kind, reason, note) values ($1, $2, $3, $4, $5, $6)",
      [current.tenantId, id, current.userId, kind, reason || null, note || null],
    );
    if (kind === "dismiss") {
      await tx.query(
        "insert into product_events (tenant_id, user_id, name, finding_id) values ($1, $2, 'finding_dismissed', $3)",
        [current.tenantId, current.userId, id],
      );
    }
    if (reason === "legitimate_domain") {
      await tx.query(
        "insert into legitimate_domains (tenant_id, domain) values ($1, lower($2)) on conflict (tenant_id, domain) do nothing",
        [current.tenantId, str(body.domain)],
      );
    }
  });
  if (reason === "not_ours") await recordOpinion(deps, current.tenantId!, currentRow, note);
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: `finding_${kind}`, targetType: "finding", targetId: id, metadata: { reason, status: next } });
  return { status: 200, body: { id, status: next } };
}

async function recordOpinion(deps: ApiDeps, tenantId: string, finding: FindingRow, note: string): Promise<void> {
  const source = { sourceId: "community", licence: "organisation feedback", tlp: "TLP:AMBER" as const };
  const now = deps.now().toISOString();
  const refs = Array.isArray(finding.stix_refs) ? finding.stix_refs.filter((item) => typeof item === "string") as string[] : [];
  let objectRef = refs.find((item) => item.includes("--"));
  if (!objectRef) {
    const marker = buildInfrastructure({ name: "Dismissed match", source, now });
    await upsertStix(deps.db, marker, tenantId);
    objectRef = marker.id;
  }
  const opinion = buildOpinion({
    opinion: "strongly-disagree",
    objectRefs: [objectRef],
    explanation: note || "This does not belong to the organisation.",
    source,
    now,
  });
  await upsertStix(deps.db, opinion, tenantId);
}

async function notify(deps: ApiDeps, current: Actor, id: string): Promise<ApiResult> {
  const finding = await loadFinding(deps, current.tenantId!, id);
  if (!finding) return { status: 404, body: { error: "That record was not found." } };
  const prefs = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ mode: Preference }>(
    "select mode from notification_preferences where user_id = $1",
    [current.userId],
  ));
  const channel = channelFor(Number(finding.confidence), prefs.rows[0]?.mode ?? "immediate");
  const copy = alertCopy(finding.kind);
  if (channel === "immediate") await deps.mail({ to: current.email, subject: copy.subject, text: copy.text });
  return { status: 200, body: { channel, sent: channel === "immediate" } };
}

async function listCredentials(deps: ApiDeps, current: Actor, role: string): Promise<ApiResult> {
  if (role !== "owner" && role !== "credential_viewer") return { status: 403, body: { error: "You do not have permission to view credentials." } };
  const rows = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ id: string; domain_name: string; breach_name: string; data_classes: string[] }>(
    "select id, domain_name, breach_name, data_classes from credential_exposures order by created_at",
  ));
  await audit(deps.db, {
    tenantId: current.tenantId,
    actorId: current.userId,
    action: "credential_exposure_viewed",
    targetType: "credential_exposure",
    metadata: { ids: rows.rows.map((row) => row.id) },
  });
  return { status: 200, body: { exposures: rows.rows } };
}

async function syncCredentials(deps: ApiDeps, current: Actor, role: string, domain: string): Promise<ApiResult> {
  if (role !== "owner" && role !== "credential_viewer") return { status: 403, body: { error: "You do not have permission to view credentials." } };
  if (!domain) return { status: 400, body: { error: "Enter a domain." } };
  if (!(await isVerified(deps.db, current.tenantId!, domain))) {
    return { status: 403, body: { error: "Verify the domain before this lookup." } };
  }
  if (!deps.hibpFetch) return { status: 400, body: { error: "HIBP is not configured." } };
  const records = await lookupHibpDomain(domain, { verified: true, fetchImpl: deps.hibpFetch });
  const secretBlob = JSON.stringify(records);
  assertNoPasswordMaterial(records, []);
  for (const record of records) {
    if (secretBlob.includes("passwordHash")) return { status: 500, body: { error: "The request could not be completed." } };
    const email = encryptField(record.email, deps.encryptionKey);
    await withTenant(deps.db, current.tenantId!, (tx) => tx.query(
      `insert into credential_exposures (tenant_id, domain_name, email_ciphertext, breach_name, breach_date, data_classes)
       values ($1, $2, $3, $4, nullif($5, '')::date, $6)`,
      [current.tenantId, domain, email, record.breachName, record.breachDate, record.dataClasses],
    ));
  }
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "credential_sync", targetType: "verified_domain", metadata: { domain, count: records.length } });
  return { status: 200, body: { imported: records.length } };
}

async function exposures(deps: ApiDeps, current: Actor, body: Record<string, unknown>): Promise<ApiResult> {
  const requested = Array.isArray(body.domains) ? body.domains.filter((item) => typeof item === "string") as string[] : [];
  const verified = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ domain: string }>(
    "select domain from verified_domains where status = 'verified'",
  ));
  const allowed = new Set(verified.rows.map((row) => row.domain.toLowerCase()));
  const domains = requested.filter((domain) => allowed.has(domain.toLowerCase())).map((name) => ({ name, verified: true }));
  const cves = Array.isArray(body.cves) ? body.cves as Array<{ product: string; cve: string; kev: boolean; epss: number; version?: string }> : [];
  const records = await correlateExposures({
    domains,
    resolve: deps.resolveHost ?? (async () => []),
    provider: deps.exposureProvider ?? { async lookupIp() { return []; } },
    cves,
  });
  await withTenant(deps.db, current.tenantId!, (tx) => tx.query(
    "insert into cost_ledger (tenant_id, category, units, aud) values ($1, 'exposure', $2, 0)",
    [current.tenantId, records.length],
  ));
  return { status: 200, body: { exposures: records } };
}

async function createAction(deps: ApiDeps, current: Actor, findingId: string, kind: string, preview: unknown): Promise<ApiResult> {
  if (!kind) return { status: 400, body: { error: "Choose an action." } };
  if (findingId) {
    const finding = await loadFinding(deps, current.tenantId!, findingId);
    if (!finding) return { status: 404, body: { error: "That record was not found." } };
  }
  const canonical = stableJson(preview);
  const previewHash = sha256(canonical);
  const inserted = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ id: string }>(
    `insert into actions (tenant_id, finding_id, kind, status, preview, preview_hash)
     values ($1, nullif($2, '')::uuid, $3, 'proposed', $4::jsonb, $5) returning id`,
    [current.tenantId, findingId, kind, canonical, previewHash],
  ));
  const id = inserted.rows[0]?.id ?? "";
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "action_proposed", targetType: "action", targetId: id });
  return { status: 200, body: { id, status: "proposed" } };
}

async function approveAction(deps: ApiDeps, current: Actor, role: string, id: string): Promise<ApiResult> {
  if (role !== "owner") return { status: 403, body: { error: "Only an owner can approve an action." } };
  const updated = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ id: string }>(
    `update actions set status = 'approved', approved_by = $2, approved_at = $3
     where id = $1 and status = 'proposed' returning id`,
    [id, current.userId, deps.now().toISOString()],
  ));
  if (!updated.rows[0]) return { status: 404, body: { error: "That record was not found." } };
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "action_approved", targetType: "action", targetId: id });
  return { status: 200, body: { id, status: "approved" } };
}

async function executeAction(deps: ApiDeps, current: Actor, id: string): Promise<ApiResult> {
  const rows = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{
    status: string; preview: unknown; preview_hash: string; finding_id: string | null;
  }>("select status, preview, preview_hash, finding_id from actions where id = $1", [id]));
  const row = rows.rows[0];
  if (!row) return { status: 404, body: { error: "That record was not found." } };
  if (row.status !== "approved") return { status: 409, body: { error: "An owner has to approve this action first." } };
  if (sha256(stableJson(row.preview)) !== row.preview_hash) return { status: 409, body: { error: "The action preview changed after approval." } };
  await withTenant(deps.db, current.tenantId!, async (tx) => {
    await tx.query("update actions set status = 'executed', executed_at = $2 where id = $1", [id, deps.now().toISOString()]);
    if (row.finding_id) {
      await tx.query(
        "insert into product_events (tenant_id, user_id, name, finding_id) values ($1, $2, 'finding_actioned', $3)",
        [current.tenantId, current.userId, row.finding_id],
      );
    }
  });
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "action_executed", targetType: "action", targetId: id });
  return { status: 200, body: { id, status: "executed" } };
}

async function connectM365(deps: ApiDeps, current: Actor, role: string, body: Record<string, unknown>): Promise<ApiResult> {
  if (role !== "owner") return { status: 403, body: { error: "Only an owner can connect Microsoft 365." } };
  const scopes = Array.isArray(body.scopes) ? body.scopes.filter((item) => typeof item === "string") as string[] : [];
  const token = str(body.refreshToken);
  if (!token) return { status: 400, body: { error: "A token is required." } };
  try {
    assertM365Scopes(scopes);
  } catch (error) {
    return { status: 400, body: { error: error instanceof Error ? error.message : "Those scopes are not allowed." } };
  }
  const sealed = sealIntegrationToken(token, scopes, deps.encryptionKey);
  await withTenant(deps.db, current.tenantId!, (tx) => tx.query(
    `insert into integration_tokens (tenant_id, provider, ciphertext, scopes)
     values ($1, 'm365', $2, $3)
     on conflict (tenant_id, provider) do update set ciphertext = excluded.ciphertext, scopes = excluded.scopes`,
    [current.tenantId, sealed.ciphertext, sealed.scopes],
  ));
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "m365_connected", metadata: { scopes: sealed.scopes } });
  return { status: 200, body: { stored: true, scopes: sealed.scopes } };
}

async function share(deps: ApiDeps, current: Actor, findingId: string): Promise<ApiResult> {
  if (!SHARING_LAUNCH_APPROVED && deps.sharingLaunchOverrideForTests !== true) {
    return { status: 403, body: { error: "Sharing is blocked until the community governance group endorses the rules" } };
  }
  const finding = await loadFinding(deps, current.tenantId!, findingId);
  if (!finding) return { status: 404, body: { error: "That record was not found." } };
  if (finding.cultural) return { status: 403, body: { error: "Cultural data cannot be shared." } };
  const prefs = await withTenant(deps.db, current.tenantId!, (tx) => tx.query<{ enabled: boolean }>(
    "select enabled from sharing_preferences where category = $1",
    [finding.kind],
  ));
  const enabled = Boolean(prefs.rows[0]?.enabled);
  let shared;
  try {
    shared = prepareShare({
      cultural: finding.cultural,
      categoryEnabled: enabled,
      approvedBy: current.userId,
      approvedAt: deps.now().toISOString(),
      launchApproved: true,
      tenantId: current.tenantId!,
      findingId,
      confidence: Number(finding.confidence),
      factors: Array.isArray(finding.confidence_factors) ? finding.confidence_factors as never : [],
      text: finding.plain_english_summary,
      secrets: { names: [], people: [], emails: [], hosts: [] },
    });
  } catch (error) {
    return { status: 403, body: { error: error instanceof Error ? error.message : "Sharing is off for this category." } };
  }
  const source = { sourceId: "community", url: "urn:community-cti:source:community", licence: "opt-in community warning", tlp: "TLP:GREEN" as const };
  const now = deps.now().toISOString();
  const indicator = buildIndicator({
    pattern: "[domain-name:value = 'shared.example']",
    name: "Community warning",
    confidence: Number(finding.confidence),
    source,
    now,
  });
  const report = buildReport({ name: shared.title, objectRefs: [indicator.id], source, now });
  await upsertStix(deps.db, indicator, null);
  await upsertStix(deps.db, report, null);
  await withTenant(deps.db, current.tenantId!, (tx) => tx.query(
    `insert into shared_items (tenant_id, finding_id, category, sanitised, approved_by, approved_at, stix_id)
     values ($1, $2, $3, $4::jsonb, $5, $6, $7)`,
    [current.tenantId, findingId, finding.kind, JSON.stringify({ summary: shared.plainEnglishSummary }), current.userId, now, report.id],
  ));
  await audit(deps.db, { tenantId: current.tenantId, actorId: current.userId, action: "finding_shared", targetType: "finding", targetId: findingId });
  return { status: 200, body: { stixId: report.id, summary: shared.plainEnglishSummary } };
}

async function spentThisMonth(deps: ApiDeps, tenantId: string): Promise<number> {
  const month = deps.now().toISOString().slice(0, 7);
  const rows = await withTenant(deps.db, tenantId, (tx) => tx.query<{ aud: string | number }>(
    "select coalesce(sum(aud), 0) as aud from cost_ledger where to_char(at at time zone 'UTC', 'YYYY-MM') = $1",
    [month],
  ));
  return Number(rows.rows[0]?.aud ?? 0);
}

async function limitFor(deps: ApiDeps, tenantId: string): Promise<number> {
  const rows = await withTenant(deps.db, tenantId, (tx) => tx.query<{ monthly_aud: string | number }>(
    "select monthly_aud from tenant_budgets where tenant_id = $1",
    [tenantId],
  ));
  if (!rows.rows[0]) return TIERS.community.monthlyAud;
  return Number(rows.rows[0].monthly_aud);
}

async function recordCost(deps: ApiDeps, current: Actor, category: string, units: number, aud: number): Promise<ApiResult> {
  if (!["agent", "exposure", "storage", "enrichment"].includes(category)) return { status: 400, body: { error: "That cost category is not recognised." } };
  if (!Number.isFinite(aud) || aud < 0) return { status: 400, body: { error: "Enter a cost amount." } };
  await withTenant(deps.db, current.tenantId!, (tx) => tx.query(
    "insert into cost_ledger (tenant_id, category, units, aud, at) values ($1, $2, $3, $4, $5)",
    [current.tenantId, category, units, aud, deps.now().toISOString()],
  ));
  const spent = await spentThisMonth(deps, current.tenantId!);
  const limit = await limitFor(deps, current.tenantId!);
  return { status: 200, body: { spent, limit, mode: processingMode(spent, limit) } };
}

async function investigate(deps: ApiDeps, current: Actor, findingId: string): Promise<ApiResult> {
  const finding = await loadFinding(deps, current.tenantId!, findingId);
  if (!finding) return { status: 404, body: { error: "That record was not found." } };
  const spent = await spentThisMonth(deps, current.tenantId!);
  const limit = await limitFor(deps, current.tenantId!);
  if (!finding.cultural && processingMode(spent, limit) === "deterministic") {
    return { status: 409, body: { error: "The monthly limit has been reached. This request stayed on the deterministic path.", mode: "deterministic" } };
  }
  const model = deps.model ?? scriptedModel({
    text: "{\"confidenceDelta\":5}",
    toolCalls: [{ name: "search_findings", arguments: {} }],
    tokensIn: 10,
    tokensOut: 8,
  });
  const result = await runAgent({
    role: "investigator",
    model,
    cultural: finding.cultural,
    user: "Review this finding and suggest a confidence change as JSON.",
    untrusted: [{ sourceId: "finding", text: finding.title }],
    tools: {
      search_findings: async () => withTenant(deps.db, current.tenantId!, (tx) => tx.query("select id from findings where status = 'open'")),
    },
  });
  let delta = 0;
  try {
    const parsed = JSON.parse(result.text) as { confidenceDelta?: number };
    delta = parsed.confidenceDelta ?? 0;
  } catch {
    delta = 0;
  }
  const next = applyInvestigation({ confidence: Number(finding.confidence), status: finding.status }, { confidenceDelta: delta, status: "dismissed" });
  if (result.status === "ok") {
    await withTenant(deps.db, current.tenantId!, (tx) => tx.query(
      "update findings set confidence = $2 where id = $1",
      [findingId, next.confidence],
    ));
  }
  const aud = result.status === "ok" ? 0.05 : 0;
  await withTenant(deps.db, current.tenantId!, async (tx) => {
    await tx.query(
      `insert into agent_runs (tenant_id, role, model, tokens_in, tokens_out, cost_aud, duration_ms, output_hash, status)
       values ($1, 'investigator', $2, $3, $4, $5, 0, $6, $7)`,
      [current.tenantId, result.model, result.tokensIn, result.tokensOut, aud, sha256(result.text), result.status],
    );
    if (aud > 0) {
      await tx.query(
        "insert into cost_ledger (tenant_id, category, units, aud, at) values ($1, 'agent', 1, $2, $3)",
        [current.tenantId, aud, deps.now().toISOString()],
      );
    }
  });
  const fresh = await loadFinding(deps, current.tenantId!, findingId);
  return {
    status: 200,
    body: {
      runStatus: result.status,
      confidence: fresh?.confidence ?? next.confidence,
      findingStatus: fresh?.status ?? finding.status,
    },
  };
}

function randomToken(): string {
  return randomUUID().replace(/-/g, "") + randomUUID().replace(/-/g, "");
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map((item) => stableJson(item)).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.keys(value as Record<string, unknown>).sort();
    return `{${entries.map((key) => `${JSON.stringify(key)}:${stableJson((value as Record<string, unknown>)[key])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
