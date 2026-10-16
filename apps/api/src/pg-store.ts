import { randomUUID } from "node:crypto";
import type { Pool, PoolClient } from "pg";
import { withTenant } from "@community-cti/db";
import { buildOpinion, type Finding } from "@community-cti/schema";
import type { AdvisoryRecord, VictimRecord } from "./advisories.js";
import type { DomainRecord, Evidence, NotifyMode, Repo, SessionRecord, ShareRecord, StoredAction, StoredFinding } from "./store.js";

type Row = Record<string, unknown>;

function iso(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return value instanceof Date ? value.toISOString() : String(value);
}

function toDomain(row: Row): DomainRecord {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    domain: String(row.domain),
    status: String(row.status),
    token: String(row.verify_token),
    verifiedAt: iso(row.verified_at),
    emailTokenHash: (row.email_token_hash as string | null) ?? null,
  };
}

function toEvidence(row: Row): Evidence {
  return {
    id: String(row.id),
    label: String(row.label),
    objectKey: (row.object_key as string | null) ?? null,
    url: (row.url as string | null) ?? null,
    collectedAt: iso(row.collected_at) ?? "",
    sourceId: String(row.source_id),
    licence: String(row.licence),
    tlp: row.tlp as Evidence["tlp"],
  };
}

function toFinding(row: Row): StoredFinding {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    kind: row.kind as Finding["kind"],
    title: String(row.title),
    plainEnglishSummary: String(row.plain_english_summary),
    confidence: Number(row.confidence),
    status: row.status as Finding["status"],
    stixRefs: (row.stix_refs as string[]) ?? [],
    provenance: row.provenance as Finding["provenance"],
    confidenceFactors: row.confidence_factors as Finding["confidenceFactors"],
    createdAt: iso(row.created_at) ?? undefined,
    cultural: Boolean(row.cultural),
    evidence: ((row.evidence as Row[]) ?? []).map(toEvidence),
  };
}

function toAction(row: Row): StoredAction {
  return {
    id: String(row.id),
    tenantId: String(row.tenant_id),
    findingId: (row.finding_id as string | null) ?? null,
    kind: String(row.kind),
    status: row.status as StoredAction["status"],
    preview: row.preview as Record<string, unknown>,
    approvedBy: (row.approved_by as string | null) ?? null,
    approvedAt: iso(row.approved_at),
  };
}

const FINDING_SELECT = `
  select f.*, coalesce(
    (select json_agg(e order by e.collected_at) from finding_evidence e where e.finding_id = f.id),
    '[]'::json
  ) as evidence
  from findings f`;

/**
 * Postgres Repo. The pool must log in as cti_app, which has no BYPASSRLS:
 * tenant isolation is enforced by row-level security, not only by the
 * tenant id in each query.
 */
export class PgStore implements Repo {
  constructor(private readonly pool: Pool) {}

  private tenant<T>(tenantId: string, fn: (client: PoolClient) => Promise<T>): Promise<T> {
    return withTenant(this.pool, tenantId, fn);
  }

  async writeAudit(row: { tenantId: string | null; actorId: string | null; action: string; targetType?: string; targetId?: string }): Promise<void> {
    const insert = (client: Pool | PoolClient) => client.query(
      "insert into audit_log (id, tenant_id, actor_id, action, target_type, target_id) values ($1, $2, $3, $4, $5, $6)",
      [randomUUID(), row.tenantId, row.actorId, row.action, row.targetType ?? null, row.targetId ?? null],
    );
    if (row.tenantId) await this.tenant(row.tenantId, insert);
    else await insert(this.pool);
  }

  async createMagicLink(email: string, tokenHash: string, expiresAt: number): Promise<void> {
    await this.pool.query("insert into magic_links (id, email, token_hash, expires_at) values ($1, $2, $3, $4)", [
      randomUUID(), email, tokenHash, new Date(expiresAt),
    ]);
  }

  async consumeMagicLink(tokenHash: string, now: number): Promise<string | null> {
    const result = await this.pool.query(
      "update magic_links set consumed_at = $2 where token_hash = $1 and consumed_at is null and expires_at > $2 returning email",
      [tokenHash, new Date(now)],
    );
    return (result.rows[0]?.email as string | undefined) ?? null;
  }

  async findOrCreateUser(email: string): Promise<{ id: string; email: string }> {
    const result = await this.pool.query(
      "insert into users (id, email) values ($1, $2) on conflict (email) do update set email = excluded.email returning id, email",
      [randomUUID(), email],
    );
    return { id: String(result.rows[0]!.id), email: String(result.rows[0]!.email) };
  }

  async getUser(id: string): Promise<{ id: string; email: string } | null> {
    const result = await this.pool.query("select id, email from users where id = $1", [id]);
    const row = result.rows[0];
    return row ? { id: String(row.id), email: String(row.email) } : null;
  }

  async acceptInvites(userId: string, email: string): Promise<void> {
    await this.pool.query("select cti_accept_invites($1, $2)", [userId, email]);
  }

  async userTenants(userId: string): Promise<Array<{ tenantId: string; name: string; role: string }>> {
    const result = await this.pool.query("select tenant_id, name, role from cti_user_tenants($1)", [userId]);
    return result.rows.map((row) => ({ tenantId: String(row.tenant_id), name: String(row.name), role: String(row.role) }));
  }

  async createSession(tokenHash: string, session: SessionRecord): Promise<void> {
    await this.pool.query(
      "insert into sessions (id, user_id, token_hash, expires_at, active_tenant_id) values ($1, $2, $3, $4, $5)",
      [randomUUID(), session.userId, tokenHash, new Date(session.expiresAt), session.tenantId],
    );
  }

  async getSession(tokenHash: string): Promise<SessionRecord | null> {
    const result = await this.pool.query("select user_id, expires_at, active_tenant_id from sessions where token_hash = $1", [tokenHash]);
    const row = result.rows[0];
    if (!row) return null;
    return {
      userId: String(row.user_id),
      expiresAt: (row.expires_at as Date).getTime(),
      tenantId: (row.active_tenant_id as string | null) ?? null,
    };
  }

  async setSessionTenant(tokenHash: string, tenantId: string): Promise<void> {
    await this.pool.query("update sessions set active_tenant_id = $2 where token_hash = $1", [tokenHash, tenantId]);
  }

  async deleteSession(tokenHash: string): Promise<void> {
    await this.pool.query("delete from sessions where token_hash = $1", [tokenHash]);
  }

  async createTenant(tenant: { id: string; name: string; orgType: string }, ownerId: string): Promise<void> {
    await this.tenant(tenant.id, async (client) => {
      await client.query("insert into tenants (id, name, org_type) values ($1, $2, $3)", [tenant.id, tenant.name, tenant.orgType]);
      await client.query("insert into memberships (id, tenant_id, user_id, role) values ($1, $2, $3, 'owner')", [randomUUID(), tenant.id, ownerId]);
    });
  }

  async getTenant(tenantId: string): Promise<{ id: string; name: string; orgType: string } | null> {
    const rows = await this.tenant(tenantId, (client) => client.query("select id, name, org_type from tenants where id = $1", [tenantId]));
    const row = rows.rows[0];
    return row ? { id: String(row.id), name: String(row.name), orgType: String(row.org_type) } : null;
  }

  async membership(tenantId: string, userId: string): Promise<{ role: string } | null> {
    const rows = await this.tenant(tenantId, (client) => client.query("select role from memberships where tenant_id = $1 and user_id = $2", [tenantId, userId]));
    const row = rows.rows[0];
    return row ? { role: String(row.role) } : null;
  }

  async setRole(tenantId: string, userId: string, role: string): Promise<boolean> {
    const rows = await this.tenant(tenantId, (client) => client.query("update memberships set role = $3 where tenant_id = $1 and user_id = $2", [tenantId, userId, role]));
    return (rows.rowCount ?? 0) > 0;
  }

  async addInvite(tenantId: string, invite: { email: string; role: string; invitedBy: string }): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      "insert into invites (id, tenant_id, email, role, invited_by) values ($1, $2, $3, $4, $5)",
      [randomUUID(), tenantId, invite.email, invite.role, invite.invitedBy],
    ));
  }

  async addConsent(tenantId: string, consent: { scope: string; grantorName: string; grantorRole: string; ip: string }): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      "insert into consents (id, tenant_id, scope, grantor_name, grantor_role, ip) values ($1, $2, $3, $4, $5, $6)",
      [randomUUID(), tenantId, consent.scope, consent.grantorName, consent.grantorRole, consent.ip],
    ));
  }

  async hasConsent(tenantId: string): Promise<boolean> {
    const rows = await this.tenant(tenantId, (client) => client.query(
      "select 1 from consents where tenant_id = $1 and scope = 'domain_monitoring' and revoked_at is null limit 1",
      [tenantId],
    ));
    return rows.rows.length > 0;
  }

  async revokeConsent(tenantId: string, at: string): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      "update consents set revoked_at = $2 where tenant_id = $1 and revoked_at is null",
      [tenantId, at],
    ));
  }

  async listDomains(tenantId: string): Promise<DomainRecord[]> {
    const rows = await this.tenant(tenantId, (client) => client.query("select * from verified_domains where tenant_id = $1 order by created_at", [tenantId]));
    return rows.rows.map(toDomain);
  }

  async getDomain(tenantId: string, id: string): Promise<DomainRecord | null> {
    const rows = await this.tenant(tenantId, (client) => client.query("select * from verified_domains where tenant_id = $1 and id = $2", [tenantId, id]));
    return rows.rows[0] ? toDomain(rows.rows[0]) : null;
  }

  async addDomain(row: DomainRecord): Promise<void> {
    await this.tenant(row.tenantId, (client) => client.query(
      "insert into verified_domains (id, tenant_id, domain, status, verify_token) values ($1, $2, $3, $4, $5)",
      [row.id, row.tenantId, row.domain, row.status, row.token],
    ));
  }

  async updateDomain(tenantId: string, id: string, patch: Partial<Pick<DomainRecord, "status" | "verifiedAt" | "emailTokenHash">> & { method?: "dns_txt" | "email" }): Promise<void> {
    const sets: string[] = [];
    const values: unknown[] = [tenantId, id];
    const add = (column: string, value: unknown) => {
      values.push(value);
      sets.push(`${column} = $${values.length}`);
    };
    if (patch.status !== undefined) add("status", patch.status);
    if (patch.verifiedAt !== undefined) add("verified_at", patch.verifiedAt);
    if (patch.emailTokenHash !== undefined) add("email_token_hash", patch.emailTokenHash);
    if (patch.method !== undefined) add("method", patch.method);
    if (patch.status === "verified") sets.push("txt_missing_since = null");
    if (sets.length === 0) return;
    await this.tenant(tenantId, (client) => client.query(`update verified_domains set ${sets.join(", ")} where tenant_id = $1 and id = $2`, values));
  }

  async domainByEmailToken(tokenHash: string): Promise<{ id: string; tenantId: string } | null> {
    const result = await this.pool.query("select id, tenant_id from cti_domain_by_email_token($1)", [tokenHash]);
    const row = result.rows[0];
    return row ? { id: String(row.id), tenantId: String(row.tenant_id) } : null;
  }

  async listFindings(tenantId: string): Promise<StoredFinding[]> {
    const rows = await this.tenant(tenantId, (client) => client.query(
      `${FINDING_SELECT} where f.tenant_id = $1 order by f.confidence desc, f.created_at desc limit 500`,
      [tenantId],
    ));
    return rows.rows.map(toFinding);
  }

  async getFinding(tenantId: string, id: string): Promise<StoredFinding | null> {
    const rows = await this.tenant(tenantId, (client) => client.query(`${FINDING_SELECT} where f.tenant_id = $1 and f.id = $2`, [tenantId, id]));
    return rows.rows[0] ? toFinding(rows.rows[0]) : null;
  }

  async updateFinding(tenantId: string, id: string, patch: { status?: Finding["status"]; confidence?: number }): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      `update findings set status = coalesce($3, status), confidence = coalesce($4, confidence), updated_at = now()
       where tenant_id = $1 and id = $2`,
      [tenantId, id, patch.status ?? null, patch.confidence ?? null],
    ));
  }

  async addFeedback(tenantId: string, item: { findingId: string; actorId: string; action: string; reason?: string; comment?: string }): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      "insert into finding_feedback (id, tenant_id, finding_id, actor_id, action, reason, comment) values ($1, $2, $3, $4, $5, $6, $7)",
      [randomUUID(), tenantId, item.findingId, item.actorId, item.action, item.reason ?? null, item.comment ?? null],
    ));
  }

  async addLegitimateDomain(tenantId: string, domain: string, findingId: string): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      "insert into legitimate_domains (id, tenant_id, domain, finding_id) values ($1, $2, $3, $4) on conflict (tenant_id, domain) do nothing",
      [randomUUID(), tenantId, domain, findingId],
    ));
  }

  async addOpinion(tenantId: string, findingId: string, opinion: string): Promise<void> {
    const object = buildOpinion({
      sourceId: "community-cti",
      licence: "Tenant feedback",
      collectedAt: new Date(),
      opinion: opinion as Parameters<typeof buildOpinion>[0]["opinion"],
      objectRefs: [`x-community-cti-finding--${findingId}`],
      explanation: "Feedback from the organisation on one of its findings.",
    });
    await this.tenant(tenantId, (client) => client.query(
      "insert into stix_objects (id, tenant_id, type, confidence, body) values ($1, $2, $3, null, $4::jsonb)",
      [object.id, tenantId, object.type, JSON.stringify(object)],
    ));
  }

  async addAction(action: StoredAction & { proposedBy: string }): Promise<void> {
    await this.tenant(action.tenantId, (client) => client.query(
      `insert into actions (id, tenant_id, finding_id, kind, status, preview, payload, proposed_by)
       values ($1, $2, $3, $4, $5, $6::jsonb, $6::jsonb, $7)`,
      [action.id, action.tenantId, action.findingId, action.kind, action.status, JSON.stringify(action.preview), action.proposedBy],
    ));
  }

  async getAction(tenantId: string, id: string): Promise<StoredAction | null> {
    const rows = await this.tenant(tenantId, (client) => client.query("select * from actions where tenant_id = $1 and id = $2", [tenantId, id]));
    return rows.rows[0] ? toAction(rows.rows[0]) : null;
  }

  async updateAction(tenantId: string, id: string, patch: Partial<Pick<StoredAction, "status" | "approvedBy" | "approvedAt">>): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      `update actions set status = coalesce($3, status), approved_by = coalesce($4, approved_by), approved_at = coalesce($5, approved_at),
       executed_at = case when $3 = 'executed' then now() else executed_at end
       where tenant_id = $1 and id = $2`,
      [tenantId, id, patch.status ?? null, patch.approvedBy ?? null, patch.approvedAt ?? null],
    ));
  }

  async listExposures(tenantId: string): Promise<Array<{ id: string; breachName: string }>> {
    const rows = await this.tenant(tenantId, (client) => client.query("select id, breach_name from credential_exposures where tenant_id = $1 order by created_at desc", [tenantId]));
    return rows.rows.map((row) => ({ id: String(row.id), breachName: String(row.breach_name) }));
  }

  async getExposure(tenantId: string, id: string): Promise<{ id: string; breachName: string } | null> {
    const rows = await this.tenant(tenantId, (client) => client.query("select id, breach_name from credential_exposures where tenant_id = $1 and id = $2", [tenantId, id]));
    const row = rows.rows[0];
    return row ? { id: String(row.id), breachName: String(row.breach_name) } : null;
  }

  async setIntegrationToken(tenantId: string, provider: string, ciphertext: string): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      `insert into integration_tokens (id, tenant_id, provider, ciphertext) values ($1, $2, $3, $4)
       on conflict (tenant_id, provider) do update set ciphertext = excluded.ciphertext, updated_at = now()`,
      [randomUUID(), tenantId, provider, ciphertext],
    ));
  }

  async clearM365(tenantId: string): Promise<void> {
    await this.tenant(tenantId, async (client) => {
      await client.query("delete from integration_tokens where tenant_id = $1 and provider = 'm365'", [tenantId]);
      await client.query("delete from m365_cached_users where tenant_id = $1", [tenantId]);
      await client.query("delete from m365_cached_domains where tenant_id = $1", [tenantId]);
    });
  }

  async listSharePrefs(tenantId: string): Promise<Array<{ category: string; enabled: boolean }>> {
    const rows = await this.tenant(tenantId, (client) => client.query("select category, enabled from sharing_preferences where tenant_id = $1 order by category", [tenantId]));
    return rows.rows.map((row) => ({ category: String(row.category), enabled: Boolean(row.enabled) }));
  }

  async setSharePref(tenantId: string, category: string, enabled: boolean): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      `insert into sharing_preferences (tenant_id, category, enabled) values ($1, $2, $3)
       on conflict (tenant_id, category) do update set enabled = excluded.enabled`,
      [tenantId, category, enabled],
    ));
  }

  async addShare(share: ShareRecord & { category: string; findingId: string | null }): Promise<void> {
    await this.tenant(share.tenantId, (client) => client.query(
      "insert into shared_items (id, tenant_id, finding_id, category, sanitised, cultural) values ($1, $2, $3, $4, $5::jsonb, $6)",
      [share.id, share.tenantId, share.findingId, share.category, JSON.stringify({ text: share.sanitised }), share.cultural],
    ));
  }

  async getShare(tenantId: string, id: string): Promise<ShareRecord | null> {
    const rows = await this.tenant(tenantId, (client) => client.query("select * from shared_items where tenant_id = $1 and id = $2", [tenantId, id]));
    const row = rows.rows[0];
    if (!row) return null;
    return {
      id: String(row.id),
      tenantId: String(row.tenant_id),
      cultural: Boolean(row.cultural),
      approvedBy: (row.approved_by as string | null) ?? null,
      sanitised: String((row.sanitised as { text?: string }).text ?? ""),
    };
  }

  async approveShare(tenantId: string, id: string, approverId: string, at: string): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      "update shared_items set approved_by = $3, approved_at = $4 where tenant_id = $1 and id = $2",
      [tenantId, id, approverId, at],
    ));
  }

  async getNotify(tenantId: string, userId: string): Promise<NotifyMode | null> {
    const rows = await this.tenant(tenantId, (client) => client.query("select mode from notification_preferences where tenant_id = $1 and user_id = $2", [tenantId, userId]));
    return (rows.rows[0]?.mode as NotifyMode | undefined) ?? null;
  }

  async setNotify(tenantId: string, userId: string, mode: NotifyMode): Promise<void> {
    await this.tenant(tenantId, (client) => client.query(
      `insert into notification_preferences (id, tenant_id, user_id, mode) values ($1, $2, $3, $4)
       on conflict (tenant_id, user_id) do update set mode = excluded.mode`,
      [randomUUID(), tenantId, userId, mode],
    ));
  }

  async costTotal(tenantId: string): Promise<number> {
    const rows = await this.tenant(tenantId, (client) => client.query("select coalesce(sum(aud), 0) as total from cost_ledger where tenant_id = $1", [tenantId]));
    return Number(rows.rows[0]?.total ?? 0);
  }

  async listAdvisories(tags: string[], since: string, limit: number): Promise<AdvisoryRecord[]> {
    const result = await this.pool.query(
      `select id, source_id, title, url, summary, published_at, cves, tags, attack_techniques, licence
       from advisories where published_at >= $1 and tags && $2::text[]
       order by published_at desc limit $3`,
      [since, tags, limit],
    );
    return result.rows.map((row) => ({
      id: String(row.id),
      sourceId: String(row.source_id),
      title: String(row.title),
      url: String(row.url),
      summary: String(row.summary),
      publishedAt: iso(row.published_at) ?? "",
      cves: row.cves as string[],
      tags: row.tags as string[],
      attackTechniques: row.attack_techniques as string[],
      licence: String(row.licence),
    }));
  }

  async listAuVictims(since: string): Promise<VictimRecord[]> {
    const result = await this.pool.query(
      "select activity, group_name, discovered_at from au_ransomware_victims where discovered_at >= $1",
      [since],
    );
    return result.rows.map((row) => ({
      activity: (row.activity as string | null) ?? null,
      groupName: String(row.group_name),
      discoveredAt: iso(row.discovered_at) ?? "",
    }));
  }
}
