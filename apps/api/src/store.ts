import { createHash, randomUUID } from "node:crypto";
import { canTransition, isDismissReason, type Finding, type Provenance } from "@community-cti/schema";
import type { ActionStatus } from "@community-cti/integrations";
import type { AdvisoryRecord, VictimRecord } from "./advisories.js";

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export interface Evidence {
  id: string;
  label: string;
  objectKey: string | null;
  url: string | null;
  collectedAt: string;
  sourceId: string;
  licence: string;
  tlp: Provenance["accessRestriction"];
}

export interface StoredFinding extends Finding {
  evidence: Evidence[];
}

export interface StoredAction {
  id: string;
  tenantId: string;
  findingId: string | null;
  kind: string;
  status: ActionStatus;
  preview: Record<string, unknown>;
  approvedBy: string | null;
  approvedAt: string | null;
}

export interface AuditRow {
  id: string;
  tenantId: string | null;
  actorId: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
}

export interface DomainRecord {
  id: string;
  tenantId: string;
  domain: string;
  status: string;
  token: string;
  verifiedAt: string | null;
  emailTokenHash: string | null;
}

export interface SessionRecord {
  userId: string;
  expiresAt: number;
  tenantId: string | null;
}

export interface ShareRecord {
  id: string;
  tenantId: string;
  cultural: boolean;
  approvedBy: string | null;
  sanitised: string;
}

export type NotifyMode = "immediate" | "digest" | "off";

/**
 * Persistence used by the API. Every tenant-scoped method takes the tenant id
 * first; the Postgres implementation runs it under row-level security for
 * that tenant, so a wrong id returns nothing rather than another tenant's row.
 */
export interface Repo {
  writeAudit(row: Omit<AuditRow, "id">): Promise<void>;

  createMagicLink(email: string, tokenHash: string, expiresAt: number): Promise<void>;
  consumeMagicLink(tokenHash: string, now: number): Promise<string | null>;
  findOrCreateUser(email: string): Promise<{ id: string; email: string }>;
  getUser(id: string): Promise<{ id: string; email: string } | null>;
  acceptInvites(userId: string, email: string): Promise<void>;
  userTenants(userId: string): Promise<Array<{ tenantId: string; name: string; role: string }>>;
  createSession(tokenHash: string, session: SessionRecord): Promise<void>;
  getSession(tokenHash: string): Promise<SessionRecord | null>;
  setSessionTenant(tokenHash: string, tenantId: string): Promise<void>;
  deleteSession(tokenHash: string): Promise<void>;

  createTenant(tenant: { id: string; name: string; orgType: string }, ownerId: string): Promise<void>;
  getTenant(tenantId: string): Promise<{ id: string; name: string; orgType: string } | null>;
  membership(tenantId: string, userId: string): Promise<{ role: string } | null>;
  setRole(tenantId: string, userId: string, role: string): Promise<boolean>;
  addInvite(tenantId: string, invite: { email: string; role: string; invitedBy: string }): Promise<void>;
  addConsent(tenantId: string, consent: { scope: string; grantorName: string; grantorRole: string; ip: string }): Promise<void>;
  hasConsent(tenantId: string): Promise<boolean>;
  revokeConsent(tenantId: string, at: string): Promise<void>;

  listDomains(tenantId: string): Promise<DomainRecord[]>;
  getDomain(tenantId: string, id: string): Promise<DomainRecord | null>;
  addDomain(row: DomainRecord): Promise<void>;
  updateDomain(tenantId: string, id: string, patch: Partial<Pick<DomainRecord, "status" | "verifiedAt" | "emailTokenHash">> & { method?: "dns_txt" | "email" }): Promise<void>;
  domainByEmailToken(tokenHash: string): Promise<{ id: string; tenantId: string } | null>;

  listFindings(tenantId: string): Promise<StoredFinding[]>;
  getFinding(tenantId: string, id: string): Promise<StoredFinding | null>;
  updateFinding(tenantId: string, id: string, patch: { status?: Finding["status"]; confidence?: number }): Promise<void>;
  addFeedback(tenantId: string, item: { findingId: string; actorId: string; action: string; reason?: string; comment?: string }): Promise<void>;
  addLegitimateDomain(tenantId: string, domain: string, findingId: string): Promise<void>;
  addOpinion(tenantId: string, findingId: string, opinion: string): Promise<void>;

  addAction(action: StoredAction & { proposedBy: string }): Promise<void>;
  getAction(tenantId: string, id: string): Promise<StoredAction | null>;
  updateAction(tenantId: string, id: string, patch: Partial<Pick<StoredAction, "status" | "approvedBy" | "approvedAt">>): Promise<void>;

  listExposures(tenantId: string): Promise<Array<{ id: string; breachName: string }>>;
  getExposure(tenantId: string, id: string): Promise<{ id: string; breachName: string } | null>;

  setIntegrationToken(tenantId: string, provider: string, ciphertext: string): Promise<void>;
  clearM365(tenantId: string): Promise<void>;

  listSharePrefs(tenantId: string): Promise<Array<{ category: string; enabled: boolean }>>;
  setSharePref(tenantId: string, category: string, enabled: boolean): Promise<void>;
  addShare(share: ShareRecord & { category: string; findingId: string | null }): Promise<void>;
  getShare(tenantId: string, id: string): Promise<ShareRecord | null>;
  approveShare(tenantId: string, id: string, approverId: string, at: string): Promise<void>;

  getNotify(tenantId: string, userId: string): Promise<NotifyMode | null>;
  setNotify(tenantId: string, userId: string, mode: NotifyMode): Promise<void>;
  costTotal(tenantId: string): Promise<number>;

  listAdvisories(tags: string[], since: string, limit: number): Promise<AdvisoryRecord[]>;
  listAuVictims(since: string): Promise<VictimRecord[]>;
}

/** In-memory Repo for tests and local experiments. Data is lost on restart. */
export class MemoryStore implements Repo {
  users = new Map<string, { id: string; email: string }>();
  sessions = new Map<string, SessionRecord>();
  magic = new Map<string, { email: string; expiresAt: number }>();
  tenants = new Map<string, { id: string; name: string; orgType: string }>();
  memberships: Array<{ tenantId: string; userId: string; role: string }> = [];
  consents: Array<{ tenantId: string; scope: string; grantorName: string; grantorRole: string; ip: string; revokedAt: string | null }> = [];
  domains: DomainRecord[] = [];
  findings: StoredFinding[] = [];
  feedback: Array<{ tenantId: string; findingId: string; action: string; reason?: string }> = [];
  allow: Array<{ tenantId: string; domain: string }> = [];
  actions: StoredAction[] = [];
  audit: AuditRow[] = [];
  exposures: Array<{ id: string; tenantId: string; emailCiphertext: string; breachName: string }> = [];
  tokens: Array<{ tenantId: string; provider: string; ciphertext: string }> = [];
  cachedUsers: Array<{ tenantId: string; upn: string }> = [];
  sharePrefs: Array<{ tenantId: string; category: string; enabled: boolean }> = [];
  shares: ShareRecord[] = [];
  notif: Array<{ tenantId: string; userId: string; mode: NotifyMode }> = [];
  costs: Array<{ tenantId: string; aud: number }> = [];
  invites: Array<{ tenantId: string; email: string; role: string; accepted?: boolean }> = [];
  opinions: Array<{ tenantId: string; findingId: string; opinion: string }> = [];
  advisories: AdvisoryRecord[] = [];
  auVictims: VictimRecord[] = [];

  async writeAudit(row: Omit<AuditRow, "id">): Promise<void> {
    this.audit.push({ ...row, id: randomUUID() });
  }

  async createMagicLink(email: string, tokenHash: string, expiresAt: number): Promise<void> {
    this.magic.set(tokenHash, { email, expiresAt });
  }

  async consumeMagicLink(tokenHash: string, now: number): Promise<string | null> {
    const link = this.magic.get(tokenHash);
    if (!link || link.expiresAt <= now) return null;
    this.magic.delete(tokenHash);
    return link.email;
  }

  async findOrCreateUser(email: string): Promise<{ id: string; email: string }> {
    const found = [...this.users.values()].find((item) => item.email === email);
    if (found) return found;
    const user = { id: randomUUID(), email };
    this.users.set(user.id, user);
    return user;
  }

  async getUser(id: string): Promise<{ id: string; email: string } | null> {
    return this.users.get(id) ?? null;
  }

  async acceptInvites(userId: string, email: string): Promise<void> {
    for (const invite of this.invites) {
      if (invite.accepted || invite.email.toLowerCase() !== email) continue;
      if (!this.memberships.some((item) => item.tenantId === invite.tenantId && item.userId === userId)) {
        this.memberships.push({ tenantId: invite.tenantId, userId, role: invite.role });
      }
      invite.accepted = true;
    }
  }

  async userTenants(userId: string): Promise<Array<{ tenantId: string; name: string; role: string }>> {
    return this.memberships
      .filter((item) => item.userId === userId)
      .map((item) => ({ tenantId: item.tenantId, name: this.tenants.get(item.tenantId)?.name ?? "", role: item.role }));
  }

  async createSession(tokenHash: string, session: SessionRecord): Promise<void> {
    this.sessions.set(tokenHash, session);
  }

  async getSession(tokenHash: string): Promise<SessionRecord | null> {
    return this.sessions.get(tokenHash) ?? null;
  }

  async setSessionTenant(tokenHash: string, tenantId: string): Promise<void> {
    const session = this.sessions.get(tokenHash);
    if (session) session.tenantId = tenantId;
  }

  async deleteSession(tokenHash: string): Promise<void> {
    this.sessions.delete(tokenHash);
  }

  async createTenant(tenant: { id: string; name: string; orgType: string }, ownerId: string): Promise<void> {
    this.tenants.set(tenant.id, tenant);
    this.memberships.push({ tenantId: tenant.id, userId: ownerId, role: "owner" });
  }

  async getTenant(tenantId: string): Promise<{ id: string; name: string; orgType: string } | null> {
    return this.tenants.get(tenantId) ?? null;
  }

  async membership(tenantId: string, userId: string): Promise<{ role: string } | null> {
    return this.memberships.find((item) => item.tenantId === tenantId && item.userId === userId) ?? null;
  }

  async setRole(tenantId: string, userId: string, role: string): Promise<boolean> {
    const member = this.memberships.find((item) => item.tenantId === tenantId && item.userId === userId);
    if (!member) return false;
    member.role = role;
    return true;
  }

  async addInvite(tenantId: string, invite: { email: string; role: string }): Promise<void> {
    this.invites.push({ tenantId, email: invite.email, role: invite.role });
  }

  async addConsent(tenantId: string, consent: { scope: string; grantorName: string; grantorRole: string; ip: string }): Promise<void> {
    this.consents.push({ tenantId, ...consent, revokedAt: null });
  }

  async hasConsent(tenantId: string): Promise<boolean> {
    return this.consents.some((item) => item.tenantId === tenantId && item.scope === "domain_monitoring" && !item.revokedAt);
  }

  async revokeConsent(tenantId: string, at: string): Promise<void> {
    for (const item of this.consents) if (item.tenantId === tenantId && !item.revokedAt) item.revokedAt = at;
  }

  async listDomains(tenantId: string): Promise<DomainRecord[]> {
    return this.domains.filter((item) => item.tenantId === tenantId);
  }

  async getDomain(tenantId: string, id: string): Promise<DomainRecord | null> {
    return this.domains.find((item) => item.id === id && item.tenantId === tenantId) ?? null;
  }

  async addDomain(row: DomainRecord): Promise<void> {
    this.domains.push(row);
  }

  async updateDomain(tenantId: string, id: string, patch: Partial<Pick<DomainRecord, "status" | "verifiedAt" | "emailTokenHash">>): Promise<void> {
    const row = this.domains.find((item) => item.id === id && item.tenantId === tenantId);
    if (!row) return;
    if (patch.status !== undefined) row.status = patch.status;
    if (patch.verifiedAt !== undefined) row.verifiedAt = patch.verifiedAt;
    if (patch.emailTokenHash !== undefined) row.emailTokenHash = patch.emailTokenHash;
  }

  async domainByEmailToken(tokenHash: string): Promise<{ id: string; tenantId: string } | null> {
    const row = this.domains.find((item) => item.emailTokenHash === tokenHash && item.status === "email_pending");
    return row ? { id: row.id, tenantId: row.tenantId } : null;
  }

  async listFindings(tenantId: string): Promise<StoredFinding[]> {
    return this.findings.filter((item) => item.tenantId === tenantId);
  }

  async getFinding(tenantId: string, id: string): Promise<StoredFinding | null> {
    return this.findings.find((item) => item.id === id && item.tenantId === tenantId) ?? null;
  }

  async updateFinding(tenantId: string, id: string, patch: { status?: Finding["status"]; confidence?: number }): Promise<void> {
    const row = this.findings.find((item) => item.id === id && item.tenantId === tenantId);
    if (!row) return;
    if (patch.status !== undefined) row.status = patch.status;
    if (patch.confidence !== undefined) row.confidence = patch.confidence;
  }

  async addFeedback(tenantId: string, item: { findingId: string; action: string; reason?: string; comment?: string }): Promise<void> {
    this.feedback.push({ tenantId, findingId: item.findingId, action: item.action, reason: item.reason ?? item.comment });
  }

  async addLegitimateDomain(tenantId: string, domain: string): Promise<void> {
    this.allow.push({ tenantId, domain });
  }

  async addOpinion(tenantId: string, findingId: string, opinion: string): Promise<void> {
    this.opinions.push({ tenantId, findingId, opinion });
  }

  async addAction(action: StoredAction): Promise<void> {
    const { proposedBy: _ignored, ...row } = action as StoredAction & { proposedBy?: string };
    this.actions.push(row);
  }

  async getAction(tenantId: string, id: string): Promise<StoredAction | null> {
    return this.actions.find((item) => item.id === id && item.tenantId === tenantId) ?? null;
  }

  async updateAction(tenantId: string, id: string, patch: Partial<Pick<StoredAction, "status" | "approvedBy" | "approvedAt">>): Promise<void> {
    const row = this.actions.find((item) => item.id === id && item.tenantId === tenantId);
    if (row) Object.assign(row, patch);
  }

  async listExposures(tenantId: string): Promise<Array<{ id: string; breachName: string }>> {
    return this.exposures.filter((item) => item.tenantId === tenantId).map((item) => ({ id: item.id, breachName: item.breachName }));
  }

  async getExposure(tenantId: string, id: string): Promise<{ id: string; breachName: string } | null> {
    const row = this.exposures.find((item) => item.id === id && item.tenantId === tenantId);
    return row ? { id: row.id, breachName: row.breachName } : null;
  }

  async setIntegrationToken(tenantId: string, provider: string, ciphertext: string): Promise<void> {
    this.tokens = this.tokens.filter((item) => !(item.tenantId === tenantId && item.provider === provider));
    this.tokens.push({ tenantId, provider, ciphertext });
  }

  async clearM365(tenantId: string): Promise<void> {
    this.tokens = this.tokens.filter((item) => !(item.tenantId === tenantId && item.provider === "m365"));
    this.cachedUsers = this.cachedUsers.filter((item) => item.tenantId !== tenantId);
  }

  async listSharePrefs(tenantId: string): Promise<Array<{ category: string; enabled: boolean }>> {
    return this.sharePrefs.filter((item) => item.tenantId === tenantId).map(({ category, enabled }) => ({ category, enabled }));
  }

  async setSharePref(tenantId: string, category: string, enabled: boolean): Promise<void> {
    this.sharePrefs = this.sharePrefs.filter((item) => !(item.tenantId === tenantId && item.category === category));
    this.sharePrefs.push({ tenantId, category, enabled });
  }

  async addShare(share: ShareRecord): Promise<void> {
    this.shares.push({ id: share.id, tenantId: share.tenantId, cultural: share.cultural, approvedBy: null, sanitised: share.sanitised });
  }

  async getShare(tenantId: string, id: string): Promise<ShareRecord | null> {
    return this.shares.find((item) => item.id === id && item.tenantId === tenantId) ?? null;
  }

  async approveShare(tenantId: string, id: string, approverId: string): Promise<void> {
    const row = this.shares.find((item) => item.id === id && item.tenantId === tenantId);
    if (row) row.approvedBy = approverId;
  }

  async getNotify(tenantId: string, userId: string): Promise<NotifyMode | null> {
    return this.notif.find((item) => item.tenantId === tenantId && item.userId === userId)?.mode ?? null;
  }

  async setNotify(tenantId: string, userId: string, mode: NotifyMode): Promise<void> {
    this.notif = this.notif.filter((item) => !(item.tenantId === tenantId && item.userId === userId));
    this.notif.push({ tenantId, userId, mode });
  }

  async costTotal(tenantId: string): Promise<number> {
    return this.costs.filter((item) => item.tenantId === tenantId).reduce((sum, item) => sum + item.aud, 0);
  }

  async listAdvisories(tags: string[], since: string, limit: number): Promise<AdvisoryRecord[]> {
    return this.advisories
      .filter((item) => item.publishedAt >= since && item.tags.some((tag) => tags.includes(tag)))
      .sort((a, b) => b.publishedAt.localeCompare(a.publishedAt))
      .slice(0, limit);
  }

  async listAuVictims(since: string): Promise<VictimRecord[]> {
    return this.auVictims.filter((item) => item.discoveredAt >= since);
  }
}

export function assertTransition(finding: StoredFinding, to: Finding["status"]): void {
  if (!canTransition(finding.status, to)) {
    const error = new Error("invalid transition");
    (error as Error & { statusCode?: number }).statusCode = 409;
    throw error;
  }
}

export { isDismissReason };
