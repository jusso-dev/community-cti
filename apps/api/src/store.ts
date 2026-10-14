import { createHash, randomUUID } from "node:crypto";
import { canTransition, isDismissReason, type Finding, type Provenance } from "@community-cti/schema";
import { canTransitionAction, type ActionStatus } from "@community-cti/integrations";

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

export class MemoryStore {
  users = new Map<string, { id: string; email: string }>();
  sessions = new Map<string, { userId: string; expiresAt: number; tenantId: string | null }>();
  magic = new Map<string, { email: string; expiresAt: number }>();
  tenants = new Map<string, { id: string; name: string; orgType: string }>();
  memberships: Array<{ tenantId: string; userId: string; role: string }> = [];
  consents: Array<{ tenantId: string; scope: string; grantorName: string; grantorRole: string; ip: string; revokedAt: string | null }> = [];
  domains: Array<{ id: string; tenantId: string; domain: string; status: string; token: string; verifiedAt: string | null; emailTokenHash: string | null }> = [];
  findings: StoredFinding[] = [];
  feedback: Array<{ tenantId: string; findingId: string; action: string; reason?: string }> = [];
  allow: Array<{ tenantId: string; domain: string }> = [];
  actions: StoredAction[] = [];
  audit: AuditRow[] = [];
  exposures: Array<{ id: string; tenantId: string; emailCiphertext: string; breachName: string }> = [];
  tokens: Array<{ tenantId: string; provider: string; ciphertext: string }> = [];
  cachedUsers: Array<{ tenantId: string; upn: string }> = [];
  sharePrefs: Array<{ tenantId: string; category: string; enabled: boolean }> = [];
  shares: Array<{ id: string; tenantId: string; cultural: boolean; approvedBy: string | null; sanitised: string }> = [];
  notif: Array<{ tenantId: string; userId: string; mode: "immediate" | "digest" | "off" }> = [];
  costs: Array<{ tenantId: string; aud: number }> = [];
  invites: Array<{ tenantId: string; email: string; role: string }> = [];
  opinions: Array<{ tenantId: string; findingId: string; opinion: string }> = [];

  writeAudit(row: Omit<AuditRow, "id">): void {
    this.audit.push({ ...row, id: randomUUID() });
  }

  membership(tenantId: string, userId: string) {
    return this.memberships.find((item) => item.tenantId === tenantId && item.userId === userId) ?? null;
  }

  hasConsent(tenantId: string): boolean {
    return this.consents.some((item) => item.tenantId === tenantId && item.scope === "domain_monitoring" && !item.revokedAt);
  }
}

export function transitionFinding(finding: StoredFinding, to: Finding["status"]): void {
  if (!canTransition(finding.status, to)) {
    const error = new Error("invalid transition");
    (error as Error & { statusCode?: number }).statusCode = 409;
    throw error;
  }
  finding.status = to;
}

export { isDismissReason };
