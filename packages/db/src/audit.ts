import type { Db } from "./types.js";
import { withTenant } from "./tenant.js";

export interface AuditEvent {
  tenantId: string | null;
  actorId?: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  metadata?: Record<string, unknown>;
}

export async function audit(db: Db, event: AuditEvent): Promise<void> {
  const write = async (tx: Db) => {
    await tx.query(
      `insert into audit_log (tenant_id, actor_id, action, target_type, target_id, metadata)
       values ($1, $2, $3, $4, $5, $6::jsonb)`,
      [
        event.tenantId,
        event.actorId ?? null,
        event.action,
        event.targetType ?? null,
        event.targetId ?? null,
        JSON.stringify(event.metadata ?? {}),
      ],
    );
  };
  if (event.tenantId) await withTenant(db, event.tenantId, write);
  else {
    await db.withTransaction(async (tx) => {
      await tx.query("set local role cti_app");
      await write(tx);
    });
  }
}
