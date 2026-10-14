import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";

export interface AuditEvent {
  tenantId: string | null;
  actorId: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  metadata?: Record<string, unknown>;
}

export async function audit(client: PoolClient, event: AuditEvent): Promise<string> {
  const id = randomUUID();
  await client.query(
    `insert into audit_log (id, tenant_id, actor_id, action, target_type, target_id, metadata)
     values ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
    [
      id,
      event.tenantId,
      event.actorId,
      event.action,
      event.targetType ?? null,
      event.targetId ?? null,
      JSON.stringify(event.metadata ?? {}),
    ],
  );
  return id;
}
