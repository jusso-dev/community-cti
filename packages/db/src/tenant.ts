import type { Db } from "./types.js";

const ROLES = new Set(["cti_app", "cti_worker"]);

export async function asRole<T>(db: Db, role: string, fn: (tx: Db) => Promise<T>): Promise<T> {
  if (!ROLES.has(role)) throw new Error(`refusing role ${role}`);
  return db.withTransaction(async (tx) => {
    await tx.query(`set local role ${role}`);
    return fn(tx);
  });
}

/** Runs fn as cti_app with app.tenant_id set for this transaction only. */
export async function withTenant<T>(db: Db, tenantId: string, fn: (tx: Db) => Promise<T>): Promise<T> {
  if (!/^[0-9a-f-]{36}$/i.test(tenantId)) throw new Error("tenantId must be a uuid");
  return db.withTransaction(async (tx) => {
    await tx.query("select set_config('app.tenant_id', $1, true)", [tenantId]);
    await tx.query("set local role cti_app");
    return fn(tx);
  });
}
