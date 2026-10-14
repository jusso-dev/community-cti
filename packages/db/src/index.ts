export { migrate, migrationsDir, type Queryable } from "./migrate.js";
export { withTenant, type TenantClient } from "./tenant.js";
export { audit, type AuditEvent } from "./audit.js";
export {
  isVerified,
  assertVerifiedDomain,
  isRoleAddress,
  reverifyDecision,
  LAPSE_AFTER_MS,
  type DomainRow,
  type ReverifyState,
} from "./verified.js";
export { PostgresIntelStore } from "./intel-store.js";
