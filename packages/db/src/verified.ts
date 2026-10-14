export interface DomainRow {
  status: string;
  verifiedAt: string | null;
}

/** Collectors, matching and credential lookups must call this before using a domain. */
export function isVerified(row: DomainRow | null | undefined): boolean {
  return !!row && row.status === "verified" && !!row.verifiedAt;
}

export function assertVerifiedDomain(row: DomainRow | null | undefined, domain: string): void {
  if (!isVerified(row)) {
    throw new Error(`Domain ${domain} is not verified for this organisation`);
  }
}

const ROLE_LOCALS = new Set(["admin", "postmaster", "webmaster"]);

export function isRoleAddress(email: string, domain: string): boolean {
  const [local, host] = email.toLowerCase().split("@");
  return host === domain.toLowerCase() && ROLE_LOCALS.has(local ?? "");
}

export const LAPSE_AFTER_MS = 14 * 24 * 60 * 60 * 1000;

export interface ReverifyState {
  status: "pending" | "email_pending" | "verified" | "lapsed";
  txtMissingSince: string | null;
}

export function reverifyDecision(
  state: ReverifyState,
  txtPresent: boolean,
  now: Date,
): ReverifyState {
  if (state.status !== "verified") return state;
  if (txtPresent) return { status: "verified", txtMissingSince: null };
  if (!state.txtMissingSince) return { status: "verified", txtMissingSince: now.toISOString() };
  const missingFor = now.getTime() - new Date(state.txtMissingSince).getTime();
  if (missingFor >= LAPSE_AFTER_MS) return { status: "lapsed", txtMissingSince: state.txtMissingSince };
  return state;
}
