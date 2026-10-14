export type ActionStatus = "proposed" | "approved" | "executed" | "failed" | "cancelled";

export interface RemediationAction {
  id: string;
  tenantId: string;
  status: ActionStatus;
  preview: Record<string, unknown>;
  approvedBy: string | null;
  approvedAt: string | null;
}

export function canTransitionAction(from: ActionStatus, to: ActionStatus): boolean {
  const allowed: Record<ActionStatus, ActionStatus[]> = {
    proposed: ["approved", "cancelled"],
    approved: ["executed", "failed", "cancelled"],
    executed: [],
    failed: [],
    cancelled: [],
  };
  return allowed[from].includes(to);
}

export function executeAction(action: RemediationAction, apply: (preview: Record<string, unknown>) => void): { status: "executed"; applied: Record<string, unknown> } {
  if (action.status !== "approved" || !action.approvedBy || !action.approvedAt) {
    throw new Error("refusing to execute without stored human approval");
  }
  apply(action.preview);
  return { status: "executed", applied: action.preview };
}
