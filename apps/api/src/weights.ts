/** Proposals only. Applying a weight change needs a reviewed pull request. */
export function proposeWeightChanges(feedback: Array<{ factor: string; upheld: boolean }>): Record<string, number> {
  const proposal: Record<string, number> = {};
  for (const item of feedback) {
    proposal[item.factor] = (proposal[item.factor] ?? 0) + (item.upheld ? 1 : -1);
  }
  return proposal;
}

export function applyWeightChanges(): never {
  throw new Error("weight changes require a reviewed pull request");
}
