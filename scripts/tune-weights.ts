import { proposeWeightChanges, applyWeightChanges } from "../apps/api/src/weights.ts";

const proposal = proposeWeightChanges([]);
console.log(JSON.stringify({ proposal, applied: false }));
try {
  applyWeightChanges();
} catch (error) {
  console.log(error instanceof Error ? error.message : "not applied");
}
