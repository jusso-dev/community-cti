import { LOOKALIKE_WEIGHTS } from "../packages/intel/dist/match/score.js";

const report = {
  changed: false,
  weights: LOOKALIKE_WEIGHTS,
  note: "This script does not modify score weights.",
};

console.log(JSON.stringify(report, null, 2));
