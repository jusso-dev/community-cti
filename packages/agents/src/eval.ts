export interface EvalCase {
  id: string;
  baseline: number;
  scripted: number;
  label: "true" | "false";
}

function mix(seed: number): number {
  let value = seed >>> 0;
  value = Math.imul(value ^ (value >>> 15), value | 1);
  value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
  return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
}

/** 200 synthetic cases. The scripted score is the baseline plus five, capped at 100. */
export function syntheticCases(): EvalCase[] {
  const cases: EvalCase[] = [];
  for (let i = 0; i < 200; i += 1) {
    const baseline = Math.floor(mix(i + 1) * 90);
    cases.push({
      id: `case-${i}`,
      baseline,
      scripted: Math.min(100, baseline + 5),
      label: baseline >= 40 ? "true" : "false",
    });
  }
  return cases;
}

export interface EvalReport {
  provider: "scripted";
  cases: number;
  meanLift: number;
  agentsEnabled: false;
  recommendation: string;
}

export function runEval(cases = syntheticCases()): EvalReport {
  const lift = cases.reduce((sum, item) => sum + (item.scripted - item.baseline), 0) / cases.length;
  return {
    provider: "scripted",
    cases: cases.length,
    meanLift: Number(lift.toFixed(2)),
    agentsEnabled: false,
    recommendation: "Do not enable agents. A scripted model beat the baseline in this file. Justin Middler has not confirmed that agents should be turned on.",
  };
}

const isCli = process.argv[1]?.endsWith("eval.js");
if (isCli) {
  console.log(JSON.stringify(runEval(), null, 2));
}
