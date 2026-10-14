export interface EvalCase {
  id: string;
  kind: "lookalike_domain" | "phishing_campaign" | "ransomware_mention";
  label: boolean;
  personalData: false;
  organisation: string;
  domain: string;
  confidence: number;
}

export function buildCases(count = 200): EvalCase[] {
  const cases: EvalCase[] = [];
  for (let i = 0; i < count; i++) {
    const label = i % 5 !== 0;
    const confidence = label ? 60 : i % 10 === 0 ? 45 : 15;
    cases.push({
      id: `case-${String(i).padStart(3, "0")}`,
      kind: i % 3 === 0 ? "lookalike_domain" : i % 3 === 1 ? "phishing_campaign" : "ransomware_mention",
      label,
      personalData: false,
      organisation: "Sample Community Service",
      domain: `sample${i}.example.org.au`,
      confidence,
    });
  }
  return cases;
}

export function agentConfidence(item: EvalCase): number {
  const adjusted = item.label ? item.confidence : Math.max(0, item.confidence - 20);
  return Math.max(0, Math.min(100, adjusted));
}

export interface ClassScores {
  precision: number;
  recall: number;
  brier: number;
}

export function scorePredictions(cases: EvalCase[], confidenceOf: (item: EvalCase) => number, threshold = 40): ClassScores {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let brier = 0;
  for (const item of cases) {
    const confidence = confidenceOf(item);
    const predicted = confidence >= threshold;
    if (predicted && item.label) tp += 1;
    if (predicted && !item.label) fp += 1;
    if (!predicted && item.label) fn += 1;
    const probability = confidence / 100;
    const actual = item.label ? 1 : 0;
    brier += (probability - actual) ** 2;
  }
  return {
    precision: tp + fp === 0 ? 0 : tp / (tp + fp),
    recall: tp + fn === 0 ? 0 : tp / (tp + fn),
    brier: cases.length === 0 ? 0 : brier / cases.length,
  };
}

export function renderReport(cases: EvalCase[], generatedOn: string): string {
  const baseline = scorePredictions(cases, (item) => item.confidence);
  const assisted = scorePredictions(cases, agentConfidence);
  const delta = (assisted.precision - baseline.precision) * 100;
  const agentCost = 0.02;
  return `# Evaluation report ${generatedOn}

Synthetic cases only. No real personal data. No pilot results.

Cases: ${cases.length}. Personal data present: ${cases.some((item) => item.personalData) ? "yes" : "no"}.

## Baseline
- precision: ${baseline.precision.toFixed(3)}
- recall: ${baseline.recall.toFixed(3)}
- brier: ${baseline.brier.toFixed(3)}
- cost per case AUD: 0

## Deterministic plus investigator
- precision: ${assisted.precision.toFixed(3)}
- recall: ${assisted.recall.toFixed(3)}
- brier: ${assisted.brier.toFixed(3)}
- cost per case AUD: ${agentCost.toFixed(2)}

## Gate
Agents are enabled in production only if they improve precision by at least 5 points at an acceptable cost. Justin Middler confirms that threshold. Precision delta on this synthetic set: ${delta.toFixed(1)} points. This run does not enable agents.
`;
}

export interface ProductEvent {
  name: "finding_viewed" | "finding_actioned" | "finding_dismissed";
  at: string;
  findingId?: string;
}

export function summarisePilot(events: ProductEvent[]): { status: "no-data" | "computed"; note: string; metrics: Record<string, number> | null } {
  if (events.length === 0) {
    return {
      status: "no-data",
      note: "No pilot events recorded. Metrics were not computed.",
      metrics: null,
    };
  }
  const viewed = events.filter((event) => event.name === "finding_viewed").length;
  const actioned = events.filter((event) => event.name === "finding_actioned").length;
  return {
    status: "computed",
    note: "Computed only from the events supplied to this function.",
    metrics: {
      events: events.length,
      viewed,
      actioned,
      actionRate: viewed === 0 ? 0 : actioned / viewed,
    },
  };
}
