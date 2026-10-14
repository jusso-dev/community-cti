import { test } from "node:test";
import assert from "node:assert/strict";
import { agentConfidence, buildCases, renderReport, scorePredictions, summarisePilot } from "./metrics.js";

test("evaluation report compares baseline with agent assistance and has no personal data", () => {
  const cases = buildCases(200);
  assert.equal(cases.length, 200);
  assert.equal(cases.every((item) => item.personalData === false), true);
  assert.equal(cases.some((item) => item.domain.endsWith(".example.org.au")), true);
  const baseline = scorePredictions(cases, (item) => item.confidence);
  const assisted = scorePredictions(cases, agentConfidence);
  assert.ok(assisted.precision > baseline.precision);
  const report = renderReport(cases, "2026-10-14");
  assert.match(report, /Baseline/);
  assert.match(report, /Deterministic plus investigator/);
  assert.match(report, /does not enable agents/);
});

test("pilot metrics are not invented when there are no events", () => {
  const summary = summarisePilot([]);
  assert.equal(summary.status, "no-data");
  assert.equal(summary.metrics, null);
});
