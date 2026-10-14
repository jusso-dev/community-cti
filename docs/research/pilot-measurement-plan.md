# Pilot measurement plan

Draft for Justin. Not completed.

No pilot has been run. This page lists the measures only. It does not contain results.

| Measure | What to record | Where it will come from |
|---|---|---|
| Alert precision | Share of findings people confirm as real | Dismiss, challenge and analyst review |
| False positives | Findings dismissed or withdrawn, with the reason | `finding_feedback` |
| Time to triage | Time from alert to first view | `product_events` |
| Time to action | Time from alert to a recorded action | `product_events` and `actions` |
| Findings acted on | Share of open findings that are actioned, dismissed or challenged | Finding status |
| Ten-minute task | Whether a person with no security team can understand a real finding and choose a next step in under ten minutes | Observed task, notes stored outside the repo |
| Cost per organisation | Agent, enrichment, storage and API cost for the month | `cost_ledger` |
| User confidence | How sure people feel at the start and the end | A short conversation, not invented scores |

`pnpm metrics:pilot` prints that no pilot events are recorded. It does not fill these measures with sample numbers.
