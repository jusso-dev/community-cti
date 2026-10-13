# ADR 0006: Agent boundaries and human approval

- Status: Accepted
- Date: 2026-10-13

## Decision

| Role | Implementation | May use LLM | Tools | May act externally |
|---|---|---|---|---|
| Collectors | Deterministic code | No | Source APIs in SOURCES.md | No |
| Enrichment workers | Deterministic code | No | Allow-listed lookups (DNS, WHOIS, CT, CVE) | No |
| Investigator agents | LLM orchestration | Yes | Read-only queries on the tenant's graph and allow-listed enrichment | No |
| Analyst agents | LLM orchestration | Yes | Read-only; writes draft findings and remediation proposals | No |
| Humans | Portal users and analysts | n/a | Approve, dismiss, challenge, execute | Yes |

## Rules
1. Conventional code for ingestion, parsing, validation and deduplication.
2. AI only where it adds measurable value, measured against a labelled evaluation set.
3. Agents output structured JSON validated against `packages/schema`; every claim must cite stored evidence ids.
4. Consequential remediation (blocking, takedowns, password resets, M365 changes) needs explicit human approval recorded in `actions` with approver and timestamp.
5. Ingested content is untrusted; see `docs/THREAT-MODEL.md`.
6. Per-tenant budgets cap inference cost.
