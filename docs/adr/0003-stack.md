# ADR 0003: Application stack and monorepo

- Status: Accepted (skeleton); revisit after ADR 0001
- Date: 2026-10-13

## Decision
- **Language:** TypeScript on Node.js 22 across API, portal, collectors and agent orchestration.
- **Monorepo:** pnpm workspaces (`apps/*`, `packages/*`).
- **API:** Node HTTP in the skeleton; Fastify planned for Phase 1 with schema validation.
- **Portal:** Next.js planned (server-rendered, accessible, low JS where possible).
- **Database:** PostgreSQL 16 with row-level security; migrations with plain SQL files under `db/migrations`.
- **Search:** OpenSearch for indicator and full-text search.
- **Object storage:** S3-compatible in an AU region for raw evidence.
- **Queue:** PostgreSQL-backed job queue (pg-boss) to avoid extra infrastructure early.
- **Tests:** Node's built-in test runner.

## Reasons
- One language keeps the team small and lets shared types (the finding and provenance model) be enforced end to end.
- Strong typing helps less experienced contributors and coding agents produce correct code.
- PostgreSQL row-level security gives database-enforced tenant isolation.
- Fewer moving parts keeps hosting cost low, which matters for free community tiers.

## Trade-offs
- Python has richer CTI libraries (pycti, pymisp, stix2). If ADR 0001 picks OpenCTI or MISP, a small Python worker package may be added for connector code. STIX objects will be validated against the official JSON schemas from TypeScript.
