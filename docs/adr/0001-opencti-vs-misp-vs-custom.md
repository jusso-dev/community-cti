# ADR 0001: Intelligence platform foundation: OpenCTI vs MISP vs custom

- Status: **Proposed** (decision owner: Justin Middler)
- Date: 2026-10-13

## Context
We need a store for indicators, campaigns, vulnerabilities and relationships, with feed ingestion and STIX 2.1 support. Building everything ourselves is slow; adopting a platform brings its own operational weight and multi-tenancy limits.

## Options

### A. OpenCTI as the backbone
- Pros: native STIX 2.1 graph, rich connector ecosystem (CISA KEV, MISP, abuse.ch, CVE), GraphQL API, good relationship modelling.
- Cons: heavy (Elasticsearch/OpenSearch, Redis, RabbitMQ, MinIO), multi-tenancy is limited so tenant isolation must still live in our app, licence is Apache-2.0 for community edition but enterprise features differ, hosting cost per environment is significant.

### B. MISP as the backbone
- Pros: mature, lightweight, huge sharing community, sharing groups and distribution levels map well to opt-in community sharing, many default OSINT feeds.
- Cons: event-centric not graph-centric, STIX 2.1 via conversion, PHP stack, UI not suitable for end users, AGPL-3.0 implications if modified and exposed.

### C. Custom on PostgreSQL plus OpenSearch
- Pros: full control of tenancy, provenance and confidence, lean hosting, aligns with our schema.
- Cons: reimplement connectors and graph features, slower to reach coverage, more code to secure.

### D. Hybrid (suggested for consideration)
Custom tenant-scoped app (C) for findings and portal, with MISP used internally for feed aggregation and community sharing, or OpenCTI as an internal analyst graph. Shared intelligence flows in; tenant data never flows back without opt-in.

## Decision criteria
Tenant isolation, operating cost per month, STIX 2.1 fidelity, connector coverage for AU-relevant sources, licence compatibility with Apache-2.0, team skills, sharing-group support.

## Decision
Not yet made. Tracked in the `needs-decision` issue for this ADR. Phase 1 code keeps an `IntelStore` interface in `packages/schema` so either backend can be plugged in. Justin Middler is the decision owner. This ADR stays **Proposed**.

## Desk review (2026-10-13)

This is not a spike result. OpenCTI and MISP were not deployed. The machine used for this review had no local Docker daemon, and the shared homelab Docker engine was not used. No RAM, CPU, or setup time was measured. No cloud quote was collected. The figures below are not measurements and not prices.

| Option | What was run | RAM | Setup time | Monthly cost AUD |
|---|---|---|---|---|
| OpenCTI | Not deployed | Not measured | Not measured | Not quoted |
| MISP | Not deployed | Not measured | Not measured | Not quoted |
| Custom PostgreSQL and OpenSearch | Compose file only (`infra/docker-compose.yml`). It was not started. | OpenSearch heap in that file is 512 MB. Host RAM was not measured. | Not measured | Not quoted |

Published docs for OpenCTI describe a heavier stack (OpenSearch or Elasticsearch, Redis, RabbitMQ, MinIO, and workers) than the custom compose file. MISP is lighter and its sharing groups match opt-in distribution more closely than OpenCTI's organisation model. Neither point was checked by running the software here.

Recommendation to record, not a decision: keep findings in the custom PostgreSQL store behind `IntelStore` for Phase 1, and revisit MISP when the community governance group endorses sharing. Do not treat this paragraph as acceptance of ADR 0001.
