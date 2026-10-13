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
Not yet made. Tracked in the `needs-decision` issue for this ADR. Phase 1 code keeps a `IntelStore` interface in `packages/schema` so either backend can be plugged in.
