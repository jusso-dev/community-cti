# ADR 0001: Intelligence platform foundation: OpenCTI vs MISP vs custom

- Status: **Accepted** (decision owner: Justin Middler)
- Date: 2026-10-14

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
**ThreatSieve is the shared intelligence source.** Community CTI does not run OpenCTI or MISP.

ThreatSieve already collects, normalises and publishes STIX. Community CTI reads that shared intelligence over ThreatSieve's tenant-authenticated TAXII 2.1 API (`THREATSIEVE_TAXII_URL`, bearer key with `intel:read`). Objects are stored in the PostgreSQL `IntelStore` with a null tenant id. Tenant findings, credentials, cultural data and sightings are not sent to ThreatSieve. The request is a read of an allow-listed collection URL.

OpenCTI and MISP remain available inside ThreatSieve's own connectors. They are not a second backbone for this product.
