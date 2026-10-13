# ADR 0002: Apache-2.0 licence

- Status: Accepted
- Date: 2026-10-13

## Context
The project aims to be reusable by community organisations, councils, government and security vendors, and may integrate with OpenCTI (Apache-2.0) and MISP (AGPL-3.0).

## Decision
Use Apache-2.0 rather than MIT.

## Reasons
- Explicit patent grant and patent retaliation clause, which matters for a security product that government and larger organisations may adopt or sponsor.
- Same licence as OpenCTI community edition and many CTI tools, which simplifies combining code.
- Still permissive, so community organisations and partners can self-host or extend it.
- NOTICE file mechanism helps preserve attribution for co-designed content.

## Consequences
Contributors license their contributions under Apache-2.0. Any MISP code reuse must stay in a separate process boundary because of AGPL-3.0.
