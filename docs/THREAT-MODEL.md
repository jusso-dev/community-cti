# Threat model

Method: STRIDE per component, reviewed each phase. Owners and status are tracked in issues labelled `area:security`.

## Assets
Tenant findings, verified domain lists, credential exposure records, M365 tokens, source API keys, consent records, audit log, community sharing pool.

## Trust boundaries
1. Internet to portal and API
2. API to database and search
3. Collectors to external sources (untrusted input)
4. Agents to model providers
5. Integrations (M365, SIEM, webhooks)

## Key threats and controls

### Tenant isolation
| Threat | Control |
|---|---|
| Missing tenant filter leaks another organisation's findings | PostgreSQL row-level security on every tenant table; `app.tenant_id` set per transaction; CI test that queries as tenant A cannot see tenant B |
| Search index leaks across tenants | Per-tenant filtered aliases; integration test per index |
| Shared intelligence reveals source organisation | Sanitisation pipeline and per-item approval before sharing |
| Caches keyed without tenant | All cache keys prefixed with tenant id; lint rule |
| Agent context mixes tenants | One agent run per tenant; context built from tenant-scoped queries only |

### Prompt injection
| Threat | Control |
|---|---|
| Ingested page or feed contains instructions to the agent | Treat all source text as data; wrap in delimiters; strip markup; agents have read-only tools only |
| Agent is tricked into an action | Agents cannot act. Remediation is proposed and requires human approval |
| Exfiltration through tool calls or links | No outbound tools with arbitrary URLs; allow-listed enrichment only; output rendered as text, no auto-loaded links or images |
| Poisoned finding text | Analyst output is validated against schema; evidence must link to stored observations |

### Credential data handling
| Threat | Control |
|---|---|
| Unlawful collection | Only sources in SOURCES.md with `approved` status; HIBP domain search for verified domains only |
| Plaintext passwords stored | Never stored; collectors drop password fields before persistence; test asserts this |
| Over-exposure inside tenant | Restricted role `credential_viewer`; every view audited |
| Breach of our database | Field-level encryption with KMS key in AU region; minimal fields |
| Domain not owned by requester | Domain verification required before credential lookups |

### Other
- Stolen M365 tokens: least privilege scopes, encrypted at rest, rotation, revocation on disconnect.
- Source API key leakage: secrets manager, never in repo.
- Denial of wallet: per-tenant inference and enrichment budgets.
