# Data governance and Indigenous data sovereignty

This document is a starting point. It must be reviewed and co-designed with participating organisations before any community sharing feature launches.

## Frameworks

### CARE Principles for Indigenous Data Governance
- **Collective benefit:** the platform exists to protect communities. Data use must benefit the organisations it comes from.
- **Authority to control:** organisations decide what is collected, kept, shared and deleted.
- **Responsibility:** we report openly on how data is used and protected, and we build capability, not dependence.
- **Ethics:** minimise harm, respect cultural protocols and consider future use.

### Maiam nayri Wingara Indigenous Data Sovereignty Principles
Aboriginal and Torres Strait Islander people have the right to exercise control of the data ecosystem, to data that is contextual and disaggregated, to data that is relevant and empowers sustainable self-determination, to data structures accountable to Aboriginal and Torres Strait Islander people, and to data that is protective and respects individual and collective interests. We apply these to every design decision touching community data.

## Commitments

1. **Consent:** collection beyond public domain monitoring needs explicit, recorded consent from an authorised person in the organisation. Consent records are stored in `consents` with scope, grantor, timestamp and revocation.
2. **Opt-in, granular sharing:** community sharing is off by default. Organisations opt in per category and approve each sanitised warning before it is shared.
3. **Sanitisation:** shared warnings strip organisation names, people, internal hostnames and anything that could identify the source unless the organisation explicitly allows attribution.
4. **Cultural data:** data flagged as cultural (by the organisation or by classification) is never shared automatically, never sent to third-party model providers without explicit approval, and never used to train or fine-tune models.
5. **No training on tenant data:** tenant data is not used to train models. Model providers must contractually commit to no retention and no training.
6. **Australian residency:** all data is stored and processed in Australian regions. Any exception (for example a model provider without an AU region) is recorded in the exceptions register below, with reason, data categories, safeguards and approver.
7. **Deletion and exit:** organisations can export and delete their data. Deletion completes within 30 days, including backups on rotation.
8. **Sponsors:** sponsors never get access to participating organisations' private intelligence.
9. **Governance group:** a community governance group with representatives from pilot organisations reviews sharing rules, exceptions and incidents.

## Credential exposure data
- Only lawful sources (for example the HIBP domain search API for verified domains).
- Store the minimum: email, breach name, breach date, data classes. Never store plaintext passwords.
- Field-level encryption, restricted roles, every view audited.
- Retention: 12 months after resolution unless the organisation chooses less.

## Retention defaults (to be confirmed)

| Data | Default retention |
|---|---|
| Raw observations | 180 days |
| Findings and feedback | Life of account plus 12 months |
| Credential exposure records | 12 months after resolution |
| Audit log | 7 years |

## Residency exceptions register

| Id | Service | Data categories | Region | Reason | Safeguards | Approved by | Date |
|---|---|---|---|---|---|---|---|
| TS-1 | ThreatSieve TAXII read | Shared STIX only. No tenant findings, credentials, or cultural data | Cloudflare global, read path | ThreatSieve is the intelligence source and this read is not pinned to an Australian region | Allow-listed https host, `intel:read` bearer key, empty request body, sightings dropped, tenant data stays in the Australian database | Justin Middler | 2026-10-14 |
