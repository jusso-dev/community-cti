# ADR 0007: Magic-link sessions without an auth library

- Status: Accepted
- Date: 2026-10-13

## Context
Sign-up needs an email magic link, an organisation, invites, and a recorded consent. Issue 13 asks for a short ADR if we choose session tables rather than a hosted login product. Passkeys and Microsoft 365 sign-in are out of scope for this phase.

## Decision
- Do not add Auth.js, Lucia, or another auth library.
- Use Lucia-style tables that we own: `magic_links` and `sessions`, created in `db/migrations/0002_platform.sql`.
- Email a single-use link. Store only the SHA-256 of the token. The raw token stays in the mailer output.
- Magic links expire after 15 minutes. Sessions expire after 12 hours.
- `POST /orgs` calls `create_organisation`, which inserts the tenant, the owner membership, and attaches the open session in one database function.
- Invites are owner-only. Consent for `domain_monitoring` stores the grantor, the time, and the caller IP.

## Consequences
- Isolation tests can call the handler without a cookie framework.
- Delivery of the email depends on the injected mail function. This change does not add a production mail provider.
- A later passkey or Microsoft 365 login would be a new ADR. It would not replace the audit trail for consent.
