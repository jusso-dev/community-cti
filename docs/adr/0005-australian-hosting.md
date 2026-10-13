# ADR 0005: Australian hosting and data residency

- Status: Accepted
- Date: 2026-10-13

## Decision
Host all production data and processing in Australian regions (for example AWS ap-southeast-2 Sydney or ap-southeast-4 Melbourne, Azure Australia East, or an Australian sovereign provider). Backups stay in Australia. Model inference uses providers with an AU region where available.

## Exceptions
Any exception is recorded in the register in `docs/DATA-GOVERNANCE.md` with data categories, reason, safeguards and approver. Cultural data is never part of an exception.

## Reasons
Indigenous data sovereignty commitments, Privacy Act expectations, government and health sector buyers (Aboriginal Medical Services), and trust.

## Open questions
Choice of provider and whether IRAP-assessed services are needed for government sponsors.
