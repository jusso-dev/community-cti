# Contributing

Thanks for helping. This project serves community organisations, so please read [docs/DATA-GOVERNANCE.md](docs/DATA-GOVERNANCE.md) first.

## Ground rules
- Write in Australian English. No em dashes and no emojis in docs, issues or UI copy.
- Every finding must carry provenance, a confidence score and a dismiss or challenge path.
- Only add sources that are listed in [docs/SOURCES.md](docs/SOURCES.md) with checked licence terms.
- No real credential or personal data in tests, fixtures or issues.
- Collectors are deterministic. Language models only run in investigator and analyst agents.

## Development
```bash
corepack enable
pnpm install
pnpm build
pnpm test
pnpm test:isolation
pnpm test:redteam
pnpm eval
pnpm metrics:pilot
```

`pnpm test:isolation` checks that each API route has a case and that one organisation cannot read another's rows. `pnpm test:redteam` runs the agent fixture set. `pnpm eval` uses a scripted model and does not mean agents are cleared to launch. `pnpm metrics:pilot` prints the event names and states that the pilot has not been run.

## Pull requests
- Link the issue and tick its acceptance criteria.
- Include the validation commands you ran.
- Significant design changes need an ADR in `docs/adr/`.
- Issues labelled `co-design` or `needs-decision` need sign-off before code lands.

## Security
Report vulnerabilities privately through GitHub security advisories, not public issues.
