# Dependency maintenance scheduling

`maintenance.yaml` selects existing `owners.json` owners with a draft-only
cadence (daily, weekly, monthly). The `dependency-maintenance` compose service
(profile `maintenance`) runs `schedule.cjs` on `MAINTENANCE_INTERVAL`
(default hourly); each cycle resolves the exact base SHA from a clean checkout
and invokes `orchestrate.cjs`, which gates each group on its cadence and keeps
state, receipts, and status in the `maintenance_state` volume.

The scheduler and orchestrator are credential-free and never see the writer
token. Due groups write one token-free request to the `maintenance_handoff`
volume and wait for the trusted credential owner, who runs `handoff.cjs` with
their user-held token in `RENOVATE_TOKEN`; only the allowlisted result returns.
The writer sees no candidate code, private configuration, or Docker socket.

Settings: `MAINTENANCE_REPOSITORY` (default `UncleThreeHomeLab/yasai-cloudlab`),
`MAINTENANCE_BASE` (default `main`). Extra scheduler arguments forward to
`orchestrate.cjs`. Run once ad hoc with
`docker compose --profile maintenance run --rm dependency-maintenance once`.
