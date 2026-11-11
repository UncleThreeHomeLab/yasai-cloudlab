# Dependency maintenance scheduling

`maintenance.yaml` selects existing `owners.json` owners with a draft-only
cadence (daily, weekly, monthly). The `dependency-maintenance` compose service
(profile `maintenance`) runs `schedule.cjs` on `MAINTENANCE_INTERVAL`
(default hourly) in the locked qualifier image; each cycle resolves the exact
base SHA from a clean checkout and invokes `orchestrate.cjs`, which gates
each group on its cadence, qualifies the native toolchain, and keeps state,
receipts, and status in the `maintenance_state` volume.

The scheduler and orchestrator are credential-free and never see the writer
token. Due groups write one token-free request to the `maintenance_handoff`
volume and wait for the named trusted automation, the `maintenance-handoff`
compose service (D47), which runs `handoff.cjs` in loop mode; only the
allowlisted result returns. The writer sees no candidate code, private
configuration, or Docker socket.

Credential custody: the owner provisions `maintenance.env` containing
`RENOVATE_TOKEN` (least scope: contents read+write, pull requests
read+write, metadata read, on the maintenance repository only) at
`${PRIVATE_CONFIG_DIR:-../cloudlab-config}/maintenance.env`, outside Git.
The handoff service refuses to start without it. Provisioning and rotation
are owner actions; the token only reaches the writer on stdin and raw logs
stay in tmpfs.

Settings: `MAINTENANCE_REPOSITORY` (default `UncleThreeHomeLab/yasai-cloudlab`),
`MAINTENANCE_BASE` (default `main`). Extra scheduler arguments forward to
`orchestrate.cjs`. Run once ad hoc with
`docker compose --profile maintenance run --rm dependency-maintenance once`.
