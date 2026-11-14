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

Credential custody: the writer token lives in the `renovate-maintenance`
1Password item, `RENOVATE_TOKEN` field (least scope: contents read+write,
pull requests read+write, metadata read, on the maintenance repository
only), outside Git. Start the profile with
`python platform/delivery/dependencies/launch.py [compose args]` (default
`up -d`): the launcher reads `OP_SERVICE_ACCOUNT_TOKEN` from `.env`,
fetches the field, refuses empty or whitespace-containing values, and
adds just `RENOVATE_TOKEN` to the compose child environment. Custom
launcher, not `op run --env-file`: the native form would inject every
`.env` entry into the compose child's environment, while this script
reads only `OP_SERVICE_ACCOUNT_TOKEN` for its own `op` authentication,
validates the vault field, and adds just `RENOVATE_TOKEN` to the child.
Scheduler-only ad-hoc runs go through the launcher too
(`python platform/delivery/dependencies/launch.py run --rm
dependency-maintenance once`): compose interpolates the whole profile,
so a bare compose invocation fails closed without the token, matching
the previous required-file behavior. Rotation is owner-side: re-run the
launcher to pick up the new value. Never run `docker compose config`
with the token in the environment: it prints the value. Requires
Python 3 and the 1Password CLI (`op`) on Linux, macOS, or Windows;
`op` authenticates with `OP_SERVICE_ACCOUNT_TOKEN` from `.env`, which
the launcher reads with the standard library (no extra packages). The
token only reaches the writer on stdin and raw logs stay in tmpfs.

Settings: `MAINTENANCE_REPOSITORY` (default `UncleThreeHomeLab/yasai-cloudlab`),
`MAINTENANCE_BASE` (default `main`). Extra scheduler arguments forward to
`orchestrate.cjs`. Run once ad hoc through the launcher:
`python platform/delivery/dependencies/launch.py run --rm dependency-maintenance once`.
