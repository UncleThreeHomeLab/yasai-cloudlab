# AGENTS.md

This repository defines the lab, its bootstrap, and its validation.

## How to read this file

Delivery first (how to work), then Bootstrap, Declarative model, and
Public/private (what to build), then Validation, Reproducibility, and Layout
(how to check, where code lives). Secrets, Documentation, and Portability
apply throughout. Specific rules override general guidance. Product choices
live in the README and owning modules; this file names roles, not products,
so others can copy it for a different stack.

## Delivery

*Decide fast, validate little, report in chat.*

Complete authorized work and make routine decisions without asking again. Do
only the requested work; ask before adding tools, services, or out-of-scope
changes. After implementation changes, run the smallest validation covering
the changed behavior and affected callers, review security, fix material
findings, then commit and push through branch protection. Report results and
limitations in chat. Stop once relevant validation passes unless new changes,
failures, or unresolved risks justify more. Documentation-only edits need
only relevant document checks — no automatic commit or push.

## Bootstrap

*Ansible sets up each server exactly once, then gets out of the way.*

Run `docker compose run --build --rm lab setup` (applies
`ansible/playbooks/setup.yml`, then `ansible/playbooks/verify.yml`) once per
server. On an already-set-up server it must refuse or safely skip, never
mutate. "Resumable" means only this: a half-finished first run may resume to
completion; a finished run is never re-run.

Ansible installs host prerequisites, the Kubernetes distribution, and the
initial platform controllers — nothing else. After bootstrap,
GitOps/controllers own convergence and native provider configurations own
accepted external resources. Do not add service playbooks, per-service
scripts, runner command branches, or SSH/API installers for workloads,
dashboards, identity, DNS, or other routine application settings.

`prove` (setup twice, zero changes on the second apply, then verify) is only
for changing bootstrap scripts themselves. Bootstrap stays bootstrap: future
Ansible changes may only change what the one-time setup installs, never turn
it into lifecycle management.

## Declarative model

*Git declarations are the source of truth; controllers do the work.*

Every future change must be declarative: no imperative steps, no manual
configuration, no SSH/API installers. Before changing a capability, identify
its desired-state source, field owner, reconciler, credentials, and deletion
policy. Routine onboarding uses reviewed Git declarations consumed directly
by the accepted owner. Use YAML for supported inputs; Helm, provider HCL,
dashboard JSON, application code, and workflow scripts keep their formats.

After merge, owners apply changes, report readiness and failures, and repair
drift. Preserve approvals and provider plan, locking, and credential gates.
External resources keep their native owner and need approved trusted
execution; never assume application CI has that authority. Report
unsupported capabilities and use an explicitly scoped platform change, not an
imperative workaround. Never claim an interface works before its full
reconciliation path is verified.

Removal from an accepted complete Git revision is deletion intent for owned
resources. Persistent data, vault items, and shared infrastructure default to
retention; automatic data deletion needs a previously approved policy with
exact scope. Source failure, invalid input, or incomplete discovery is never
deletion intent.

## Public and private

*Two repos, one boundary: nothing private leaks into public, or vice versa.*

Public is this repository. Private is a separate repository configured per
environment through ignored local configuration — never name it in tracked
files. Applications and deployments can each live on either side
independently. Cross the split by reference only, without copying details
across it. Each side versions only its own non-secret declarations; secrets
and provider state stay outside Git on both sides. Generic private tunnel
ranges may be configuration defaults.

Nothing from a private service or deployment — addresses, source bindings,
inventory, credentials, diagnostic dumps, DNS records — may appear in public,
and vice versa. Public exposure declarations belong in public Git; private
exposure, source bindings, and sensitive inventory belong in private Git.

Enforcement: review tracked files and history before publishing; private reads
go through the read-only repo-access App, public metadata reads use a
disposable token restricted to the public repository. Gates fail closed: an
unreachable or unauthorized source blocks changes instead of falling back.

## Validation

*Only checks that server setup works, plus ad-hoc checks while working.*

"Setup works" is defined by `ansible/playbooks/verify.yml` (nodes, storage
and backup, GitOps convergence and authorization, certificates, mesh, access,
and its remaining component stages). Run it with
`docker compose run --build --rm lab verify`; credential-free static checks
with `docker compose run --build --rm lab validate`.

Every check file exists for bootstrap validation: existing test files are
migration candidates — each becomes bootstrap validation under its owner or
is removed. All future checks validate server setup, nothing else. Do not add
committed tests for application behavior, release flows, or one-off service
verification.

Agents validate server-side install work ad hoc while working and report in
chat; ad-hoc validation is never committed. Non-setup changes need no check.

## Reproducibility

*Anyone must rebuild the lab from a clean checkout.*

A clean checkout, `.env`, and Docker Compose must bootstrap the lab on two
existing, reachable VMs. VM creation and upstream firewalls are external
prerequisites. Version all non-secret inputs, dependencies, automation, and
validation. Keep tracked files environment-agnostic; environment specifics
live in ignored local configuration. Never rely on cached images,
credentials, copied tokens, or untracked scripts. Generate node secrets
automatically and preserve them. Pin artifacts and images by checksum or
digest; keep runner package sources fixed. State the host OS and update
policy in the README. Update pins and run validation together.

## Layout

*Where code lives and how to change it without breaking ownership.*

- Group code by responsibility; one job per module. Extend existing modules
  before adding new ones; avoid needless layers.
- Ansible lives under `ansible/playbooks/` with a thin bootstrap entry point;
  stages import in dependency order. No `automation/` framework or
  repository-owned role hierarchy.
- Keep component inputs, tasks, and assets with their owner. Shared setup
  validation lives in `verification/`; runner validation with the runner.
  Never import validation code into runtime modules.
- Reuse public interfaces, not private files or side effects. Define shared
  settings once. Prefer maintained modules and native interfaces; keep a
  custom helper only for a demonstrated gap with one owner.
- Onboard routine applications through supported declarations only — no
  per-application installers or runner command branches.
- Split files when responsibilities differ. A migration is incomplete until
  replaced tasks, helpers, inputs, callers, docs, and deployed runtime are
  retired together with no duplicate writers. Preserve bootstrap, validation,
  error handling, and safety gates; never merge responsibilities just to
  reduce file count.

## Secrets

*Where secrets live and what the agent may do with them.*

List bootstrap inputs in `.env.example`; keep values in ignored `.env`.
Application secrets belong in the configured secrets manager and sync into
the cluster through the secrets controller. Keep required item field names
with their owning module. Never print or commit secret values.

Keep `OP_SERVICE_ACCOUNT_TOKEN` read-only for the secrets controller. The
provisioning token (`OP_PROVISION_SERVICE_ACCOUNT_TOKEN`) stays local, never
on hosts or in Kubernetes. When supplied, agents may create missing
secrets-manager items for the authorized task: check existing items first,
preserve their values, default to empty fields for the user to fill in, and
stop on duplicate titles or incompatible fields. Empty fields block delivery
and must not replace valid credentials. Send sensitive item JSON through
standard input, never arguments or logs. Never overwrite, rotate, delete,
share, or vault-scope beyond the exact authorization. Removing a delivery
declaration never authorizes vault item deletion.

## Documentation

*README stays short; details live with their owner.*

Root README is a quick intro: overview, architecture diagram, lab resources,
setup, stack tables, illustrated flows, host OS and update policy. Setup is a
short numbered sequence (prerequisites, VM preparation, `.env` copy,
credentials, bootstrap/validate commands); link owning modules for details.
One short caption per diagram; never repeat diagram steps in prose. Do not
append implementation, recovery, catalog, security, onboarding, or
verification narratives — update the owning module and link only when useful
to new users. Before finishing a README edit, remove repetition and check
setup still works.

All tracked docs stay brief: current settings, secret field names, and safety
requirements only. Never record milestones, roadmaps, plans, history,
measurements, or acceptance narratives. Scratch notes go in ignored
`docs/local/`; never stage them unless asked. Progress, validation evidence,
and security findings go in chat. No extra reports or workflows unless asked.

## Portability

*Automation runs the same on Linux, macOS, and Windows.*

Use Docker Compose; do not add PowerShell scripts. Keep automation
provider-neutral.
