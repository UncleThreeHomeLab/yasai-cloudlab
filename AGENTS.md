# AGENTS.md

This repository defines the lab, its automation, and its checks.

## Delivery

Complete authorized work and make routine decisions without asking again.
After implementation changes, run tests covering the changed behavior and affected
callers, review security, fix material findings,
then commit and push through branch protection. Documentation-only edits do
not need an automatic commit or push. Report results and limitations in chat.
Use the smallest relevant checks. Do not run unrelated or redundant tests.
Once relevant checks pass, stop testing unless new changes, failures, or unresolved
risks justify more checks. Run the full test suite only when changes have broad
impact or targeted checks cannot cover the affected behavior. Documentation-only
edits need only relevant document checks.

## Code is the lab

Put lasting changes and the steps to apply them in this repository. Use VM
sessions for inspection, not manual configuration. Applying the code must be
safe to repeat and must preserve existing secrets and data.

Use the established declarative owner for each resource and field: Ansible for
host bootstrap and explicit operations, GitOps/controllers for continuous
Kubernetes convergence, and native provider configurations for accepted external
resources. Preserve required continuous repair. Destructive actions require an
explicit resource and data scope.

## Declarative changes

Before changing a capability, identify its desired-state source, field owner,
reconciler, credentials and deletion policy. Routine onboarding and configuration
must use reviewed Git declarations consumed directly by the accepted owner.
Use YAML for supported user inputs; native Helm, provider HCL, dashboard JSON,
application code and workflow scripts can keep their established formats.
Changing file format alone is not a declarative migration.

Keep Ansible for hosts, infrastructure prerequisites, initial controller bootstrap
and scoped operations such as recovery. Do not add service playbooks, per-service
scripts, runner command branches or SSH/API installers for workloads, dashboards,
identity, DNS or other routine application settings. Do not compile Git intent
into a runtime snapshot that needs another operator apply to advance. Extend
existing charts, controllers and native providers; keep one writer per field.

After reviewed merge, owners must apply supported changes, report readiness and
failures, and repair drift. Preserve source/workflow approvals and provider plan,
locking and credential gates. External resources retain their native owner and
require approved trusted execution; never assume application CI has that authority.
If a capability is unsupported, report the gap and use an explicitly scoped
platform change, not a new imperative onboarding workaround. Do not claim a
planned interface works before its full reconciliation path is verified.

Public exposure declarations belong in public Git; private exposure declarations,
private source bindings and sensitive inventory belong in private Git. Resolve
approved service/backend references without exposing private details publicly.

Removal from an accepted complete Git revision is deletion intent for owned
resources under their accepted policy. Ordinary owned workloads, routes,
dashboards and monitors should be cleaned up automatically. Persistent data,
vault items and shared infrastructure default to retention. Automatic data
deletion requires a previously approved policy with exact resource/data scope;
do not ask again for that same authorized scope. Source failure, invalid input
or incomplete discovery is never deletion intent. Preserve ownership/policy
records until ordered cleanup finishes; report blockers and retained data.
Verify pruning, cascading cleanup and backing-storage reclaim behavior together.

## Reproducibility

A clean checkout, `.env`, and Docker Compose must apply and verify the lab on
two existing, reachable VMs. VM creation and upstream firewalls are external
prerequisites unless a provider integration is requested.

Version all required non-secret inputs, dependencies, automation, and checks.
Do not rely on cached images, credentials, copied tokens, or untracked scripts.
Generate node secrets automatically and preserve them on repeat applies.
Pin downloaded artifacts and images by checksum or digest, and keep runner
package sources fixed. State the host OS and update policy in the README.
Update pins and run verification together.

For setup changes, run `prove` for the affected components where supported:
apply twice, require zero changes on the second
apply on both nodes, then verify real behavior. Test a clean checkout when
changing packaging or entry points. Report only what was tested; existing-VM
checks do not prove empty-VM setup. Never wipe VMs to test reproducibility.
Configuration reproducibility does not replace backup and restore testing.

## Organization and modules

- Group code by responsibility. Each module has one job and clear inputs and outputs.
- Organize Ansible as component playbooks under `ansible/playbooks/`. Keep lifecycle
  entry points thin; explicitly import stages in dependency order. Numbers make
  sequential stages readable; imports determine execution. Do not recreate an
  `automation/` framework or a repository-owned role hierarchy.
- Keep component inputs, tasks, assets and tests with their owner; runner checks
  belong in `ansible/runner/tests/`. Keep shared integration checks in
  `verification/integration/`. Put reusable test fixtures in the owning
  component's `tests/fixtures.py`; never import fixtures from test suites or
  import test code into runtime modules.
- Define shared settings once. Reuse public interfaces, not private files or side effects.
- Extend existing modules before adding new ones. Avoid needless layers and folders.
- Extend supported application declarations for routine onboarding. Do not add
  per-application installers or runner command branches.
- Prefer maintained modules and native interfaces. Retain a custom helper only
  for a demonstrated gap, with one owner, clear inputs/outputs and behavior checks.
- Split files when responsibilities differ. Remove replaced code, update references,
  and verify preserved behavior.
- A migration is incomplete until replaced Ansible tasks/playbooks, helpers,
  runner/Compose commands, generated inputs and deployed runtime are retired.
  Update imports, setup/verify entry points, packaging, callers, tests and docs
  together. Move needed logic to its owner once; leave no duplicate or fallback
  writers. Preserve active bootstrap, validation, locks and recovery paths.
  Remove obsolete installed files/units through scoped repeatable retirement;
  retain compatibility steps only while supported upgrades require them.
- Before deleting or merging files, check imports, runner commands, deployment
  references and tests. Preserve validation, error handling and safety gates;
  do not combine different responsibilities merely to reduce file count.
- Use explicit dispatch tables for repeated runner command routing. Keep component
  behavior with its owner and preserve credential validation and write gates.
- Run relevant local tests through Docker Compose; use
  `docker compose run --build --rm lab test` when the full suite is warranted.
  Local tests must not require VM or service credentials. Keep component test processes isolated when
  standalone VM modules use overlapping import names.
- Update callers, deployed runtime paths, portable checks and concise documentation
  together. Keep operations repeatable and resumable; preserve recovery paths.
- For declarative migrations, verify creation, updates, drift repair and removal
  under the accepted policy, including data retention and deletion blockers.
  Check a clean checkout and prove later setup cannot recreate the retired writer.

## Documentation

Treat the root README as a quick introduction for someone new to the repo.
Keep its scope to a short overview, architecture diagram, lab resources, setup,
stack tables and illustrated flows. Preserve the lab, stack, external service
and automation tables, host OS and update policy. Keep component purposes concise.

Write setup as a short numbered installation sequence: local prerequisites,
VM preparation, copying `.env.example` to `.env`, preparing required credentials,
and the main apply/verify command. Keep essential prerequisites visible; link to
owning modules for credential fields and service-specific requirements.

Let diagrams explain detailed flows. Use one short caption per flow; add only
essential caveats that the diagram cannot show. Do not repeat diagram steps in prose.

Do not append implementation details, recovery procedures, command catalogs,
security internals, onboarding instructions or verification narratives to the
root README when completing a task. Update the existing owning module or contract
when lasting details are needed; add a short README link only when useful to new
users. Expand README scope only when explicitly requested. Before finishing a
README edit, remove repeated explanations and check that setup remains usable.

Apply the same brevity to all tracked documentation and descriptive contract
fields. Keep only current settings, required secret field names and concise
behavior or safety requirements. Never record milestones, roadmaps, work plans,
session history, completed work, test measurements or acceptance narratives.
Preserve machine-consumed configuration and checks.

Keep detailed reference material and working notes in ignored `docs/local/`
when useful. Never stage or publish these files unless explicitly requested.
Use plain language and maintain one home for each topic.

Do not create extra docs, dated reports, session histories, or security report
files unless explicitly requested. Put progress, test evidence, and security
findings in chat. Do not add GitHub Actions workflows unless explicitly requested.

## Secrets

List bootstrap inputs in `.env.example`; keep their values in ignored `.env`.
Use `VM_HOST` and `VM_PASSWORD` from `.env` for VM access. Application secrets
belong in 1Password and are synchronized through External Secrets. Keep required
item field names with their owning module. Never print or commit secret values.

When `OP_PROVISION_SERVICE_ACCOUNT_TOKEN` is supplied in ignored `.env`, agents
may create missing 1Password items required by the authorized task in CloudLab
without asking again. Use a separate service account with Read Items and Write
Items access to that vault. Keep `OP_SERVICE_ACCOUNT_TOKEN` read-only for ESO.
The provisioning token stays local; never deliver it to hosts or Kubernetes.
Check for existing items before creation, preserve their values on repeat runs,
and stop on duplicate titles or incompatible fields. For application secrets,
default to creating the approved item with empty required fields for the user
to fill in 1Password. Preserve partially completed items. Report pending items
and missing field names without values; empty fields block delivery/readiness
and must not replace valid deployed credentials. Once completed, the supported
reconciler should resume without another operator apply. If placeholder creation
or completion detection is unsupported, report that gap rather than treating
empty credentials as valid or silently generating values.

Generate application secret values securely only for an explicitly approved
profile or request; preserve automatic node bootstrap generation. Send sensitive
item JSON through standard input, never command arguments or logs. Do not
overwrite, rotate, delete, share items, or create vaults without exact authorized
scope. Removing a delivery declaration does not authorize vault item deletion.
Missing write access is a prerequisite to report, not permission to expand the
reader's privileges.

## Scope

Do only the requested work. Make routine implementation choices yourself;
ask before adding tools, services, or changes outside the agreed scope.

## Portability

Use Docker Compose for automation on Linux, macOS, and Windows. Do not add
PowerShell scripts. Keep automation provider-neutral.

Keep private deployment addresses, private repository inputs, credentials and
diagnostic dumps out of public Git. Version non-secret declarations in their
owning public or private repository; secrets and provider state stay outside Git.
Generic private tunnel ranges may be configuration defaults.
Review tracked files and Git history before making the repository public.
