# AGENTS.md

This repository defines the lab, its automation, and its checks.

## Delivery

Complete authorized work and make routine decisions without asking again.
After implementation changes, test, review security, fix material findings,
then commit and push through branch protection. Documentation-only edits do
not need an automatic commit or push. Report results and limitations in chat.

## Code is the lab

Put lasting changes and the steps to apply them in this repository. Use VM
sessions for inspection, not manual configuration. Applying the code must be
safe to repeat and must preserve existing secrets and data.

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

For setup changes, run `prove`: apply twice, require zero changes on the second
apply on both nodes, then verify real behavior. Test a clean checkout when
changing packaging or entry points. Report only what was tested; existing-VM
checks do not prove empty-VM setup. Never wipe VMs to test reproducibility.
Configuration reproducibility does not replace backup and restore testing.

## Organization and modules

- Group code by responsibility. Each module has one job and clear inputs and outputs.
- Keep entry points thin and implementation and checks with their owning module.
  Give cross-module tests a clear integration owner.
- Define shared settings once. Reuse public interfaces, not private files or side effects.
- Extend existing modules before adding new ones. Avoid needless layers and folders.
- Split files when responsibilities differ. Remove replaced code, update references,
  and verify preserved behavior.

## Documentation

Keep the root README as a short overview with prerequisites, required inputs,
and starting commands. Use plain language and maintain one home for each topic.

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
and stop on duplicate titles or incompatible fields. Generate secrets securely
and send sensitive item JSON through standard input, never command arguments or
logs. Do not overwrite, rotate, delete, share items, or create vaults unless the
task separately authorizes that action. Missing write access is a prerequisite
to report, not permission to expand the reader's privileges.

## Scope

Do only the requested work. Make routine implementation choices yourself;
ask before adding tools, services, or changes outside the agreed scope.

## Portability

Use Docker Compose for automation on Linux, macOS, and Windows. Do not add
PowerShell scripts. Keep automation provider-neutral.

Keep deployment addresses, private repository inputs, credentials, and diagnostic
dumps out of Git. Generic private tunnel ranges may be configuration defaults.
Review tracked files and Git history before making the repository public.
