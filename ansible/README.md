# Ansible

Compose provides the pinned execution environment in [runner](runner/).
Use `lab setup` to install once and verify, `lab prove` to run setup twice and
verify zero repeat changes on both nodes; completed servers refuse repeat runs.
Use `lab monthly-proof` for the monthly backup subset, `lab validate` for
credential-free syntax, input, lint and rendered-chart checks, and `lab test`
for isolated local tests.

[Lifecycle playbooks](playbooks/) explicitly order component work. Components
keep numbered setup stages, named operations, inputs, assets and tests together.
GitOps/controllers retain continuous Kubernetes ownership; native infrastructure
roots retain external state and review gates. See [AGENTS.md](../AGENTS.md).

[Inventory](inventory.yml) loads host connection inputs from the runner;
[group variables](group_vars/all/) define shared settings. Put bootstrap secrets
in ignored `.env`, using [`.env.example`](../.env.example). Values are literal.
Use explicit `recovery-*` operations or named component recovery playbooks.
`backup` retains monthly export restrictions. Maintenance and upgrade require
an existing named component operation; `setup` and `prove` run once per server.
Unspecified operations refuse before credentials or host access.
Distribution upgrades, reboots and arbitrary version overrides are unsupported.
`nuke` always refuses until exact resource and data scope is separately authorized.

[Host](playbooks/host/), [network](playbooks/network/), [Tailscale](playbooks/tailscale/)
and [K3s](playbooks/k3s/) stages preserve host identities and independent access.
Tailscale logout and reauthentication require one explicit host. K3s migration
and rollback retain checkpoints and require independent access and recovery;
ordinary maintenance and upgrades require reviewed scope and pinned artifacts.
`inspect` reads sanitized host prerequisites before bootstrap; `baseline` reports
capacity and existing controller ownership. Neither mutates hosts. `setup` refuses
completed servers and records its reviewed revision on each server after verification.

[Secrets](playbooks/secrets/), [Longhorn](playbooks/longhorn/) and
[Argo CD](playbooks/argocd/) stages seed locked charts only before their recorded
writer release. Argo then reconciles workloads; ESO alone writes generated
Secrets. Bounded ownership transactions retain durable checkpoints, identity
checks and exclusive locks. Recovery requires the declared Argo writer suspended;
ordinary setup preserves its accepted ownership and existing data.
The existing read-only `github-argocd` App must select both the public platform
repository and private configuration repository before native handoff. Public
metadata reads use a disposable token restricted to the public repository.
First-binding reads remain anonymous under their durable operation; failed
acquisition or unconfirmed revocation blocks changes.

Private source registry advancement uses `platform/acceptance/private-sources.yaml`
in the private repository. Its only fields are string `version: v1`, `revision`
(40 lowercase hexadecimal characters), and `nonce` (64 lowercase hexadecimal
characters). Compute SHA-256 in memory over six UTF-8 lines, each ending in LF:
`cloudlab-private-source-acceptance-v1`, the exact configured repository URL,
`private-sources`, `platform/sources.yaml`, the revision, and the nonce. Publish
only the opaque digest as `privateSources.commitment` in
`gitops/roots/public/values.yaml` through protected review. Advance or roll back
by reviewing the corresponding receipt and commitment together.

[Certificates](playbooks/certificates/), [Istio](playbooks/istio/) and
[access](playbooks/access/) order staging issuance, gateways and private resolvers.
Host DNS runs independently of Kubernetes. Scoped tailnet operations preserve
unrelated grants. The control-machine governance reconciler
(`docker compose --profile infra run --rm infra-github once`, looped by
`up -d`) plans the accepted [github-workflows root](../infra/github-workflows/)
every cycle; apply requires the exact reviewed plan hash. Encrypted state,
backend locks and interrupted-operation recovery remain with each root.
Ordinary setup never imports existing external resources.

[Backup](playbooks/backup/) owns independent control-plane capture, restic/B2
operations and local freshness checks within the existing monthly window.
Capture and restore retain prior verified generations until replacement succeeds.

[Observability](playbooks/observability/) keeps Git-owned dashboards and rules, private access,
redaction and bounded storage. Native ApplicationSets own Harbor installation;
the [Harbor settings executor](../infra/harbor/) reconciles reviewed registry
bindings under content-bound approval, retaining credentials, unrelated projects
and recoverable artifacts. Component tests own
browser and provider fixtures.

CI tools are qualified before job credentials are delivered. Application CI is
registered through reviewed private registration YAML; Argo reconciles the
derived runner pools. Releases are proposed as `apps/releases/*.json` PRs and
merged through branch protection; release Apps never merge their own PRs.
See [service onboarding](../docs/service-onboarding.md).
