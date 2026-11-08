# Ansible

Compose provides the pinned execution environment in [runner](runner/).
Use `lab setup` to converge and verify, `lab prove` to run setup twice and verify
zero repeat changes on both nodes, `lab validate` for credential-free syntax,
input, lint and rendered-chart checks, and `lab test` for isolated local tests.

[Lifecycle playbooks](playbooks/) explicitly order component work. Components
keep numbered setup stages, named operations, inputs, assets and tests together.
GitOps/controllers retain continuous Kubernetes ownership; native infrastructure
roots retain external state and review gates. See [AGENTS.md](../AGENTS.md).

[Inventory](inventory.yml) loads host connection inputs from the runner;
[group variables](group_vars/all/) define shared settings. Put bootstrap secrets
in ignored `.env`, using [`.env.example`](../.env.example). Values are literal.
Use explicit `recovery-*` operations or named component recovery playbooks.
`backup` retains monthly export restrictions. Maintenance and upgrade require
an existing named component operation or reviewed pins followed by `setup` and
`prove`. Unspecified operations refuse before credentials or host access.
Distribution upgrades, reboots and arbitrary version overrides are unsupported.
`nuke` always refuses until exact resource and data scope is separately authorized.

[Host](playbooks/host/), [network](playbooks/network/), [Tailscale](playbooks/tailscale/)
and [K3s](playbooks/k3s/) stages preserve host identities and independent access.
Tailscale logout and reauthentication require one explicit host. K3s migration
and rollback retain checkpoints and require independent access and recovery;
ordinary maintenance and upgrades require reviewed scope and pinned artifacts.
`inspect` reads sanitized host prerequisites before bootstrap; `baseline` reports
capacity and existing controller ownership. Neither mutates hosts.

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

Private source advancement is generic across consumers (`private-sources`,
`services`, `observability`, `permissions`): publish an acceptance receipt at
`platform/acceptance/<consumer>.yaml` on a private branch, compute its matching
public commitment with
`docker compose run --rm --entrypoint python lab playbooks/argocd/files/private_sources.py commit <consumer> <private-repository> <revision> <nonce>`,
merge the receipt, then merge the commitment (and any enablement or pin) into
`gitops/roots/public/values.yaml`. The identity binding accepts only a
Git-accepted receipt revision; host input alone never retargets it. Qualify a
new consumer with the isolated controller fixture
(`verification/integration/private_source_acceptance.py`) before transferring a
live owner, and verify live convergence with the private verification payload.

[Certificates](playbooks/certificates/), [Istio](playbooks/istio/) and
[access](playbooks/access/) order staging issuance, gateways and private resolvers.
Host DNS runs independently of Kubernetes. Scoped tailnet operations preserve
unrelated grants. The control-machine governance reconciler
(`docker compose --profile infra run --rm infra-github once`, looped by
`up -d`) plans the accepted [github-workflows root](../infra/github-workflows/)
every cycle; apply requires the exact reviewed plan hash. Encrypted state,
backend locks and interrupted-operation recovery remain with each root.
Ordinary setup never imports existing external resources.

[Data](playbooks/data/) keeps scoped SQL grants, S3 credentials and bucket repair
on its independent five-minute host timer. CNPG and Argo retain continuous data
service ownership. Its shared lock protects adoption, capture and isolated restore.
[Backup](playbooks/backup/) owns independent control-plane capture, restic/B2
operations and local freshness checks. `backup` explicitly orders control-plane,
data/identity and Harbor recovery owners within the existing monthly window.
Capture and restore retain prior verified generations until replacement succeeds.

[Identity](playbooks/keycloak/) preserves the shared config-cli Lease, five-minute
repair and private retirement tombstones. Setup reconciles only accepted identity;
enrollment, client changes, offboarding and emergency repair remain named operations.
Data capture and isolated restore retain physical signing state and current input checks.
For an interrupted native Argo binding, set `KEYCLOAK_ARGO_RECOVERY_REVISION` to
the pending checkpoint's exact private SHA and rerun `lab identity-argo`; clear it
after acceptance. Recovery validates current private Git authorization before
reading historical inputs and refuses changed resource identities.
A paused catalog with a pending sync operation stays blocked for inspection or
scoped recovery; binding recovery never cancels or clears operations.

[Services](playbooks/services/) binds the approved private catalog directly to Argo.
Application charts consume Git definitions; the data owner repairs scoped public CA
configuration. External publication, identity and retirement remain explicit.
The public root owns the catalog Application and its reviewed `services.revision` pin.

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
