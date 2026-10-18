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

[Certificates](playbooks/certificates/), [Istio](playbooks/istio/) and
[access](playbooks/access/) order staging issuance, gateways and private resolvers.
Host DNS runs independently of Kubernetes. Scoped tailnet operations preserve
unrelated grants. [Infrastructure](playbooks/infrastructure/) invokes the accepted
[native roots](../infra/); apply requires the exact reviewed plan, source and
inputs. Encrypted state, backend locks and interrupted-operation recovery remain
with each root. Ordinary setup never imports existing external resources.

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

[Services](playbooks/services/) binds the approved private catalog directly to Argo.
Application charts consume Git definitions; the data owner repairs scoped public CA
configuration. External publication, identity and retirement remain explicit.
`playbooks/services/repair-source-owner.yml` requires `services_source_recovery_file` in
`/recovery/`; it restores only the recorded fixture-created sources field conflict.

[Observability](playbooks/observability/) keeps Git-owned dashboards and rules, private access,
redaction and bounded storage. [Harbor](playbooks/harbor/) retains Argo installation,
scoped registry credentials and coordinated recovery. Its host schedules use the
same monthly export window and local-only freshness checks. Component tests own
browser and provider fixtures.
