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
Use explicit `recovery-*` operations for recovery. `backup` retains monthly export
restrictions. Maintenance, upgrade and destruction refuse unspecified scope.

[Host](playbooks/host/), [network](playbooks/network/), [Tailscale](playbooks/tailscale/)
and [K3s](playbooks/k3s/) stages preserve host identities and independent access.
Tailscale logout and reauthentication require one explicit host. K3s migration
and rollback retain checkpoints and require independent access and recovery;
ordinary maintenance and upgrades require reviewed scope and pinned artifacts.

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
