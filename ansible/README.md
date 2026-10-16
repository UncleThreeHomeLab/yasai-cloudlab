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
