# yasai-cloudlab

Two cloud VMs, one K3s cluster. Managed as code with Ansible and Docker Compose.

## The lab

Both VMs run **Debian 13 (Trixie), x86_64**.

| VM | Role | CPU | Memory | Disk |
| --- | --- | --- | --- | --- |
| Main | Control plane + workloads | 16 vCPUs | 32 GB | 640 GiB |
| Worker | Workloads | 16 vCPUs | 32 GB | 640 GiB |

These are the current resources, not minimum requirements. The control plane
uses SQLite and depends on the main VM.

## Cluster components

| Category | Component | Purpose |
| --- | --- | --- |
| Platform | K3s | Kubernetes with bundled DNS, metrics, and local storage |
| Deployment | Argo CD | Private API, public platform root and optional scoped private sources |
| Connectivity | WireGuard | Encrypted traffic between the VMs |
| Host access | Tailscale | Independent SSH access; requires scoped enrollment credentials |
| Private access | Tailscale operator + CoreDNS | L3 gateway ingress, independent private DNS and an authenticated Kubernetes API proxy |
| HTTPS and mesh | cert-manager + Istio | Automatic certificates, separate public/private gateways and workload identity |
| Security | Host firewalls | Restrict public access; keep cluster and ingress ports private |
| Secrets | External Secrets Operator | Synchronize 1Password values into Kubernetes Secrets |
| Storage | [Longhorn](https://github.com/longhorn/longhorn) | Persistent volumes with one replica on each VM |
| Application data | CloudNativePG + SeaweedFS | Private SQL/TLS and authenticated S3; gated by restore acceptance |
| Identity | Keycloak | Realm configuration, passkeys and application OIDC |
| Recovery | SQLite + restic | Consistent monthly control-plane export; separate credentials and acceptance |

## External services

| Category | Service | Purpose |
| --- | --- | --- |
| Storage | [Backblaze B2](https://www.backblaze.com/cloud-storage) | External storage for Longhorn backups |
| Secrets | 1Password | CloudLab vault, accessed with a read-only service account |
| Public access | Cloudflare Tunnel + Access | Outbound tunnel, verified origin HTTPS and explicit human/machine policies |
| Infrastructure state | GitLab | Private encrypted OpenTofu state, independent locks and version recovery |

**Storage:** Applications opt in to Longhorn; `local-path` remains the default.
Longhorn schedules monthly B2 backups and keeps the latest scheduled backup per
volume.

## Automation

| Tool | Purpose |
| --- | --- |
| Ansible | Configure hosts and cluster; verify the result |
| Docker Compose | Run the pinned automation environment |
| OpenTofu | Separate Cloudflare and GitHub infrastructure roots with pinned providers |

Automation installs missing host packages from configured Debian repositories;
distribution upgrades are managed separately. Bootstrap inputs are listed in
[`.env.example`](.env.example); private values stay in ignored `.env`.

## Setup

1. Clone this repo and install Docker with Compose on your local machine.
2. Prepare two reachable Debian 13 VMs with SSH access and automatic time
   synchronization. VM creation and upstream firewall rules are managed outside
   this repo; allow the required outbound traffic, including NTP.
3. Copy [`.env.example`](.env.example) to `.env`. Fill in both VM credential sets,
   the CloudLab read-only 1Password token, and the enabled service inputs.
4. Prepare the external services: a CloudLab vault, scoped Tailscale credentials,
   a B2 bucket/key and restic password, and Cloudflare DNS/tunnel/Access credentials.
   Keep application secrets in 1Password. Access and application credential fields
   are defined in the [access](platform/connectivity/access/contract.json),
   [data](platform/data/contract.json) and [identity](platform/identity/keycloak/contract.json)
   contracts. Host-access inputs are listed in `.env.example`; backup inputs are
   defined by the [recovery module](automation/recovery/runner.py).

From the repo directory, apply and verify:

```sh
docker compose run --build --rm lab prove
```

`prove` applies twice, requires zero changes on the second apply on both VMs,
then verifies behavior. GitOps bootstrap requires verified Tailscale host access
and a fresh control-plane recovery point; its [prerequisite checks](ansible/roles/gitops/tasks/prerequisites.yml)
run before bootstrap. Repeat application preserves existing secrets and data.

Infrastructure checks run with `docker compose run --build --rm infra check cloudflare`
(or `github`). Live infrastructure operations require private inputs outside the
checkout, selected by `INFRA_PRIVATE_DIR`; the independent client receives no
deployment credentials. Required files and credential fields are validated by the
[infrastructure module](automation/infra/command.py). Ownership acceptance is required
before ordinary live operations.
