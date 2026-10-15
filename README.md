# yasai-cloudlab

A K3s cluster on two cloud VMs, managed with Ansible and Docker Compose.

[Architecture](#architecture) | [The lab](#the-lab) | [Setup](#setup) | [The stack](#the-stack) | [Detailed flows](#detailed-flows)

## Architecture

![Architecture](assets/arch.png)

## The lab

Both VMs run **Debian 13 (Trixie), x86_64**.

| VM | Role | CPU | Memory | Disk |
| --- | --- | --- | --- | --- |
| Main | Control plane + workloads | 16 vCPUs | 32 GB | 640 GiB |
| Worker | Workloads | 16 vCPUs | 32 GB | 640 GiB |

These are the current resources, not minimum requirements. The control plane
uses SQLite and depends on the main VM.

Automation installs missing host packages from the configured Debian repositories.
Distribution upgrades are managed separately.

## Setup

1. Clone this repo and install Docker with Compose on your local machine.
2. Prepare two reachable Debian 13 VMs with SSH access and automatic time
   synchronisation. VM creation and upstream firewall rules are managed outside
   this repo. Allow the required outbound traffic, including NTP.
3. Copy [`.env.example`](.env.example) to `.env`. Fill in both VM credential sets,
   the CloudLab read-only 1Password token and the inputs for enabled services.
4. Prepare the external services: a CloudLab vault, scoped Tailscale credentials,
   a B2 bucket and key, a restic password and credentials for Cloudflare DNS, Tunnel and Access.
   Keep application secrets in 1Password. Access and application credential fields
   are defined in the [access](platform/connectivity/access/contract.json),
   [data](platform/data/contract.json) and [identity](platform/identity/keycloak/contract.json)
   contracts. Inputs for host access are listed in `.env.example`. Backup inputs
   are defined by the [recovery module](automation/recovery/runner.py).

From the repo directory, apply and verify:

```sh
docker compose run --build --rm lab prove
```

`prove` applies the configuration twice and requires no changes on the second
apply on either VM. It then checks behaviour. GitOps bootstrap needs verified
Tailscale host access and a fresh recovery point for the control plane.
The [prerequisite checks](ansible/roles/gitops/tasks/prerequisites.yml) run first.
Running the configuration again preserves existing secrets and data.
If the accepted Argo application controller cannot start after an OOM kill, run
`docker compose run --rm lab gitops-controller-recover`. This uses published memory
settings, preserves StatefulSet and credential identities, and verifies handoff to
Argo without vault access. It can replace only an OOM-failed pod stuck on old
settings, with UID and version preconditions. Healthy controllers and unrelated
failures cannot receive memory changes.

Check external infrastructure declarations independently with
`docker compose --profile infra run --build --rm infra check cloudflare`
or `docker compose run --build --rm infra-github check github`.
Verify GitHub governance separately with `docker compose run --rm infra-github verify github`
alongside `prove`; its credentials and state remain outside deployment jobs.
Live operations require private inputs and
accepted ownership; required fields and write gates belong to the
[infrastructure client](automation/infra/command.py).
Recover missing Cloudflare inputs from protected evidence and current vault values
with `docker compose run --rm --entrypoint python service -m automation.infra.input_recovery`.
Every original input checksum must match; existing files are never overwritten.

Application onboarding uses the [service contract](charts/service/README.md),
administrator-controlled ApplicationSets and scoped data/OIDC references. The
[notes example](apps/notes/README.md) contains the web/API demonstration. Enable
services only with a reviewed catalog in the designated private configuration repo.

Independent public monitoring uses the [monitoring contract](platform/observability/contract.json).
Keep `CloudLab/uptimerobot-management/API_KEY` in 1Password. Run
`docker compose run --build --rm lab observe external-check` before `external-apply`.
Only the account's active registered-email contact receives notifications. Disposable
`fixture-ready`, `fixture-fail`, `fixture-status` and `fixture-remove` commands test
delivery without interrupting production. Confirm outage and recovery email receipt;
provider status alone does not prove delivery.

Private telemetry uses the same [monitoring contract](platform/observability/contract.json).
Run `lab observe credentials` through Compose with the local vault writer, then
`gh auth token | docker compose run -T --rm lab observe identity-prepare`.
Merge the returned private client PR before enabling `observability.enabled` in
the public root. Add `grafana` and `kiali` to `PRIVATE_ACCESS_HOSTS`. Apply with
`prove`. Dashboards require Keycloak; telemetry PVCs exclude off-site backups.
Normal apply resumes only the accepted retired identity owner before its consumers.
Initial identity enrollment remains explicit.

## The stack

**Available:** implemented here. **In progress:** open PR. **Planned:** not implemented.
Deployment still depends on inputs and verification.

### Cluster components

| Category | Component | Purpose | Status |
| --- | --- | --- | --- |
| Platform | K3s | Kubernetes with DNS, metrics and local storage | Available |
| Deployment | Argo CD | Private API, public platform root and optional scoped private sources | Available |
| Connectivity | WireGuard | Encrypted traffic between the VMs | Available |
| Host access | Tailscale | Independent SSH access with scoped enrolment credentials | Available |
| Private access | Tailscale operator + CoreDNS | L3 gateway ingress, independent private DNS and an authenticated Kubernetes API proxy | Available |
| HTTPS and mesh | cert-manager + Istio | Automatic certificates, separate public/private gateways and workload identity | Available |
| Security | Host firewalls | Restrict public access and keep cluster and ingress ports private | Available |
| Secrets | External Secrets Operator | Synchronise 1Password values into Kubernetes Secrets | Available |
| Storage | [Longhorn](https://github.com/longhorn/longhorn) | Persistent volumes with one replica on each VM | Available |
| Application data | CloudNativePG + SeaweedFS | Private SQL over TLS and authenticated S3, subject to restore checks | Available |
| Identity | Keycloak | Realm configuration, passkeys and application OIDC | Available |
| Recovery | SQLite + restic | Monthly control plane export with separate credentials and recovery checks | Available |
| Packaging | Helm | Versioned workload charts | Available |
| Runners | ARC | Separate application and infrastructure runners | Planned |
| Registry | Harbor | Private images and OCI charts | Planned |
| Builds | BuildKit | Rootless image builds | Planned |
| Supply chain | Trivy + Cosign | Scan, sign and verify images | Planned |
| Policy | Kyverno | Admission and image policies | Planned |
| GitOps | ApplicationSet | Admin-approved app deployments and scoped data requests | Enabled |
| Releases | Argo Rollouts | Canary releases and previews | Planned |
| Metrics | Prometheus + Alertmanager | Metrics, SLOs and alerts | Available |
| Logs | Grafana Alloy + Loki | Collect and store redacted logs | Available |
| Traces | OpenTelemetry + Tempo | Collect and store traces | Available |
| Dashboards | Grafana + Kiali | Private service health and mesh views | Available |

**Storage:** Applications opt in to Longhorn. `local-path` remains the default.
Longhorn schedules monthly B2 backups and keeps the latest scheduled backup per
volume.

### External services

| Category | Service | Purpose | Status |
| --- | --- | --- | --- |
| Storage | [Backblaze B2](https://www.backblaze.com/cloud-storage) | External storage for Longhorn backups | Available |
| Secrets | 1Password | CloudLab vault, accessed with a read-only service account | Available |
| Public access | Cloudflare Tunnel + Access | Outbound tunnel, verified origin HTTPS and explicit human/machine policies | Available |
| Source | GitHub | Code and GitOps repositories | Available |
| Certificates | Let's Encrypt | Public TLS certificates | Available |
| Infrastructure state | GitLab | Encrypted state with a separate lock for each root | In progress ([#122](https://github.com/UncleThreeHomeLab/yasai-cloudlab/pull/122)) |
| Monitoring | UptimeRobot | Independent HTTPS checks and email alerts | Available |

### Automation

| Tool | Purpose | Status |
| --- | --- | --- |
| Ansible | Configure and verify hosts and the cluster | Available |
| Docker Compose | Run the pinned automation environment | Available |
| OpenTofu | Manage external resources, with Compose for bootstrap and recovery | In progress ([#122](https://github.com/UncleThreeHomeLab/yasai-cloudlab/pull/122)) |
| GitHub Actions | Trusted builds and infrastructure jobs through ARC | Planned |
| Renovate | Reviewed dependency updates | Planned |

## Detailed flows

### Access

Cloudflare Tunnel carries public requests to the public Istio gateway.
Tailscale carries private requests to a separate gateway. Both route to apps over
HTTPS. cert-manager manages certificates and Cloudflare Access protects selected public hosts.

![Access](assets/access.png)

### Identity

Users sign in through Keycloak. Apps use OIDC tokens and roles to control access.
External Secrets copies scoped credentials from 1Password into Kubernetes.
Background refreshes run once a day to bound vault requests. Explicit
credential rotations request immediate refresh; failed synchronization retains
existing Secrets and reports degraded health. Other vault edits can take up to
24 hours to reach applications.
Apply retries an exhausted root or identity sync only when its failures were
ExternalSecrets that became Ready after the failed operation. Other failures
remain visible; retries preserve the source, credentials and data.
Istio encrypts traffic between workloads and checks which services may communicate.

![Identity](assets/identity.png)

### Delivery

GitHub Actions runs trusted builds on ARC workers in Cloudlab. Images are built,
scanned, signed and stored in Harbor. Argo CD reads public or private GitOps repos
and deploys the selected images. Dedicated infrastructure runners execute OpenTofu.
GitHub governance runs separately through Compose.

![Delivery](assets/delivery.png)

### Releases

Argo Rollouts sends a small share of traffic to a new revision. Prometheus metrics
and k6 tests guide promotion or rollback. ApplicationSet creates private previews
for approved revisions. Preview resources are removed when the preview closes or expires.

![Releases](assets/releases.png)

### Data

Apps use PostgreSQL managed by CloudNativePG and private S3 storage from SeaweedFS.
Longhorn replicates their volumes across both VMs. Coordinated monthly backups go
to B2. Isolated restores check that databases and objects can be recovered.

![Data](assets/data.png)

### Observability

Prometheus collects metrics. Alloy sends logs to Loki and traces to Tempo.
Grafana brings these signals together, Kiali shows mesh traffic and Alertmanager
routes alerts. UptimeRobot checks public access independently. Telemetry stays on local storage.

![Observability](assets/observability.png)

### Foundation

Compose runs Ansible to configure both VMs and K3s. Dedicated ARC runners apply
reviewed OpenTofu changes to Cloudflare and Harbor, with encrypted state in GitLab.
Compose remains available for bootstrap, recovery and GitHub governance.
K3s recovery uses a separate monthly restic backup to B2.

![Foundation](assets/foundation.png)
