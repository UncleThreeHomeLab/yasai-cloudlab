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
| Platform | K3s | Kubernetes with bundled DNS, ingress, metrics, and local storage |
| Connectivity | WireGuard | Encrypted traffic between the VMs |
| Host access | Tailscale | Independent SSH access; requires scoped enrollment credentials |
| Security | Host firewalls | Restrict public access; keep cluster and ingress ports private |
| Secrets | External Secrets Operator | Synchronize 1Password values into Kubernetes Secrets |
| Storage | [Longhorn](https://github.com/longhorn/longhorn) | Persistent volumes with one replica on each VM |
| Recovery | SQLite + restic | Consistent monthly control-plane export; separate credentials and acceptance |

## External services

| Category | Service | Purpose |
| --- | --- | --- |
| Storage | [Backblaze B2](https://www.backblaze.com/cloud-storage) | External storage for Longhorn backups |
| Secrets | 1Password | CloudLab vault, accessed with a read-only service account |

**Storage:** Applications opt in to Longhorn; `local-path` remains the default.
Longhorn schedules monthly B2 backups and keeps the latest scheduled backup per
volume.

## Automation

| Tool | Purpose |
| --- | --- |
| Ansible | Configure hosts and cluster; verify the result |
| Docker Compose | Run the pinned automation environment |

## Run it

1. Prepare two reachable VMs and Docker Compose.
2. Fill in `.env` from [`.env.example`](.env.example), including the 1Password token. Create the B2 item in CloudLab. Keep secrets out of Git.
3. Apply and verify:

```sh
docker compose run --build --rm lab prove
```

This applies twice, requires zero changes on the second apply, and tests
networking, persistent storage and disposable local SQLite recovery. It creates
no B2 backups. Cloud backup fixtures and initial recovery exports run only on day
1 UTC through separate monthly proof actions.

VM creation, provider firewalls, the B2 bucket/key, and the 1Password vault/service account are external prerequisites.
Application deployment and full-cluster recovery are outside the current scope.
