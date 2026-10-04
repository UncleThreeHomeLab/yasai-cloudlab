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
| Deployment | Argo CD | Private API, public platform root and optional scoped private sources |
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
networking, cross-node storage, local snapshot restoration and disposable SQLite recovery. It creates
no B2 backups. Cloud backup fixtures and initial recovery exports run only on day
1 UTC through separate monthly proof actions.

VM creation, provider firewalls, the B2 bucket/key, and the 1Password vault/service account are external prerequisites.
Private GitOps inputs are optional and stay in `.env`; their App key stays in
1Password. Full-cluster recovery remains outside the verified scope.

Private repository credentials refresh every five minutes using one item
extraction. Only the rendered Argo fields enter the generated Secret. Provider
rate limits can delay rotation; wait for the service-account quota to reset
instead of forcing repeated synchronization. The credential failure check uses
an isolated project, namespace and temporary credential, verifies successful
access before and after the failure, and cleans up interrupted fixtures on rerun.
It never changes the working ESO credential to simulate authentication failure.

Host packages come from each VM's configured Debian repositories. Apply installs
missing prerequisites; it does not perform distribution upgrades. Runner package
sources and application artifacts are pinned separately.

ESO's bounded chart bootstrap records its writer release before Argo adoption.
`docker compose run --build --rm lab eso-interruption-test` proves initial seed
resume before that release. For bounded same-version recovery, publish
`externalSecrets.reconcile: false` in the public root, run `lab eso-recover`
through Compose, then publish `true` and run `prove`. Recovery refuses an active
Argo writer. Ansible always owns the 1Password bootstrap token.

The Longhorn chart keeps the existing version and storage policy. Its pinned
vendor patch removes Helm upgrade/uninstall hooks and retains CRDs during adoption;
`lab charts` verifies both archive checksums, patch scope, and resource parity.
`lab longhorn-interruption-test` checkpoints and resumes its initial handoff while
an attached disposable volume checks disk I/O. Enable `longhorn.enabled` only after
writer release. To recover, publish `longhorn.reconcile: false`, run
`lab longhorn-recover`, restore reconciliation, then run `prove`. Storage bootstrap
refuses competing Argo operations and preserves existing objects and credentials.
Argo owns explicit Settings; their duplicate controller defaults are removed.
Longhorn alone generates the immutable StorageClass from its Argo-owned ConfigMap.
That ConfigMap preserves its original YAML bytes to prevent controller replacement.

Backup declarations use `platform/storage/longhorn-backup`. The bootstrap-owned
Application receives the destination from the existing ESO Secret; Git contains no
bucket or credentials. Before enabling `longhornBackup.enabled`, run
`lab longhorn-backup-interruption-test` through Compose to seed, stop and resume
without changing object or credential identities. Recovery requires publishing
`longhornBackup.reconcile: false`, running `lab longhorn-backup-recover`, restoring
reconciliation, then running `prove`. These actions do not create off-site backups.
