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

The former ESO/Longhorn renderers and ordinary Ansible apply paths are retired.
Chart modules own their values, image locks and shared storage policy. `lab charts`
checks reviewed semantic hashes as well as artifact and image integrity; intentional
configuration changes require reviewing that contract and running `prove` again.
Bootstrap and explicit recovery render those same charts. Existing VM-generated
manifests are not inputs to apply, verification or recovery.

Certificate support uses cert-manager 1.21.2 and Cloudflare DNS-01. The
`CloudLab/cloudlab-dns01` item requires `API_TOKEN` and `ZONE_ID`; restrict the token
to DNS Edit and Zone Read for that zone. ESO owns the credential, cert-manager
owns ACME account keys and TLS Secrets, and Argo owns their declarations. The
selected zone enters a bootstrap-owned Application at runtime, never public Git.
Staging issuance must pass before production is enabled. Separate wildcard
certificates cover public names and `internal` names; Cloudflare edge TLS and
Istio's workload CA remain separate. No HTTP challenge port is opened.

Certificate setup resumes its durable staging checkpoint after interruption.
Do not delete issued Secrets or account keys to retry issuance. Repair the scoped
credential or controller, then rerun `prove`; changed zones, conflicting owners
and replaced identities require an explicit migration. Verification triggers only
staging renewal with pinned `cmctl`, checks key rotation without replacing objects,
validates production trust/SANs and renewal schedules, and mounts each certificate
in a disposable consumer. This proves forced reissuance, not an observed natural
renewal interval.

Istio ambient uses pinned 1.31.1 release charts with the K3s CNI profile. Only
explicitly labeled namespaces join the mesh; system namespaces and future
connectors remain outside automatic enrollment. The mesh default requires STRICT
mTLS. Workloads also need explicit identity authorization and NetworkPolicy;
the disposable proof tests each boundary separately, including HBONE port 15008.
NetworkPolicy closes then opens only HBONE port 15008; authenticated workload
identity controls callers. Checks use fresh pods because existing HBONE connections
may survive policy updates; they do not prove immediate connection revocation.
No waypoint is needed for these L4 identity policies.

Public and private gateways use separate namespaces, service accounts, certificates
and route selectors. Both services remain ClusterIP, with two bounded replicas.
Istio owns generated gateway workloads; Argo owns Gateway and configuration objects.
Their selected DNS zone comes from the accepted Certificate resources at runtime.
Verification checks actual mutual-TLS traffic metrics, trusted HTTPS, unknown
host/SNI rejection, forbidden route attachment, drift repair and controller stability.

The ten existing Gateway API 1.6.1 standard CRDs match the pinned upstream contract
and retain their K3s/Traefik owner. `prove` checks their specs and retained identities;
it does not introduce a second CRD writer. Keep Traefik until the access cutover,
which must explicitly preserve or transfer CRD ownership before retiring its chart.
Istio's CA and gateway identities are retained in a private recovery checkpoint.
Repair declarations or credentials and rerun `prove`; do not delete CA keys, TLS
Secrets or reinstall controllers to recover. External access and failover proof
belong to the subsequent access cutover.
For focused troubleshooting, `docker compose run --build --rm lab mesh-check`
reconciles the retained mesh configuration and runs its disposable checks. A full
`prove` is still required after setup changes.
