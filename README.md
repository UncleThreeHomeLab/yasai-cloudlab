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
| Recovery | SQLite + restic | Consistent monthly control-plane export; separate credentials and acceptance |

## External services

| Category | Service | Purpose |
| --- | --- | --- |
| Storage | [Backblaze B2](https://www.backblaze.com/cloud-storage) | External storage for Longhorn backups |
| Secrets | 1Password | CloudLab vault, accessed with a read-only service account |
| Public access | Cloudflare Tunnel + Access | Outbound tunnel, verified origin HTTPS and explicit human/machine policies |

**Storage:** Applications opt in to Longhorn; `local-path` remains the default.
Longhorn schedules monthly B2 backups and keeps the latest scheduled backup per
volume.

## Automation

| Tool | Purpose |
| --- | --- |
| Ansible | Configure hosts and cluster; verify the result |
| Docker Compose | Run the pinned automation environment |

## Run it

1. Prepare two reachable VMs with automatic time synchronization and Docker Compose. Permit outbound NTP traffic and its replies through upstream firewalls. Apply retries an already active systemd-timesyncd daemon once if the clock is unsynchronized, then waits up to one minute. Verification is read-only; both stop before cluster operations if synchronization fails.
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

Private repository credentials refresh hourly using one item
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

The ten Gateway API 1.6.1 CRDs match the pinned upstream contract and retain their
original identities under a restricted Argo Application. The staged access cutover
retires Traefik before adopting its retained CRDs. `prove` checks their specs,
identities and the sole active GitOps owner.
Istio's CA and gateway identities are retained in a private recovery checkpoint.
Repair declarations or credentials and rerun `prove`; do not delete CA keys, TLS
Secrets or reinstall controllers to recover.
For focused troubleshooting, `docker compose run --build --rm lab mesh-check`
reconciles the retained mesh configuration and runs its disposable checks. A full
`prove` is still required after setup changes.

`docker compose run --build --rm lab access-preflight`
audits live foundation health, retained ownership, legacy ingress dependencies and
external credentials without changing the lab. It exits with status 2 when inputs
are missing. The [access contract](platform/connectivity/access/contract.json) owns
item fields, tags and selected modes; `.env.example` lists runtime inputs. The
charts select two-replica L3 ingress and a separate two-replica auth-mode
API proxy, preserving application HTTPS at Istio. The operator itself remains
single-replica. Cloudflared reads only the pre-provisioned runtime credential; the
1Password reader never creates or rotates credentials.

`docker compose run --build --rm lab access-prepare-tags` prepares only operator
tag ownership through an ETag-guarded policy update, before OAuth credential
creation. It preserves existing grants. Save generated OAuth and machine secrets
once in the declared 1Password items; keep the existing reader read-only.

`lab access-external` through Compose is a guarded external reconciliation path.
It requires prerequisite health and ready access workloads, configures Access
before tunnel routes and publishes DNS last. It retains external identities and
create intents on the existing server under `/var/lib/cloudlab/connectivity/receipts`.
A host lock covers each provider transaction, including runs from another checkout.
Existing local receipts migrate once from the private `ssh_known_hosts` volume.
Retain the server receipts during recovery; never delete them to bypass an ownership error.
Repair missing credentials and rerun. A missing/replaced external identity,
unowned resource, hostname removal or classification change requires explicit
migration. Ordinary apply reconciles local and external resources without replacing
their retained identities.

`lab access-bootstrap` reconciles scoped tailnet grants and the bounded access
Application after the GitOps operator and ESO credentials are ready. A native
Kubernetes admission policy adds probes to new proxy Pods without taking ownership
of operator-generated StatefulSets. Health probes check local process readiness;
they do not replace end-to-end HTTPS and API acceptance.

Private DNS runs as a separate systemd service on each existing host. Tailnet
clients receive the L3 service address; hosts and Pods receive the private gateway
ClusterIP. Both views are authoritative: unknown private names never fall back to
public resolvers. The host service retains original upstream resolvers to avoid a
cluster bootstrap dependency. Configuration is checked with the pinned binary
before activation, and both host resolvers must pass before host resolution changes.
Only the custom CoreDNS forwarding ConfigMap belongs to the DNS Application.
Keep `/var/lib/cloudlab/private-dns`, `/etc/cloudlab-dns`, and the access ownership
checkpoints during recovery. Repair declared inputs and rerun `lab access-bootstrap`;
never delete retained identities to bypass a conflict. Cloudflared uses HTTP/2
transport because the existing network does not pass its QUIC checks.

`lab access-check` tests real outside HTTPS, machine authentication, anonymous
denial, private DNS/HTTPS and Kubernetes RBAC. It then replaces one stateless
connector or gateway Pod, or sends SIGKILL to one verified proxy container. Proxy
Pod identities are retained to avoid overlapping StatefulSet identities after a
forced deletion. Each component gets 90 seconds of new requests after the confirmed
failure, with a maximum 30-second interval without a successful request.
It requires two healthy replicas on distinct nodes before each failure, waits for
both replicas to recover, and removes disposable backend namespaces afterward.
`prove` includes these checks. Human sign-in requires the approved mailbox once;
`lab access-human-proof` reads JSON containing `token` or one raw JWT from standard input,
verifies the Access JWT signature and protected backend, and records evidence
without retaining the session. Repeat checks require the same application identity,
audience and policy. Changed human policy requires a fresh sign-in proof.

For a live Access proof without copying a browser cookie, pipe the pinned helper's
output directly into the proof command. Replace `<application-url>` with the
declared canary URL; use `access-human-proof` for the real application after cutover.

```sh
docker compose -p identity-access-browser -f compose.identity-proof.yaml run --rm -T access-browser access login --app '<application-url>' | docker compose -p yasai-cloudlab run --rm -T lab identity-access-canary-proof
```

Open the headless login link shown on standard error and authenticate in your own
browser. The JWT goes through the pipe, never the terminal or command arguments.
The helper caches sessions only in container memory; `--rm` removes the container.
Never run the first half alone or redirect its output to a file or log.

`lab access-cutover` requires complete replacement acceptance from the last 24 hours,
rechecks access, and audits the stored Helm release for all ten CRD retention rules.
Only then does Ansible disable bundled Traefik and restart K3s. ServiceLB stays
active until its controller removes Traefik's Service finalizer and all load-balancer
workloads. After CRD adoption, Ansible disables unused ServiceLB with a second K3s
restart. These required configuration restarts interrupt the single control plane;
they do not prove control-plane HA. The handoff retains CRD UIDs and pinned definitions, then
assigns their sole ongoing owner to a restricted Gateway API Argo Application.
Keep `/var/lib/cloudlab/connectivity/cutover.json` and `k3s-before-cutover.yaml`.
Rerun `lab access-cutover` after a failed transition; normal apply resumes a prepared
or adopted handoff. Do not restore the old K3s configuration after adoption without
suspending the new CRD owner and reviewing a reverse handoff. Never delete retained CRDs.

Existing host SSH and controller recovery remain independent of the operator and
access paths. Multiple connectors and gateways do not make the single K3s server highly
available.

Application data uses the locked charts and policy in `platform/data`. It starts
with one PostgreSQL 18.4 instance and one SeaweedFS master, volume, filer and S3
instance. Each persistent volume explicitly selects two-replica Longhorn storage;
the global default stays `local-path`. SeaweedFS uses embedded LevelDB metadata.
Native SQL TLS and private S3 HTTPS require scoped application credentials.
After milestone 03 prerequisites, `lab data-bootstrap` reapplies only this module;
`lab data-check` runs its private-access and local recovery gates without B2.
These focused checks do not replace the required full `lab prove`.
Certificate DNS-01 self-checks use public resolvers, independent of private split
DNS; this exposes only the necessary ACME TXT records, not public service addresses.
Argo owns declarations, CNPG owns PostgreSQL roles and generated workloads, ESO
owns application Secrets, and cert-manager owns TLS Secrets. The data reconciler
owns SQL grants, buckets and S3 credential reloads; it does not rely on Helm hooks.

For initial credential provisioning, create a separate 1Password service account
with CloudLab Read Items and Write Items permissions. Put its token in ignored
`.env` as `OP_PROVISION_SERVICE_ACCOUNT_TOKEN`; keep the existing ESO token
read-only. Run `docker compose run --build --rm lab data-credentials`. This creates
only missing items from `platform/data/contract.json` and preserves existing
values. The writer stays local. Database and S3 secrets are generated
securely; the endpoint derives from the existing private DNS zone. The application
backup reuses the existing Longhorn B2 item and native backup store. B2-managed
AES256 encryption protects stored backups; Backblaze holds the encryption keys.
Shared keys do not enforce separation between prefixes.
`lab data-rotate` explicitly rotates the notes SQL password and S3 key pair through
1Password, forces ESO refresh, reloads the consumers, and tests new acceptance and
old denial. A failed run resumes from a private local checkpoint on rerun; no writer
token leaves the runner. Ordinary apply never rotates credentials. Other vault
credential changes reconcile within the hourly ESO refresh plus the five-minute
S3 reload interval. Plan for a brief client reconnect during rotation.

Application backups run monthly, on day 1 at 03:00 UTC. No daily dumps or retained
local backup generations remain. The data owner disables app SQL logins and S3
keys, drains sessions, then cleanly stops PostgreSQL and all SeaweedFS writers.
It takes a coordinated four-volume Longhorn snapshot before restoring service.
The monthly operation uploads those snapshots to the existing B2 target, restores
all four volumes into disposable services, and checks SQL roles, extensions,
object bytes, tags, metadata and attachment references. Only a passing replacement
can retire the previous good generation. The old logical backup path retires
after this gate; no duplicate restic application export remains.

Temporary snapshots are removed after verification. Longhorn may retain removed
snapshot blocks in its active volume chain until they become purgeable; these
are not retained recovery points. Recovery inventories and job receipts remain
locally, not database dumps or object copies. Object checksums stream without
staging object files. Captures admit at most 4 GiB of database data and 8 GiB of
objects. Cold capture causes a brief service outage. No additional writer role
or key may bypass this maintenance boundary.

Physical recovery requires the pinned PostgreSQL major version and matching
SeaweedFS format. Tests use isolated PVCs on the existing VMs, current vault
passwords, verified SQL TLS, and private HTTPS. They do not prove empty-VM recovery.
The legacy StorageClass group name remains unchanged because its parameters are
immutable; it has no independent recurring jobs. Only the coordinated data owner
starts these four backups, excluding disposable telemetry.

Use the Compose entry point with `lab data-monthly`, `data-freshness`,
`data-restore`, or `data-retrieve`. Freshness reads only local receipts.
Transfer, retention and full backup verification are batched monthly.
`data-acceptance-export` is the recorded initial exception for this replacement.
`data-restore` deliberately restores the latest B2 generation into isolated
services. `data-retrieve` independently checks every compressed backup block using
only the checkout and vault reader, without retaining local backup files.
Both restore commands are explicit exceptions to the monthly B2 schedule.
`data-check` tests temporary local snapshots without B2 access or retained backups.

After interrupted maintenance, inspect the failure and use `lab data-resume`.
Retry a failed monthly candidate before another capture. After inspecting an
interrupted test, `lab data-cleanup-fixtures` removes only owner-checked disposable
namespaces and recorded PV identities, never production volumes or good backups.

Whole-lab loss can lose every change since the last successful monthly export,
roughly a month or longer after failures. No continuous WAL archiving or PITR is
provided. Disk replication is not database or S3 service HA. Identity and other
dependent applications require the complete data recovery proof.

Identity acceptance remains gated on live recovery and SSO checks. The pinned
Operator/server/config-cli combination is verified in disposable fixtures; see
`platform/identity/keycloak/contract.json` for inputs, lifecycle ownership,
limitations and client contracts. No Grafana or Harbor installation is included.

Connect to Tailscale and open `https://login.<zone>/realms/platform/account/`
for platform account self-service. Exact split DNS sends this same issuer hostname
to the private gateway, preserving browser SSO and the passkey origin. Platform
self-service also works publicly; administration and management remain private.
The private Keycloak hostname root opens this page;
the explicit master admin console uses its separate master account.

Run `docker compose run --build --rm lab identity-check` for chart and input checks.
Run `docker compose -p cloudlab-identity-proof -f compose.identity-proof.yaml run
--build --rm browser` for the HTTPS reference app, virtual WebAuthn and measured
JWT offboarding proof. Run the `compose.identity-operator-proof.yaml` fixture under
project `cloudlab-identity-operator-proof` with `run --build --rm proof` for Operator
reconciliation. Afterwards clean each named project with `down --volumes
--remove-orphans`; wait for cleanup before restarting it. These fixtures prove no
personal passkey enrollment, production gateway privacy or Argo/Access cutover.
The contract also records the disposable offline emergency/retirement procedure.
Run it after browser proof and before fixture cleanup; it disables the fixture
bootstrap account and temporary emergency client through config-cli.

`lab identity-credentials` creates missing task-owned vault items and preserves
existing values. `lab identity-operation` accepts complete private JSON on standard
input and writes a reviewable source change to the private recovery volume.
It supports provisioning, retirement, removal plans, offboarding and Argo/Access
client plans. It sends no invitations and makes no realm changes.
The output includes `identity/configmap.yaml` and, for Argo, a private values file.
Argo provisioning requires exact public and private origins (`additional_origins`
contains the second origin). `lab identity-private-publish` accepts the same complete
input and creates a reviewable PR in the designated private configuration repository;
`initialize-state` publishes the initial complete inventory. Existing files outside
that bundle and omitted overlays are retained. It requires the local GitHub
provisioning credential and never merges or modifies realms.
GitHub Free does not enforce private branch protection. Private PR review and
compiler validation are procedural safeguards; public implementation PRs remain
protected. Argo values must use a validated immutable private revision.
`set-user-email` accepts exact private `{action, realm, username, email, verified}`
inputs for one active, inventoried membership. It stores an optional
`profile: {email, verified}` on that membership; scoped config-cli reconciliation
manages only those two profile fields. Omitted profiles remain unmanaged.
`verified` is an explicit operator assertion of address ownership, not an SMTP
verification test. This operation sends no messages, resets no credentials and
never re-enables an account. Master administration keeps its separate vault email.
`lab identity-client-credential` accepts private `{action, realm, client_id}` JSON;
initial provisioning can also include the exact confidential `client` contract
before its private publication. Current complete private inputs must be available;
public or retired contracts are rejected. Publish the client after the vault
secret exists, then verify ESO and scoped reconciliation before using it.
Identity credentials refresh hourly to fit the existing 1Password subscription.
Explicit rotation forces one ESO refresh; realm reconciliation still runs every
five minutes. Quota exhaustion blocks credential delivery until reset and never
justifies weaker vault permissions or another subscription.
Provisioning preserves existing secrets. Rotation uses a resumable vault checkpoint
and verifies new credentials accepted and old credentials denied after ESO/CLI
reconciliation. Public or retired clients are rejected. `lab identity-client-remove`
accepts `{realm, client_id}` only after the private retirement/removal tombstone is
published and the client is disabled. It waits the declared session/token bound,
runs the serialized Argo removal job and restores normal reconciliation. These
live operations remain unverified.
`lab identity-offboard` accepts private JSON `{realm, username, user_id, email}` on stdin.
First publish the persistent private user tombstone and let the sole config-cli writer
disable the exact account. The operation refuses missing sources, enabled accounts,
changed IDs, unverified email and machine identities, then invalidates Keycloak
sessions while preserving credentials. Platform offboarding also requires accepted
dedicated Access cutover with no prior provider allowed by managed human applications.
It revokes Access tokens without changing devices or WARP sessions through the existing
external owner. API acknowledgment does not prove browser denial: measure current
Keycloak, Argo and Access sessions separately. Existing signed JWTs can remain valid
until expiry, and unmanaged client lifetimes require separate review. These live
offboarding and integrated deadline checks remain unverified. Runtime phases
`identity-server`, `identity-bootstrap`, `identity-primary` and `identity-scoped` require published,
explicitly enabled Operator/CNPG inputs and verified prior recovery/access receipts.
They preserve bootstrap access; retirement and live cutovers remain incomplete.
`lab identity-recover-startup` repairs an owned server-only installation whose
failed Pod still uses an older template. It stops and resumes the server through
Argo's existing maintenance field, preserves the database, and resumes safely
from a private checkpoint. It never applies to an already bootstrapped realm.
`lab identity-primary-credentials` provisions separate master/platform passwords
and opaque usernames after checking the existing signed human Access proof.
The `keycloak-primary-admin` vault schema is versioned with the identity contract.
Its ESO resource remains declared after initialization; normal writers never mount
primary passwords. This preserves credential ownership without an orphan blocking CD.
Declare the platform username's `platform-admin` membership in the private source,
then run `lab identity-primary`. Initial login requires verified WebAuthn enrollment;
repeat never resets existing credentials or re-enables a disabled account. Enroll
the actual passkeys in your personal vault before retiring bootstrap access.
`lab identity-primary-login-items` creates separate standard Login items in CloudLab:
`keycloak-platform-admin-login` and `keycloak-master-admin-login`. It copies the
existing credentials and private website links; it never creates a passkey or
modifies an existing Login item. Enroll with the 1Password browser extension, then
move those Login items to your personal vault. For platform enrollment, open the
private CD website stored on its item and select Keycloak login. For master, open
the private admin console website. Run this creation command only when
preparing CloudLab items, not after moving them. The original machine-owned
`keycloak-primary-admin` item remains the ESO source during initialization.
`lab identity-login-guide` maintains a separate CloudLab Secure Note named
`keycloak-login-guide` with private login links and account instructions. It preserves
notes outside its managed section and never edits Login items or enrolled passkeys.
Use generated usernames: email login is disabled. The platform account signs into
applications; the separate master account administers the private master console.
The public issuer root opens authenticated platform self-service. Platform account
paths work on both gateways; master, admin/API and management paths remain private.
Private services share one HTTPS listener and certificate so browsers can reuse
HTTP/2 connections across Argo and Keycloak without selecting a different route
table. Exact route hostnames, allowed namespaces and gateway policies enforce
the access boundaries. To verify reuse without credentials, pass private JSON
`{zone, gateway_address}` on stdin to
`docker compose -f compose.identity-proof.yaml run --build --rm -T private-routing`.
The address must be the existing private gateway's tailnet address. All three
private origins must work on each connection, and the canonical issuer must
still deny realm administration.
After both real browser logins and recovery custody are complete, run
`lab identity-retire-bootstrap` with JSON
`{"recovery_custody_confirmed": true}` on standard input. This operation verifies
owned WebAuthn credentials, required user verification, current private membership
and recent master/Argo browser events before stopping the server. It creates one
temporary `keycloak-emergency-<nonce>` CloudLab item with `client_id` and
`client_secret`, delivered only through ESO. An Argo job exercises the official
offline service bootstrap; serialized config-cli jobs disable the exact bootstrap
user, password grant and temporary service. The operation checks unrelated users,
credentials and signing state, then measures or conservatively bounds old admin
JWT expiry to 300 seconds. A private checkpoint resumes interrupted operations;
pending retirement blocks ordinary bootstrap and backup maintenance. Keep the
public revision fixed until retirement finishes. Retired ESO resources and vault
items remain declared without being mounted by the server or normal writer.
Repeat checks active scoped reconciliation and cannot re-enable bootstrap access.
Production retirement is not accepted until this operation passes with real
passkeys and confirmed recovery custody.
Machine bootstrap validates the complete private source but creates no people;
private overlays apply in the primary/scoped phases. Creation-only credentials
do not enter normal CLI state tracking. Scheduled scoped reconciliation retains
remote state and disables checksum caching for drift repair.
Scheduled runs skip an occupied valid writer lock and try at the next five-minute
schedule. Sync runs fail and retry across lease expiry; foreign locks and API errors
never count as a successful skip.
Primary creation adds an admin-only ownership field to the current user profile;
other profile fields and realm attributes remain intact. Creation finishes with
credential-free canonical inputs in the same serialized job, using a separate
primary checksum key. CLI checksum output never feeds back into those inputs.
Phase changes wait for
the previous writer to stop and its lease to expire. Readiness requires Argo to
have compared the current inputs, including changes at the same Git revision.
`lab identity-health` checks live public discovery/JWKS/token access, canonical proxy
headers, denied management paths and private audit permissions using ready ESO inputs.
Probes identify themselves as CloudLab clients; they never impersonate a browser.
After publishing the Argo client and private values together, `lab identity-argo`
reads them with the existing read-only GitHub App, validates the exact overlay at
an immutable commit, and binds it through the public root owner. Run `lab apply`
afterward to reconcile both Argo routes from its ConfigMap interface. Browser,
RBAC and measured session checks remain required before Access cutover. A killed
root handoff can be repaired with `lab gitops-bootstrap` independently of Keycloak.
The handoff grants only the declared ESO kind in the exact root namespace before
CD validation. Recovery verifies saved resource identities and source, stops the
sole controller for that grant, then resumes it; no IdP login is required.
After native Argo convergence, `lab identity-access-prepare` creates or reconciles
the dedicated OIDC provider using the client secret delivered through ESO. Its
host-backed receipt preserves provider identity and tracks credential rotation
without storing the secret. Existing providers and application policies remain
unchanged. Masked provider secrets require browser verification; preparation does
not claim cutover acceptance. An ambiguous interrupted creation fails closed.
After verified real enrollment and bootstrap retirement, run
`lab identity-access-canary`. It creates a disposable protected path on the existing
public smoke host, leaving real application policies unchanged. Open
`/__cloudlab_identity_access_canary`, sign in using the dedicated provider, then
send its Access JWT as JSON `{token}` on stdin to
`lab identity-access-canary-proof`. The signed token, exact policy, backend response
and independent machine denial are verified without retaining the session.
Run `lab identity-access-cutover` within 15 minutes of this proof.
It checks current native Argo configuration,
active private membership, WebAuthn and the dedicated OIDC client before changing
only owned human policies. Approved email, exact `/platform-admin` claim and the
dedicated provider are all required; prior provider is retained. Machine policies
remain independent. Reconciliation preserves the selected provider from its
private host receipt and never contacts Keycloak for this selection.
The dedicated provider's human policy uses the current verified platform email
from its private membership profile. Before cutover, the prior provider's approved
email remains unchanged. Cloudflare account identity and machine policies are
independent of this application policy. Record a new signed browser proof with
`lab access-human-proof` before claiming Access login
acceptance. Provider credential rotation invalidates earlier browser evidence;
both proofs require a newly issued Access JWT and a recent successful dedicated
Keycloak code exchange after configuration. Use a fresh private browser session;
an existing Access organization session can skip the IdP exchange and cannot prove rotation.
role denials, session deadlines and IdP outage still require real integration tests.
`lab identity-access-canary-remove` removes only its exact owned path application
and disposable namespaces. Cleanup remains available without Keycloak login.

Identity shares the existing monthly-only Longhorn backup boundary. Capture hooks
quiesce identity before CNPG shutdown; restore hooks check signing-state hashes
and invalidate sessions in the isolated database. Full identity recovery also needs
current private inputs and membership/revocation review before issuer reopening.
The isolated restore replays current vault credentials and private tombstones,
then verifies a signed JWT under a different internal issuer. No restored gateway
route is created. This implementation still needs live identity restore acceptance.
No daily generations or additional cloud schedule are introduced.
