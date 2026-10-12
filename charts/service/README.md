# Service contract

Start with [the synthetic definition](../../apps/synthetic.yaml). The chart creates
only a workload, ServiceAccount, ClusterIP Service, optional routes and retained PVC.
The platform owns namespaces, quotas, gateways, policies, data provisioning and
ExternalSecret declarations. ApplicationSets use fixed projects, namespace destinations
and approved immutable sources; authors cannot supply these fields in service values.

| Input | Requirement |
| --- | --- |
| `name`, `owner` | Explicit application and owner labels |
| `image` | Full image reference with SHA-256 digest |
| `ports`, `health` | Named ports and HTTP readiness/liveness paths |
| `resources`, `replicas` | CPU/memory requests and limits within the namespace budget |
| `environment` | Non-secret strings; secret values belong in 1Password |
| `secrets`, `configMaps` | Approved names and bounded read-only mount paths |
| `persistence` | Opt-in replicated storage, at most 4 GiB, retained on removal |
| `exposure`, `additionalExposures` | One hostname/class/access/path/port contract for routes and external consumers |
| `data` | Optional database/bucket names, scoped credential references and `retain` policy |
| `oidc` | Optional applications-realm client, exact callback paths, audience, profile/email scopes and role/group mapping |
| `monitoring`, `rollouts` | Disabled until their separately verified integrations exist |

Source visibility (`approval.visibility`) is independent of network exposure.
Public exposure requires an explicit `public`, `human` or `machine` classification.
Private exposure requires an `internal` hostname and tailnet protection. Confidential
OIDC clients require a scoped secret reference; public PKCE clients have no secret.
Callback URLs and web origins derive from the same exposure hosts. Identity alone
creates, rotates and removes clients. Workload mTLS remains a separate mesh boundary.

Service PVCs use one workload replica and retain two storage replicas. The data
module's monthly export covers its SQL/S3 volumes; arbitrary service PVCs need
separately verified backup coverage before holding important data.

Keep the complete administrator catalog in `services/catalog.json` in the designated
private configuration repository. Each entry contains `definition`, `approval` and
`publication` (`ready`, `published` or `retired`). `dataApprovals` binds each request
to its service, name and scoped 1Password item; database bindings also name the
migration item. Required database fields are `username`, `password`, `database`;
bucket fields are `BUCKET`, `ACCESS_KEY_ID`, `SECRET_ACCESS_KEY`, `ENDPOINT`, `REGION`.
Privileged data credentials and migration credentials never reach application pods.

1. Validate the definition with `docker compose run --rm lab service validate <file>`.
2. Review the complete catalog, exact source SHA and approved references. Use
   `docker compose --profile services run --rm service catalog-propose <file>`
   with the existing GitHub writer supplied through standard input if needed.
3. For OIDC, run `service identity-provision <bundle>` through the same Compose
   entry point. Merge its scoped identity PR, then run `lab identity-scoped`.
4. Enable `services.enabled` in the public root. Provision missing data items with
   `lab data-credentials`; existing values persist. Then run `lab apply`. Argo deploys
   the reviewed catalog and workloads; data owners reconcile requests and grants.
5. Run `service ready <bundle>`, then `service publish <bundle>`. The bundle contains
   `definition`, `approval`, `platformRepository`, `platformRevision`, `origin` and
   `application` (null for public access). Backend, client, scoped credentials and
   TLS must converge before protection/tunnel checks and DNS publication.
6. Run `docker compose run --build --rm lab prove` and the service lifecycle checks.
   Use `service fixture-proof <bundle>` only for the designated disposable fixture;
   it publishes twice, retires reachability/workload, and verifies retained SQL,
   S3, volume contents, credentials and shared resource identities.

Private catalog reads use the existing scoped GitHub App. A local file under
`docs/local` may stage a proposal; it is not required by a clean checkout. Missing
private inputs stop before mutation or live planning. Reviewed Access protection
must already belong to the platform; an HTTPRoute does not create DNS or Access.

Remove reachability with `service retire <bundle>`. DNS and tunnel/routes withdraw
before identity or workload removal. For OIDC, publish `identity-retire`, wait for
disable convergence, then publish `identity-remove` and rerun retirement. Identity
enforces its token/session grace period and preserves the vault value. Retired
catalog entries remain as explicit retention intent. Namespaces, quotas, credentials,
PVCs, databases, buckets and shared resources are retained; service removal never
disposes of data. An exposure-class change requires retirement followed by a
separately reviewed migration, not an ordinary apply.

Rerun an interrupted operation with the same reviewed inputs. Existing client
credentials persist; each stage observes its owner again. Native OpenTofu state and
the versioned catalog remain authoritative. A successful tool apply is not a
distributed transaction; failed native state upload requires the existing protected
state-recovery procedure before publication resumes.
