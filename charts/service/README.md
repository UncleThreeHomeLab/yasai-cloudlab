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
| `secrets`, `configMaps` | Approved names and bounded read-only mount paths, each with optional per-container selection (`application`, `dependencies`) |
| `apiToken` | Disabled; approved API clients declare an audience-bound token with short expiry, mounted in the application container only |
| `dnsConfig` | Null for cluster defaults; otherwise the accepted resolver nameservers |
| `isolation.enabled` | Disabled; dormant default-deny NetworkPolicy for workload pods |
| `persistence` | Opt-in replicated storage, at most 4 GiB, retained on removal |
| `exposure` | Class signal only (`none`, `public`, `private`); addresses come from exposure inputs, never the catalog |
| `data` | Optional database/bucket names, scoped credential references and `retain` policy |
| `oidc` | Optional explicit identity client settings; the identity owner compiles clients from the catalog |
| `monitoring` | Disabled; application monitoring stays with its accepted telemetry owner |
| `rollouts.enabled` | Optional stateless Rollout with Gateway API weights and per-revision analysis |

Workloads implement `application-no-api` by default: named ServiceAccount, no
token, Restricted Pod Security, exact read-only mounts and no Kubernetes API
access. Each pod carries its `cloudlab.io/workload` identity and must select
that workload's own ServiceAccount; sharing across workloads is refused.
Controller, job and host-exception profiles are unavailable through
this chart; the platform owns those identities separately.

Source visibility (`approval.visibility`) is independent of network exposure.

Public exposure addresses live only in public `services/exposures.yaml`; private
exposure addresses live only in private `platform/access/policy.yaml`. Service
routes, DNS, tunnel/Access protection, and identity callbacks derive from those
files. Ordinary catalog entries declare only the exposure class; catalog hostname,
access, path, port, backend, and additional-view fields are retired. Notes and
composition keep catalog-driven routes with explicit addresses.

For ordinary `charts/service` entries, declare explicit identity settings:

```yaml
definition:
  oidc:
    enabled: true
    realm: applications
    client: prices-ui
    public: true
    callbackPaths: [/oauth/callback]
    audience: prices-api
    scopes: [profile, email]
    roleMapping: {viewer: [viewer]}
```

These are fields within a complete catalog entry. The identity owner compiles
applications-realm clients from these settings plus approved exposure hosts; its
leased Keycloak writer owns convergence. The reference profile (`clientReference`,
`approval.identityClient`) is retired. For a confidential client, add
`secretReference`, its approved `secretReferences` entry and scoped
`definition.secrets` mount. Missing approved service items are created empty by the
control-machine credential reconciler after the catalog merge, while shared OIDC
keys stay user-supplied. Confidential clients without a ready vault secret stay
pending and never block other clients. Secret, identity and data bindings live only
in the accepted private catalog; per-service `secrets.yaml` files do not exist.

Real browser login and allowed/denied application checks remain required.
Administrator-approved multi-workload charts use optional `approval.composition` in
the same private catalog. Its exact chart source, image value paths, rendered pod
profiles, named backends/selectors, retained claims, aggregate secret item fields and namespace
budget are validated by [the composition owner](../../ansible/playbooks/services/files/compositions.py).
Converge composition namespace admission before enabling the catalog. The workload
project cannot write policies, secrets or release state; a separate platform-owned
ApplicationSet binds every component to the same reviewed release record. Private
values and release metadata stay in `approval.repository`; the application
chart has its own immutable source. Composition `backends` keys exactly match declared exposure hostnames; each
entry supplies its actual Service name, port and pod selector (one backend per host).
Optional listener readiness selects an approved path/status separately from workload
health; it does not prove OAuth consent or application login. Composition canaries are unsupported; ordinary
service and Notes defaults stay unchanged.
Optional composition `connections` declares source/destination workload names and TCP
ports. Each workload then requires an exact `selector` and unique non-default
`podSpec.serviceAccountName`. Ports must belong to declared destination listeners;
backend selectors must match one workload. The platform owns default-deny mesh
policies and permits only these identities and original ports. Application network
policies must allow ambient TCP 15008 only between approved peers. Keep ambient
capture enabled; workload charts cannot own mesh authorization policies.
Current composition transport checks require a primary exposure, Python in its
backend and an existing healthy Python caller in another restricted service
namespace. Confirm these before onboarding; checks do not create running probe pods.
Connection checks also use existing Python callers and live listeners to prove
allowed peers, denied peers and forbidden ports on otherwise allowed peers.
Declare container listener names as `http*`, `ssh` or `postgresql` for harmless
HTTP health, SSH banner or PostgreSQL SSL negotiation checks; other protocols
require a supported verification method before onboarding.
Rollouts require the Git-owned [controller and pinned plugin](../../platform/delivery/rollouts/),
an exposed stateless service and `http-metrics:9091`. The exporter must label
`cloudlab_http_requests_total`, `cloudlab_http_duration_seconds_bucket` and
`cloudlab_http_duration_seconds_max` with `service`, `traffic="release"` and
`revision` from the chart-supplied `CLOUDLAB_REVISION`. Initialize zero error counters.
The maximum gauge must retain the maximum for the evaluation window. Keep this
synthetic traffic separate from user SLOs. [Release policy](release-policy.json)
sets the 120-second window, minimum 230 samples and strict error/latency limits.
Missing, non-finite, low-sample or failed queries abort; they cannot promote.
The platform owns the shared PodMonitor in the existing watched telemetry namespace,
with a cap of eight simultaneous revision targets. Application projects cannot write
telemetry resources or deploy into that namespace.
The catalog delegates only backend weights and revision selectors to Rollouts.
Argo owns Rollout, Services, HTTPRoutes and AnalysisTemplates; Rollouts owns generated
ReplicaSets and AnalysisRuns. Existing Deployments require a staged migration: run
the Rollout alongside the Deployment, verify stable traffic, then retire only the
superseded stateless Deployment. The Notes application repository owns its signed
release demonstration and bounded traffic proof. Platform tests stay offline.
An administrator may set `approval.artifact` with `repository`, `project`,
`releasePath`, `sourceRepository`, retained signing `identities` and `action`
(`Audit` before tested `Enforce`). The repository must match the application and
visibility project; the release path is `apps/releases/<approval.name>.json`.
The platform supplies `artifactPolicyHash` to roll workloads through admission
when approved artifact policy changes, preserving normal rollout availability.
ApplicationSet follows that file on GitOps `main`, publishes digest/source/run
annotations and supplies only the project's pull credential. Public signatures
require the exact GitHub issuer, shared workflow, source repository and main ref;
private verification receives only `ci-private-verifier/public_key`.
Repository-owned public publication instead uses the exact source identity
`https://github.com/<sourceRepository>/.github/workflows/ci.yaml@refs/heads/main`;
the source repository, main ref and issuer checks still apply. Retain old identities
while their signed rollback digests remain deployed or recoverable.
Registry verification uses a pull-only credential copy in Kyverno's namespace;
Kyverno receives no application Secret collection permissions.
The exact declared bootstrap image remains an explicit unsigned recovery exception.
Retain approved signing identities and registry artifacts for rollback.
After a release converges, run `docker compose run --rm --entrypoint python
infra-harbor /workspace/verification/integration/application_release.py`. This
tests enforcement only against named server dry-runs, retains its registry proof
artifacts and pulls the approved digest on both node host networks. Change the
production policy to `Enforce` only after this check passes.
The complete reviewed definition supplies Helm values. When the chart and definition
share the platform repository, one pinned source uses those values directly. A separate
repository uses its approved immutable values source; the complete definition still
overrides it. This avoids conflicting revisions of the same Argo repository.
Public exposure requires an explicit `public`, `human` or `machine` classification.
Private exposure requires an `internal` hostname and tailnet protection. Confidential
OIDC clients require a scoped secret reference; public PKCE clients have no secret.
Callback URLs and web origins derive from approved exposure hosts. Identity alone
creates, rotates and removes clients. Workload mTLS remains a separate mesh boundary.

Service PVCs use one workload replica and retain two storage replicas. The data
module's monthly export covers its SQL/S3 volumes; arbitrary service PVCs need
separately verified backup coverage before holding important data.

Keep the complete administrator catalog in `services/catalog.json` in the designated
private configuration repository. Each entry contains `definition`, `approval` and
`publication` (`ready`, `published` or `retired`). `dataApprovals` binds each request
to its service, name and scoped 1Password item; database bindings also name the
migration item. Optional `applicationRole` and `migrationRole` must appear together,
use distinct non-reserved SQL identifiers, and match the corresponding vault
usernames. Required database fields are `username`, `password`, `database`;
bucket fields are `BUCKET`, `ACCESS_KEY_ID`, `SECRET_ACCESS_KEY`, `ENDPOINT`, `REGION`.
Privileged data credentials and migration credentials never reach application pods.

1. Write the public exposure entry in public `services/exposures.yaml` and merge
   its PR; write private exposures in private `platform/access/policy.yaml` and
   merge its PR. Ordinary catalog entries carry only the exposure class.
2. Review the complete catalog, exact source SHA and approved references, then
   merge the private catalog PR and rotate the services acceptance receipt and
   commitment for the catalog, identity values, and policy paths together.
3. For OIDC, declare explicit client settings in the catalog entry. The identity
   owner compiles the client and converges it through the normal leased writer;
   no identity inventory hand-edit is needed for applications clients.
4. Enable `services.enabled` in the public root; `services.revision` is the exact
   platform commit for its root-owned catalog Application. Missing approved data
   items are provisioned as empty placeholders by the credential reconciler;
   existing values persist. Argo deploys supported definition changes and repairs
   drift without a local catalog apply. Data owners reconcile approved requests
   and grants.
5. Merge the exposure PRs, then read readiness from Argo (routes, certificates)
   and the connectivity reconciler status (DNS, tunnel, protection). For public
   DNS, merge the plan-approval binding PR the reconciler reports; the standing
   loop applies the bound plan with no second command. Backend, client, scoped
   credentials and TLS must converge before protection/tunnel checks and DNS
   publication.
6. Run `docker compose run --build --rm lab prove` for setup changes only.

Private catalog reads use the existing scoped GitHub App. Missing private inputs
stop before mutation or live planning. An HTTPRoute does not create DNS or Access.

Remove reachability through Git: set the public entry to `publication: retired`
and merge its public PR, then bind the resulting Cloudflare plan if public DNS
changes. Remove private policy entries only together with the catalog retirement
in a single atomic private PR; a lone private removal fails closed. Argo
withdraws the routes while the reconciler withdraws DNS/tunnel/protection and
verifies authoritative withdrawal plus route absence. Identity tombstones still
disable clients first through the private revocations registry; service
retirement never disables a shared active client. Retired catalog entries remain
as explicit retention intent. Namespaces, quotas, credentials, PVCs, databases,
buckets and shared resources are retained; service removal never disposes of
data. An exposure-class change requires retirement followed by a separately
reviewed migration, not an ordinary apply.

The pinned Kyverno legacy verifier omits Fulcio intermediate certificates. Public artifact policies therefore pin the public Fulcio roots and intermediate from Cosign-verified Sigstore TUF material; `platform/delivery/services/sigstore-fulcio.lock.json` records its source and checksums. Update these anchors with verification before upstream certificate rotation. Exact GitHub issuer, workflow identity, repository, main ref, SCT and Rekor verification remain required.

The preview owner alone supplies `previewWaypoint` and `previewIdentity` for
namespace-local waypoint enrollment and immutable cleanup metadata. Ordinary
services retain their existing routing and identity behavior.
