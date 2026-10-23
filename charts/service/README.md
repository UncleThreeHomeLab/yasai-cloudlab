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
| `exposure`, `additionalExposures` | One primary exposure plus optional private views; common hostname/class/access/path/port fields |
| `data` | Optional database/bucket names, scoped credential references and `retain` policy |
| `oidc` | Optional applications-realm client, exact callback paths, audience, profile/email scopes and role/group mapping |
| `monitoring` | Disabled; application monitoring stays with its accepted telemetry owner |
| `rollouts.enabled` | Optional stateless Rollout with Gateway API weights and per-revision analysis |

Source visibility (`approval.visibility`) is independent of network exposure.
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
ReplicaSets and AnalysisRuns. Do not enable this on an existing Deployment without
an explicitly reviewed migration; Notes retains its accepted signed Deployment flow.
Run `docker compose run --build --rm --entrypoint python lab -m
playbooks.rollouts.tests.proof prove` from a clean published checkout. It applies
the scoped GitOps, service and telemetry owners twice and exercises disposable releases through the
existing private gateway, with verified TLS, 6 RPS, four VUs and 190 seconds per case.
It reuses the accepted signed public image and its unchanged Enforce policy. ESO
delivers only the existing public pull credential; no application credentials enter
the fixture. No application CI or dedicated test repository is required.
It restores the healthy release before removing its data-free namespace. Interrupted
proofs retain `/recovery/rollouts-proof.json`; rerun with `cleanup` to restore and
remove only those owned fixtures. Measurements remain in the recovery volume.
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
   `lab data-credentials`; existing values persist. Then run `lab setup` for prerequisites. Argo reads
   `services/catalog.json` directly from the protected private branch and deploys
   supported definition changes without a local catalog apply or VM lookup.
   Data owners reconcile approved requests and grants.
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

The pinned Kyverno legacy verifier omits Fulcio intermediate certificates. Public artifact policies therefore pin the public Fulcio roots and intermediate from Cosign-verified Sigstore TUF material; `platform/delivery/services/sigstore-fulcio.lock.json` records its source and checksums. Update these anchors with verification before upstream certificate rotation. Exact GitHub issuer, workflow identity, repository, main ref, SCT and Rekor verification remain required.
