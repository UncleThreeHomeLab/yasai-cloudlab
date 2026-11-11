# Add a service

Follow these steps for an application built on lab runners.
Use the [service contract](../charts/service/README.md) for deployment inputs.
Complete the dashboard stage as well as CI and publication. Report unfinished
requirements and explicit user waivers before declaring onboarding complete.
Identify all runtime processes, including queue consumers and webhook dispatchers,
and deploy their approved entry points. HTTP readiness does not prove background
work is running; verify a requested job advances beyond the queue.

**User:** make manual GitHub changes and review PRs.
**Agent:** prepare configuration, open PRs and verify deployment.
The user may explicitly delegate PR review and merge to the agent.
Use existing capabilities for the requested stages. Report a blocked prerequisite
or check with its manual step and owning module; continue independent settings.
A failed check does not authorize platform repairs or redesign.
Keep confirmed source-visibility and service-access choices across later stages.
Ask again only for a requested change or conflicting observed state.
Keep application inputs in private GitOps. Never put private repo details,
credentials or diagnostic dumps in this public repo.
Public approval reads use the existing `github-argocd` read App prerequisite in
[Ansible](../ansible/README.md); no application App grant is added for these reads.

Shared access reads private `platform/access.yaml` at the approved identity binding,
with the existing `administrator` field. Private main cannot advance this value;
changing the configured administrator requires an explicitly scoped RBAC migration.
The access chart uses its reviewed public pin independently of public main.

Service catalogs default to private `services/catalog.json`. Administrators may
select `services/catalog-v2.yaml` through public `services.catalogPath`; supported
paths are `services/catalog[-lowercase-name].json` or `.yaml`, directly under
`services/`. Prepare a new catalog without changing the active file, then review
its path and immutable `services.revision` together in one public change. The
existing Application switches owner and catalog together and continues tracking private
main. Preflight validates against that exact public owner's native chart; source
failure blocks validation without falling back to the checkout. Publishers update
only the selected catalog. Initial identity activation still requires an exact
matching source; existing checkpoints without a path refer only to the default.

With an egress-capable owner, ordinary `charts/service` approvals require `egress`;
`[]` renders namespace-wide isolation with no allow rules. Declare each destination:

```yaml
egress:
  - namespace: kube-system
    podSelector:
      matchLabels: {k8s-app: kube-dns}
    ports: [{port: 53, protocol: TCP}, {port: 53, protocol: UDP}]
  - ipBlock:
      cidr: 192.0.2.0/24
      except: [192.0.2.128/25]
    ports: [{port: 443, protocol: TCP}]
```

Use the actual resolver labels; DNS has no implicit allowance. Each peer requires
both the exact namespace and pod labels, or one IPv4 `ipBlock`. Keep external
addresses in private Git. CIDRs require canonical network addresses; exclusions
must be distinct strict subnets. IPv6, hostnames and named ports are unsupported.
Broad CIDRs require an explicit administrator choice; CIDRs do not authorize hostnames.
Rules never add implicit DNS or Internet access. Notes and
compositions retain their own controls and reject this field. Removing a rule
withdraws that allowance. Retiring a retained entry clears all allows while keeping
the deny policy. Keep an egress-capable owner during rollback; whole-entry removal cannot
withdraw policies automatically while catalog pruning is disabled. Before changing
the active owner/path, verify dependencies and actual CNI, mesh and dual-stack
enforcement, including other policies that may add allows. Rendered policies alone
do not establish isolation.

External rules require an explicitly selected owner revision supporting `ipBlock`;
existing owner pins do not advance automatically. Approve external address ranges
separately from promoting the owner. Public HTTPS and dynamic webhooks gain no
allowance from this capability alone.

Run the [egress verifier](../verification/integration/workload_egress.py) against
the two existing nodes before advancing the active owner:

```text
docker compose run --rm --entrypoint python lab /workspace/verification/integration/workload_egress.py
```

It uses local VM bootstrap inputs and creates only receipt-owned test namespaces.
After failure, append the reported `--cleanup RUN_ID`; keep the recovery volume
until cleanup confirms absence. `--resume RUN_ID` finishes cleanup, then requires
a fresh proof. Existing connections and unsupported destinations remain separate gates.
Ambient DNS can answer Service names locally; test forwarded queries separately.
For ambient peers, verify the HBONE transport allowance and use mesh authorization
to restrict workload identity and inner ports.

Use `--external-ipv4` for the isolated external lifecycle. Supply private JSON on
stdin: `addresses` contains two distinct off-cluster IPv4 addresses; `ports`
contains two distinct TCP ports. All four HTTP listeners must return exactly
`cloudlab-external-egress-proof`. Keep these controls reachable throughout the
proof; missing or unhealthy controls leave it unqualified. This does not qualify
hostnames, HTTPS, UDP, IPv6 or established connections.

Shared gateways read `platform/certificates.yaml` from private Git main and
`identity/argo-values.yaml` at the existing approved identity binding revision.
Argo origins advance only after that identity revision is approved; changing main
alone does not authorize new administrative origins. Controllers reconcile these
shared inputs; service onboarding does not apply a gateway playbook.

The `identity.application.enabled` native owner is enabled for the accepted
installation. Initial enrollment requires a separately reviewed bootstrap
profile. Root follows this public setting without retaining a private feature
override. Its ApplicationSet reads the exact approved identity revision's
`identity/keycloak-values.yaml`: installationRevision, loginHost, adminHost,
database, databaseRole, databaseHost, databasePort, databaseCA,
trustedProxyAddresses and retiredEmergencyItem. The private enrollment marker is
fixed to `526891f62eb9b9a50a0ffaf6ef020269d09e7746`; other private pins are refused.
Public `identity.application.installationRevision` selects the supported active chart.
The existing retained task's `keycloak_native_handoff=true` prepares the accepted
idle installation before activation. Preparation requires a separate equality
check of the approved private file and current installation; the host handoff
does not fetch that file. Routine setup observes that owner; maintenance and
recovery retain their four scoped operational fields. Native
proxy inputs support canonical private IPv4 Pod ranges of /24 or narrower.
Realm configuration remains a separate owner. Chart promotion requires a
separately reviewed platform change.

Harbor's native installation owner is enabled for the accepted installation. Its private
`platform/harbor.yaml` accepts only `installationRevision`, `harborHost`,
`loginHost` and `gatewayIP` at the accepted identity binding. The supported
installation revision is `d3d639cf80e8cfecebeb756d666a24db92a6bb74`;
pin promotion requires a separate guarded platform change. Public server
defaults stay in `platform/harbor/server/values.json`. The two Applications
retain data and credentials; coordinated recovery owns only maintenance and
seven replica fields. Routine setup observes the accepted owner; it does not apply Applications.
Explicit registration retains the existing host lock and protected adoption intent.
Fresh enrollment still requires a separately approved disabled bootstrap profile
and durable absence intent; the enabled default does not qualify empty-VM setup.
The retained `harbor_native_handoff=true` task registers the reviewed handoff. Registry API
resources keep their separate native provider owner.
Validated idle captured monthly recovery is preserved through same-resource handoff; its offsite window and cleanup owner remain unchanged.

Native ApplicationSet catalog ownership requires `privateSources.acceptanceCommitment`
once `identity.argo` is bound. The reviewed public SHA-256 commitment
binds one private receipt at `platform/acceptance/private-sources.yaml` to an
immutable catalog revision. Its exact fields are `version`
(`cloudlab-private-source-acceptance/v1`), `consumer` (`private-sources`), `revision`
(40 lowercase hex characters), and a fresh cryptographically random `nonce`
(64 lowercase hex characters). Keep the receipt, source address and revision private.
The native AppSet and generated child declare
`Prune=false,Delete=false`; the native owner also declares create-update retention.
Verification refuses missing or mismatched receipts. The commitment hashes UTF-8 fields separated by
LF: version, consumer, designated private URL, `platform/sources.yaml`, revision,
nonce, followed by a final LF.

The native generator merges a fixed consumer row with the exact private receipt,
so missing input reaches validation. The isolated
[native qualification procedure](../verification/integration/private_source_acceptance.py)
uses fixed `cloudlab-prices-source-proof`, `cloudlab-prices-observability-proof`
and `cloudlab-prices-permissions-proof` scopes. Its guarded seed/adopt interface checks
the same Application and resource UIDs across owner transfer; it does not
authorize production adoption.

The registry receipt above is operational. The separate
`cloudlab-consumer-source-acceptance/v1` binds permissions through its native
ApplicationSet; observability controller integration remains pending.
Receipts use `platform/acceptance/observability.yaml` or
`platform/acceptance/permissions.yaml`, paired with
`observability.configuration.acceptanceCommitment` or `permissions.acceptanceCommitment`.
Its receipt fields are `version`, `consumer`, ordered `paths`, `revision` and
`nonce`. Observability binds the selected `services.catalogPath` followed by
`platform/observability.yaml`; permissions binds `platform/permissions.yaml`.
`read_consumer` authenticates current protected public approval and reads the
complete bundle at one accepted commit. Owners still validate their document
profiles. Permissions use normalized `cloudlab-permissions-input/v2`: the native
Git generator extracts `permissions` into fixed inline chart values; unrelated
root fields are not an authorization interface. One native validating admission policy owns private
subject/profile/scope validation before Application updates. Public profiles have
an independent owner at the same immutable chart pin. Start with an empty assignment
list; converge catalog pin changes before adding IDs. Adding or reusing IDs requires
complete old-state convergence at the same catalog pin. Missing profile
projection pauses Application updates until its independent public owner restores it. Remove an ID,
observe binding absence and fresh denial before reusing it. Production activation
requires complete native invalid-input repair and separately established evaluator
effectiveness. Stored declarations, status and admitted-source convergence alone
do not authorize activation.

Additional isolated private roots use `platform/sources.yaml` in the designated
private configuration repository. Most applications use the existing service
catalog and need no additional root. For an approved separate root:

```yaml
sources:
  - name: example
    repository: https://github.com/OWNER/PRIVATE-REPO.git
    revision: main
    path: gitops
```

Merge the complete list through a reviewed private PR and record its immutable
catalog commit. Publish a fresh `platform/acceptance/private-sources.yaml` receipt
in a later private commit, setting its `revision` to the catalog commit, not the
receipt commit. Approve the matching public `privateSources.acceptanceCommitment`,
then verify native reconciliation: the catalog and child Applications must be
Healthy/Synced and their repository ExternalSecrets Ready. Catalog, receipt-publication
and identity-binding revisions are independent. Argo maintains the restricted
project, repository credential and isolated `cloudlab-private-example` namespace;
registration changes need no Ansible apply.
Private roots accept branches, tags and commit pins; verification snapshots declared
symbolic refs in the designated repository through its authenticated reader.
Invalid YAML or unavailable Git blocks reconciliation and preserves accepted resources.
Removing a row removes its registration and delivered repository credential;
the namespace and child workloads/data are retained. Retire workloads through
their owning declarations before removing a root when cleanup is intended.

Shared DNS-01 issuer and gateway TLS settings live in private
`platform/certificates.yaml` (`zone` and `production: true`). Merge approved
changes through its private PR; Argo reads this file directly, gates production
behind current staging readiness and retains issued credentials. Routine service
onboarding reuses this shared TLS owner and does not run certificate Ansible.
Changing the accepted DNS zone requires a separately scoped migration.

## 1. Create the application repo

1. **User:** identify the intended new repo or an existing repo you administer.
   **Agent:** read and report the existing repo's observed visibility, if it exists.
2. **Agent:** ask whether the source repo should be public or private, unless
   the user already explicitly answered. Wait for that answer before creating
   the repo, selecting GitHub Apps, or generating/approving CI configuration.
   The observed setting is not consent. No default or preselected answer counts
   as confirmation. Source visibility selects the CI trust boundary;
   service network access is a separate choice.
3. **User:** create the repo with the confirmed visibility. For an existing repo
   with different visibility, change it manually to the agreed setting first.
   **Agent:** never change visibility or expand repo grants silently.
4. **User:** push an initial commit and set `main` as the default branch.
   **Agent:** confirm the repo is active, is not a fork, and its actual visibility
   matches the confirmed choice. Stop and resolve any mismatch before registration.
5. **Agent:** collect the application name, `OWNER/REPO`, and visibility for registration.
   Use a name starting with a lowercase letter, followed by lowercase letters,
   digits or hyphens; maximum 35 characters.

**Done when:** the repo has a `main` commit and its actual visibility matches
the user's explicit choice.

## 2. Set the source review boundary

Private source repositories do not require branch protection or a plan upgrade.
Review and merge through PRs, then explicitly approve each exact main revision
before CI access. Private PR/dev jobs stay disabled in this mode. This does not
waive the separate automatic release merge guard in section 5.2.

The protection steps below apply to public source repositories only.

1. **User:** open the repo's **Settings > Branches**. Add a branch protection rule
   for `main`, or inspect an existing rule before changing it.
2. **User:** require a pull request before merging. Set approval requirements
   to match available reviewers.
3. **User:** leave force pushes and branch deletion disabled. Save the rule.
4. **Agent:** confirm GitHub reports `main` as protected. Check the saved rule
   requires PRs and blocks force pushes and deletion.
5. **User:** after the first successful test check, open **Settings > Branches**
   and edit the `main` rule. Enable **Require status checks to pass before merging**.
   In **Search for status checks**, search the actual successful name, for example `test`.
   Click the matching result so it appears in the required list, then save.
   The checkbox alone is insufficient; do not require a check that has never run.
   **Agent:** verify the named check appears in classic protection's `contexts`/`checks`
   or the active ruleset's required checks. An enabled rule with empty lists is incomplete.

**Done when:** public protection is active, or private changes use reviewed PRs
and exact main-revision approval. Add public required CI checks once CI works.

Private sources use exact-revision approval without requiring branch protection.
The existing fallback requires explicit approval of each exact `main` revision.
Private PRs get no runner access in that mode. Never silently use this fallback.

See GitHub's [branch protection instructions](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule).

## 3. Grant the runner App access manually

**Agent:** before selecting an App, confirm section 1's explicit visibility choice
matches the repo's actual visibility. If either is missing or conflicting, stop
and resolve it with the user before granting access. Use the confirmed choice below.
The names below identify lab credentials; confirm the matching installed App.

| Source repo | Runner App credential |
| --- | --- |
| Public | `github-arc-public` |
| Private | `github-arc` |

A public-source app uses `github-arc-public` while its runner/service configuration
remains in private GitOps; service network access is a separate choice.

1. **User:** open the repo owner's account or organization settings.
   Find **Installed GitHub Apps** and select **Configure** for the matching App.
2. **User:** use **Only select repositories**. Add the application repo.
   Preserve existing approved selections. Save.
3. **Agent:** confirm the installation includes the repo and grants repository
   **Administration: write** and **Metadata: read**. No organization grants are needed.
   Report mismatches; do not expand permissions automatically.
4. **Agent:** confirm the matching credential exists in the CloudLab vault.
   Required fields: `APP_ID`, `INSTALLATION_ID`, `PRIVATE_KEY`.
   Never print or copy secret values into the repo.

**Done when:** the matching runner App can access the selected repo.
App access alone does not enable repository GitHub Actions, register runners
or approve workflows.

See GitHub's [installed App instructions](https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps).

### Keep release access separate

With automatic promotion, release Apps propose image-update PRs in the owning GitOps repo.
Manual private promotion uses local human authentication; CI receives no release App credentials.
Do not add the application source repo to a release App for runner registration.

| Source repo | Release App credential | GitOps destination |
| --- | --- | --- |
| Public | `github-release-public` | Designated public platform repo |
| Private | `github-release-private` | Designated private configuration repo |

Reuse existing destination grants. Release Apps must not merge their own PRs.
GitOps merge protection remains with its existing declarative owner;
the manual steps above apply to the application source repo.

## 4. Set up the repo's runner controller

Run commands from the root of this platform repo, unless stated otherwise.
This step creates the controller that manages the repo's runners.
It does not enable jobs yet.

### 4.1 Check the existing CI platform — Agent

Check the shared controller quota before adding a service. Public root
`ci.applicationCapacity` reserves one controller and two listeners per application,
plus the shared controller and one rollout slot. Increase this reviewed GitOps
setting when the approved application count grows; keep runner job budgets unchanged.
Never patch the live quota to bypass its declarative owner.

1. Use a clean checkout of a reviewed, published platform revision.
2. Check `ci.enabled: true` in
   [`gitops/roots/public/values.yaml`](../gitops/roots/public/values.yaml).
   Confirm Argo has deployed the CI ApplicationSets.
3. Confirm CI tool images were published and qualified on both nodes
   before onboarding runners for a new repo.
4. Confirm local `gh` authentication can read the application repo.
   The application must belong to the same owner as the public platform repo.
   Read the immutable repository id; renames never move runner authorization.

If prerequisites are missing, stop. Use the
[CI platform setup](../ansible/README.md) before onboarding the application.
Do not rebuild or requalify working CI tools for each new repo.

### 4.2 Write the registration in private GitOps — Agent

Open a checkout of the private repo. The commands below assume that checkout
is `../cloudlab-config`, beside this platform checkout. Substitute your actual
checkout path if different.

Create a branch in the private checkout:

```sh
git -C ../cloudlab-config switch -c onboard/example-app
```

Create `platform/ci/applications/example-app.yaml` in that private checkout,
following [`registration.schema.json`](../platform/delivery/ci/registration.schema.json):

```yaml
application: example-app
source:
  repository: OWNER/REPO
  repositoryId: "REPOSITORY_ID"
  visibility: public
ci:
  profile: public-main
  approval:
    revision: REVIEWED_MAIN_SHA
  jobs:
    test: true
    publish: false
```

Replace `example-app`, `OWNER/REPO`, `REPOSITORY_ID` and `REVIEWED_MAIN_SHA`.
Set `visibility` to `public` or `private` to match GitHub; observed visibility
must match the declaration. Use the same application name in paths below.
Private sources use exact-revision main-only approval; private PR/dev jobs
stay disabled. A new source revision never inherits a previous approval.

This file is the versioned registration input. Argo deploys the pool files
derived from it (step 4.3). Do not copy registration files into this public repo.

Dormant annotated copies live at `platform/delivery/ci/examples/registration.example.yaml` and `release.example.json`; no reconciler reads that path. The live registration is `platform/ci/applications/<name>.yaml` in private GitOps; the live release record stays `apps/releases/<name>.json` in the owning GitOps repo per `release.schema.json`.

### 4.3 Review the derived pools — Agent

Argo derives the controller, runner and publisher pools from the registration
during reconciliation; no pool files are authored. The fixed platform profile
[`platform/delivery/ci/pool/values.json`](../platform/delivery/ci/pool/values.json)
supplies the runner pod specification, tool digests, isolation and budgets;
the registration carries only identity, approval and destination bindings:

| Component | Derived content |
| --- | --- |
| `controller` | Watched namespace `cloudlab-ci-public-example-app` (or `cloudlab-ci-private-example-app`); `runnerPools: 1` (`2` with publishing) |
| `runner` | `cloudlab-example-app` in the watched namespace; repository endpoint; `test` and main-only `build` eligibility binding `repository_id`, `repository`, `workflow_ref: OWNER/REPO/.github/workflows/ci.yaml@<ref>`, `workflow_sha` and `sha` to the approved revision; `testing.image` pin |
| `publisher`, publishing only | Separate publisher role `cloudlab-example-app-publish`; `publish` eligibility; `publishing` with application, source and release repository identities, registry, project, workflow identity, release visibility and mode |

For `main` approvals, `ref` is `refs/heads/main` with `push` and
`workflow_dispatch` events. For public PR test-only approvals, `ref` is
`refs/pull/PR_NUMBER/merge` with the `pull_request` event and `test` job only,
and the approved revision must be the PR's current merge revision. The pool
chart validates every binding; Argo rejects mismatched identity, visibility,
workflow approval or publishing destination.

Retire `platform/ci/pools/example-app/` after the derived pools converge;
the ApplicationSets no longer read it. Removing the registration deletes its
owned pools after review; keep the registration while the repo needs CI.
Never widen runner access, credentials or resource budgets beyond the fixed
profile.

### 4.4 Propose the registration in private GitOps — Agent, then User

1. **Agent:** confirm the registration YAML is in the private repo
   (`platform/ci/applications/example-app.yaml`).
   Do not copy it into this public repo.
2. **Agent:** review the file before opening a PR. Confirm application name,
   immutable repository id, visibility namespace, approved revision,
   qualified tool digests and immutable `testing.image`.
   For this example, the controller name is `cloudlab-example-app-controller`;
   its watched namespace is `cloudlab-ci-public-example-app` for public repos,
   or `cloudlab-ci-private-example-app` for private repos.
3. **Agent:** commit the file, push `onboard/example-app` and open a PR
   targeting private `main`.
   Preserve existing files for other applications. If this application already
   has configuration, review its diff instead of treating it as a new installation.
4. **User:** review and merge through branch protection.

Do not enable `jobs.publish` until publishing is approved. Publishing also
needs section 5.2 prerequisites; the controller quota derives the second pool.
Do not manually create runner pods or apply pool manifests.

### 4.5 Verify Argo deployment — Agent

Use the existing private Argo/Kubernetes access to check:

| Check | Expected result for `example-app` |
| --- | --- |
| Argo application | `cloudlab-ci-example-app-controller` exists; Synced and Healthy |
| Controller Deployment | `cloudlab-example-app-controller` is Available in `cloudlab-ci-system` |
| Watched namespace | Matches the visibility namespace from step 4.4 |
| GitOps source | Tracks private `main` containing the merged registration |

Argo reads `platform/ci/applications/*.yaml` automatically.
If the application is missing, inspect the
`cloudlab-ci-application-controller` ApplicationSet and its private source access.
If deployment fails, inspect Argo conditions and controller events before changing inputs.
Keep credentials and diagnostic dumps out of tracked files.

`ci.poolEnabled` controls the older shared fixture pool. Leave it unchanged
when adding these application-specific controllers and pools.

**Done when:** the repo's controller is healthy. Jobs remain disabled until
registration approval derives the runner pool and, when needed, the publisher pool.
Tests select `cloudlab-example-app`; publishing, when configured, selects
`cloudlab-example-app-publish`. Workflows must not select GitHub-hosted runners.

## 5. Enable application CI

Use the application repo for build logic and private GitOps for runner configuration.
Keep the section 4 platform prerequisites in place. No GitHub-hosted runners are used.
Test-only CI is supported. Add publishing only when required; it is not a prerequisite
for running application tests on lab runners.
PRs and every non-main branch, including development branches, run direct tests only.
They never build images. Protected `main` runs tests first, then any configured builds
and publishing jobs.

**Agent:** enable this flow only after the published platform includes direct-test
support, its immutable runner/builder pins are approved, and the executor is qualified
on both nodes. The retained CI receipt must record `direct_test_nodes_verified: 2`
and the matching `direct_test_profile_sha256`; never edit the receipt manually.
Require an approved dependency-environment digest. Older tool pins do not provide this flow.

**Agent:** before running workflows, inspect repo **Settings > Actions > General**
or `GET /repos/OWNER/REPO/actions/permissions`. Confirm Actions is enabled and the
required pinned actions/workflows are allowed under organization policy.
Use an existing accepted settings owner where applicable; otherwise the **User**
or an explicitly authorized **Agent** performs repository-level bootstrap.
Keep organization policy unchanged and preserve workflow-token defaults:
`default_workflow_permissions: read`, `can_approve_pull_request_reviews: false`.

### 5.1 Prepare the application files — Agent, then User

1. **Agent:** use the application's existing test entrypoint, for example
   `deploy/testing/run_tests.sh`. Run the checked-out source directly with
   `cloudlab-test`, offline at `/app`, with fresh writable test state.
   The checked-out tracked source is read-only; tests receive no runner credentials.
2. **Agent:** prepare a dependency-only test environment separately from reviewed application `main` (protected for public sources), using the procedure below.
   Do not bake application code or tests into the environment or build it inside PR/dev tests.
   Review its immutable `testing.image` pin with private runner configuration.
3. **Agent:** add or update `.github/workflows/ci.yaml` in the application repo.
   Use a direct `test` job on eligible internal PRs, branch pushes and `main`.
   Put image builds in a separate `build` job with `needs: test`, restricted to
   protected `main` pushes or manual dispatch on `main`. No PR/non-main build job runs.
   Optional `publish` also requires successful tests and any configured build job,
   and has the same main-only restriction. Enable `workflow_dispatch`
   so the approved revision can be run after runner setup.
4. **Agent:** choose the supported workflow form below. Pin external actions
   and reused workflows to reviewed 40-character commits. Give jobs bounded
   timeouts, at most 25 minutes, and only required token permissions.
5. **User:** review and merge the application changes through branch protection.
   **Agent:** record the resulting application `main` SHA for approval.
   Jobs cannot execute on the new lab pool until section 5.4 is complete.

| Source repo | `.github/workflows/ci.yaml` form | Assigned runners |
| --- | --- | --- |
| Public, protected `main` | Repository-owned direct `test`, main-only `build` and optional `publish` | Tests/builds: `cloudlab-example-app`; publishing: `cloudlab-example-app-publish` |
| Private, exact main approval | Pinned shared direct `test` and main-only `publish` | `cloudlab-example-app` and `cloudlab-example-app-publish`; no PR/dev jobs |

For public repository-owned jobs, put the assigned name directly in `runs-on`.
Keep test/build logic in the application repo. With an approved test environment
and an existing `deploy/testing/run_tests.sh`, the test job runs:

```sh
cloudlab-test --source . -- sh deploy/testing/run_tests.sh
```

This job runs tests, not a Dockerfile build. It never prepares its own environment.
Only main build jobs use BuildKit against approved application Dockerfiles for
`linux/amd64`. The existing publisher expects root `Dockerfile`'s `runtime` target.
For publishing, check out the
reviewed platform implementation under `platform/` and the application under
`application/`, then run
`python3 -I -S platform/platform/delivery/ci/publisher/publisher.py`.

The pinned [application-test.yaml](../.github/workflows/application-test.yaml)
runs direct tests through `cloudlab-test` using `deploy/testing/run_tests.sh`.
For private sources, call this single-job workflow from `test` and approve each
exact main SHA in the registration. Do not enable private PR/dev
jobs or substitute a prior image-building revision. Public repository-owned jobs
retain their protected-main and approved-workflow requirements.
Use [application-publish.yaml](../.github/workflows/application-publish.yaml)
as the reference for main-only publishing layout and permissions.
Public signing requires `id-token: write`. The shared publishing workflow also
requests that permission. Test jobs use Contents and Pull requests read access.

#### Prepare and approve the dependency environment — Agent, then User

For public sources, require protected main. For private sources, review the exact
main recipe and record its SHA for registration approval.
The owner requires clean tracked source, matching labels and
current GitHub main. Private environments publish to `cloudlab-private`; only the
private pool receives its pull-only credential. Never place private images or
source metadata in the public project. Scanning gates remain mandatory.

Run these operations from a normal, clean, published platform clone.
Use the reviewed application's actual dependency recipe and complete test entrypoint;
the examples below use `deploy/docker/tests.Dockerfile`, target `test-environment`,
and `deploy/testing/run_tests.sh`.

1. **Agent:** confirm the recipe and test entrypoint are reviewed on protected public
   `main`. Read its current SHA:

   ```sh
   gh api repos/OWNER/REPO/branches/main --jq '{protected: .protected, sha: .commit.sha}'
   ```

   For public sources, require `protected: true`; private sources use exact revision approval. Replace `ENV_MAIN_SHA` below with that exact SHA.
   Create fresh ignored `.infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/tracked-source/`.
   This environment revision is separate from the later workflow-approval SHA.
2. **Agent:** clone the exact revision into ignored scratch space with Unix line
   endings, without changing host Git settings:

   ```sh
   git clone --config core.autocrlf=false --branch main --single-branch https://github.com/OWNER/REPO.git .infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/source
   git -C .infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/source rev-parse HEAD
   git -C .infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/source status --porcelain --untracked-files=all
   ```

   Require the recorded SHA and empty status. Reuse an existing clone only after
   these checks pass. Export that revision's tracked source:

   ```sh
   git -C .infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/source archive --format=tar --output=.infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/source.tar ENV_MAIN_SHA
   tar -xf .infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/source.tar -C .infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/tracked-source
   ```

   The export omits `.git` and untracked `.env` or credentials. Inspect tracked inputs;
   stop if secrets or credential files are tracked. Never mount the whole app checkout for validation.
3. **Agent:** build the dependency-only target from that canonical tracked source:

   ```sh
   docker build --platform linux/amd64 --file .infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/tracked-source/deploy/docker/tests.Dockerfile --target test-environment --label org.opencontainers.image.source=https://github.com/OWNER/REPO --label org.opencontainers.image.revision=ENV_MAIN_SHA --tag example-app-test-environment:ENV_MAIN_SHA .infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/tracked-source
   ```

   The source label omits `.git`; the revision label must identify the actual build source.
   Keep dependency downloads on HTTPS with trusted CA bootstrap and TLS/package-signature
   verification. Preserve secret-excluding `.dockerignore` rules and batch necessary
   allowlisted layers within the real lab scratch budget; local overlay success is insufficient.
4. **Agent:** run the complete suite offline against current tracked source.
   Replace `TRACKED_SOURCE_ABSOLUTE_PATH` with the absolute path of the exported
   `tracked-source/` directory, not the application checkout:

   ```sh
   docker run --rm --platform linux/amd64 --network none --workdir /app --mount "type=bind,source=TRACKED_SOURCE_ABSOLUTE_PATH,target=/app,readonly" --entrypoint sh example-app-test-environment:ENV_MAIN_SHA deploy/testing/run_tests.sh
   ```

   Require the full suite to pass before saving that tested image, without rebuilding or retagging it:

   ```sh
   docker image save --output .infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/environment.tar example-app-test-environment:ENV_MAIN_SHA
   ```

   Mount no `.env`, `.git`, credentials or Docker socket.
   Keep test state temporary; this local check does not replace native executor qualification.
5. **Agent:** scan that unchanged archive with the current locked scan
   configuration and publish it to the visibility-matching Harbor project.
   Require the locked scan to pass unchanged; never weaken its gate.
   If protected `main` advances before publication, stop and rebuild/retest from its new SHA.
   Never relabel an old archive to match a newer revision.
   Record the immutable pushed reference as ignored `reference.json` with shape
   `{"image": "<immutable registry reference>"}`.
   Set `testing` in the private registration
   `platform/ci/applications/example-app.yaml` to that object,
   preserving the other inputs. **User:** review it with the runner configuration PR.
   Enable no workflow until both the full suite and scan pass and the environment pin is approved.

**Done when:** the dependency-environment pin and direct-test workflow are reviewed,
the source commit is recorded, and builds are restricted to tested protected `main`.

### 5.2 Check registry and release prerequisites, publishing only — Agent

Skip application-release prerequisites when publishing is not requested.
Keep section 4's platform prerequisites and section 5.1's approved test environment.

1. Confirm the existing Harbor project matches source visibility:
   `cloudlab-public` or `cloudlab-private`. Both require authentication.
   Use the [Harbor API contract](../infra/harbor/contract.json) for accepted
   projects, robot permissions and provisioning operations.
2. Confirm CloudLab vault items `harbor-cloudlab-public-pull` and
   `harbor-cloudlab-public-push` exist for public sources, or their
   `harbor-cloudlab-private-pull` and `harbor-cloudlab-private-push` equivalents.
   Required fields: `username`, `password`, `secret_version`.
   Use existing credential owners to create missing items; preserve existing values.
3. For automatic promotion, confirm the matching release App can propose PRs in the destination below.
   Use the [Harbor installation contract](../infra/harbor/contract.json)
   for App fields and grants. Keep App keys in 1Password.


4. For automatic promotion, confirm the destination has the required server-enforced release merge guard:
   approved administrators merge through PRs; release Apps cannot merge.
   Use the existing [workflow policy owner](../infra/github-workflows/merge-guard.tf).
   Private exact-revision approval does not waive this guard. If the destination
   cannot enforce it, stop publishing rather than bypassing the check.
5. For private signing, confirm CloudLab items `ci-private-signer/private_key`
   and `ci-private-verifier/public_key` exist with their retained values.
   Use the existing credential owners to create missing items; preserve
   existing keys. The local provisioning token stays local.
   Never put secret values in GitOps files.

| Source repo | Release App credential | Release file destination |
| --- | --- | --- |
| Public, default destination | `github-release-public` | Public platform repo: `apps/releases/example-app.json` |
| Public, explicit private destination | `github-release-private` | Private GitOps repo: `apps/releases/example-app.json` |
| Private | `github-release-private` | Private GitOps repo: `apps/releases/example-app.json` |

Set the `publishing` block in the private registration
`platform/ci/applications/example-app.yaml` to select the designated
`releaseRepository` GitOps destination. Registry project and signing still
follow source visibility. Private source releases cannot target public GitOps.

For multiple images, add `components`, mapping each component name to its relative
`dockerfile` and optional build `target`, plus an explicit `primaryComponent`.
All components use the application's approved registry repository. The publisher
scans, publishes and verifies every signature before proposing one release file.
That file adds `components` and `primary_component`; its `digest` remains the primary image.

#### Manual private promotion

Set `releaseMode: "manual"` with an explicit private `releaseRepository` in
the registration. No CI pod receives GitOps write credentials.
Automatic promotion's guards stay unchanged.

CI scans and signs all images, then signs an immutable candidate in the same
authenticated Harbor application repository. Its tag is
`release-candidate-SOURCE_SHA-RUN_ID-ATTEMPT`, covered by existing immutable `release-*` policy.
CI prints only `candidate_digest`;
release JSON stays in Harbor until a reviewer submits the release PR.

After the main workflow completes successfully, an authorized reviewer verifies
the completed run and attempt, the approved publisher configuration, the
candidate digest and all signatures, then submits `apps/releases/example-app.json`
directly as a private PR with the verified `digest`, `source_revision` and
`workflow_run_id`. Review that PR normally; the submitter never merges their
own release. Do not upload candidate JSON to public GitHub artifacts or release files.

**Done when:** registry/signing inputs and either guarded automatic promotion or
reviewer-submitted manual promotion are configured.

### 5.3 Approve the runner configuration — Agent

Read the existing private registration:
`../cloudlab-config/platform/ci/applications/example-app.yaml`.
Keep application name, source identity and visibility consistent with section 4.
Include the reviewed `testing.image` pin from section 5.1.

Replace `REVIEWED_MAIN_SHA` with the exact 40-character application `main`
commit from section 5.1. For public sources, require protected main; for
private sources, use the pinned shared test/publish interface and the reviewed
current main commit. Review and merge the application PR before this
main-only approval; no private PR job receives runner access. Renew approval for
every source revision. Repository-owned approval remains public-only.

Update `ci.approval.revision` (and `ci.jobs`) in the registration; Argo
re-derives the pools from section 4.3:

| Component | Purpose |
| --- | --- |
| `controller` | Controller configuration; publishing updates quota to `runnerPools: 2` |
| `runner` | Approves direct tests and any main-only build job on `cloudlab-example-app`; pins the test environment |
| `publisher`, publishing only | Approves publishing and assigns `cloudlab-example-app-publish` |

Without publishing, the controller normally remains unchanged; no second-pool
quota is needed. Only for publishing, complete section 5.2 and add the
`publishing` block to the registration.

The registration binds workflow approval and, when publishing, the release
destination; it does not deploy runners, create registry credentials or publish
an application image.

**Done when:** the registration covers the reviewed application revision.

### 5.4 Deploy the approved pools — Agent, then User

1. **Agent:** confirm the registration in private
   `platform/ci/applications/example-app.yaml`.
   Review the jobs; tests and main-only builds normally leave the controller unchanged.
   For publishing, include `jobs.publish` and the `publishing` block.
2. **Agent:** review the diff. Confirm repo identity, visibility, workflow approval,
   runner names, qualified tool digests and immutable `testing.image`;
   check release destination and publishing
   credential references only when publishing is enabled.
   Open a private GitOps PR. Preserve other applications and existing secret values.
3. **User:** review and merge through branch protection.
4. **Agent:** wait for Argo applications `cloudlab-ci-example-app-controller`
   and `cloudlab-ci-example-app-runner` to become Synced and Healthy.
   If publishing, also check `cloudlab-ci-example-app-publisher`.
   Confirm the enabled pools and their required Secrets
   converge in `cloudlab-ci-public-example-app` or `cloudlab-ci-private-example-app`.
5. **Agent:** check the application's **Settings > Actions > Runners** for
   the assigned scale sets. Runners are ephemeral; idle pools need not retain job pods.

**Done when:** the requested pools exist and only approved workflows can use them.

### 5.5 Run CI and optionally publish an image — Agent, then User

1. **Agent:** verify eligible PR and non-main pushes run direct `test` only, with no
   image build. Then dispatch `.github/workflows/ci.yaml` on the approved application
   `main` revision. Confirm direct tests pass before build/publish jobs start.
   Non-main tests require the current branch head and original actor's current repo write permission.
   Do not switch jobs to GitHub-hosted runners to resolve a queued job.
2. **Agent:** confirm the real test suite passes against the current source.
   Only protected `main` then runs configured image builds. Skip publishing when not requested.
   When enabled, publishing builds root `Dockerfile`'s `runtime` target, or the
   reviewed component Dockerfiles and targets. It scans each image, pushes it to
   the matching Harbor project and verifies its signature. It then proposes
   `apps/releases/example-app.json` in the destination
   from section 5.2.
3. **User:** if publishing, review and merge the release PR through branch protection.
   **Agent:** verify the release file records the expected `digest`,
   `source_revision` and `workflow_run_id`. For component releases, check every
   component digest and that `primary_component` matches `digest`.
   The release App never merges its own PR.
4. **User:** where protection is supported, open **Settings > Branches** and edit
   the application `main` rule. Enable **Require status checks to pass before merging**.
   In **Search for status checks**, search the actual successful check name, for example `test`.
   Click the matching result to add it to the required list, then save.
   **Agent:** verify GitHub reports that named required check in classic protection
   or an active ruleset, not merely an enabled checkbox or empty `contexts`/`checks`.
   Keep these manual protection changes with the user.
5. **Agent:** if publishing, retain the published digest for service deployment.
   If workflow bytes change, renew workflow approval before expecting jobs to run.
   Private exact-revision mode also needs renewed approval for each source commit.

**Done when:** the real tests pass on lab runners and required check configuration
matches the approved protection mode. If publishing was requested, its signed image
and initial release must also pass review. CI without publishing creates no approved
application release; stop before service deployment until artifact publication is configured.

## 6. Deploy the service

**Agent:** check application topology against the approved chart before promising deployment
or preparing catalog changes. The shared `charts/service` contract uses one image per
service, fixed non-root containers, read-only root filesystems and dropped capabilities.
It does not accept arbitrary multi-image stacks, privileged workers or host access.
If no existing approved declaration fits, report the unsupported requirement to the
service owner and stop deployment. Continue independently requested CI work;
CI approval does not authorize deployment or a new platform implementation.

**Before starting:** complete section 5's publishing path and have its approved image digest available.
Section 4 creates only the controller; it does not complete CI setup.

Use `example-app` below as the service name. Service names allow at most 31 characters.
Private paths are relative to the `PRIVATE_CONFIG_REPOSITORY` checkout
(`../cloudlab-config` in section 4). Platform paths are relative to this public repo.

### 6.1 Define the service — Agent

1. Open private `services/catalog.json`. Add an `example-app` entry to `catalog`,
   or update its existing entry. Preserve all other entries and `dataApprovals`.
2. Set the entry's `definition.name`, `definition.owner` and `definition.image`.
   Use the approved full image reference ending in `@sha256:<digest>`.
3. Set `definition.ports`, `definition.health`, `definition.resources` and
   `definition.replicas` to match the application. Put non-secret settings in
   `definition.environment`.
4. Use [the synthetic definition](../apps/synthetic.yaml) and
   [service schema](../charts/service/values.schema.json) for required fields.
   Keep the complete definition inside the catalog entry.

**Done when:** the catalog describes the image, health checks and workload budget.

### 6.2 Declare dependencies — Agent, then User

Argo CD owns the shared data Applications from the pinned public charts and approved
private binding. Native settings require authenticated sources and the registered
settings ConfigMap; repair continues under the data owner lock.
Maintenance and hibernation use two scoped Root inputs; Root alone converges the
data Application's complete source array. Seaweed replica operations remain scoped
to its single source. Operational overrides must agree before source-owner migration.
Initial bootstrap does not replay accepted workloads or generate a desired-value cache. Routine private
catalog request advancement retains its scoped source and no-adoption gates.
Data reads the reviewed `services.catalogPath`; unavailable selected inputs never
fall back to the legacy catalog. Validate the complete selected catalog at its
accepted private revision before switching paths. Do not substitute a service playbook.

For application SQL schemas, export reviewed, repeatable SQL from the application
source and record its SHA-256. Versioned migration execution currently has no
supported executor; do not run ad-hoc SQL against shared data. No migration
credential reaches application pods. Configure the application to check its schema
version instead of changing schemas at runtime. Reapply only reviewed SQL;
destructive migrations require a separate explicit data scope.

1. **Agent:** update the same entry in private `services/catalog.json`.
   Declare required SQL/S3 resources in `definition.data`, storage in
   `definition.persistence`, secret mounts in `definition.secrets`, and login in
   `definition.oidc`. Leave unused features disabled or empty. Ordinary storage
   is one claim of at most 4Gi; composition claims must fit their approved
   claim count and storage budget, or the catalog render fails closed.
2. **Agent:** add scoped data bindings to the catalog's top-level `dataApprovals`.
   Match the service, resource name and credential reference. Include the database
   migration item when needed. Approve required references in
   `approval.secretReferences`; never grant application pods privileged data credentials.
   After merge, the application-data-reconciler provisions approved buckets and
   least-privilege SQL grants without operator commands; buckets, databases and
   their access bindings are retained on removal.
3. **User/Agent:** keep secret values in 1Password's CloudLab vault.
   Use the [service contract](../charts/service/README.md) for required item fields
   and credential provisioning. The accepted private catalog carries every secret,
   identity and data binding; per-service `secrets.yaml` files do not exist and are
   never created beside a workload. After merging the catalog PR, the control-machine
   credential reconciler creates missing approved items with empty required fields;
   keep its private checkout at reviewed main and the same active catalog path as
   public `services.catalogPath`. Run it as a daemon with
   `docker compose --profile credentials up -d credential-reconciler` and inspect
   its persisted per-cycle report for created, pending and awaiting-administrator
   items. Ordinary secrets need an `approval.secretBindings` entry binding the
   approved name to its vault item and fields. Composition secrets need an
   `approval.composition.secrets` entry. Every ordinary secret mount must match
   exactly one binding, data credential, or confidential OIDC secret name;
   anything else fails the cycle. The reconciler preserves existing items
   and reports pending field names.
   **User:** fill pending fields in 1Password. External Secrets remains the sole
   synchronizer. Guarded ordinary, composition and SQL/S3 secret templates reject
   missing or empty required fields and preserve valid deployed credentials.
   Completing those fields lets External Secrets resume delivery on its refresh
   interval. Other consumers must not adopt placeholders until their delivery and
   retention guards are verified.
4. **Agent:** configure optional login through section 6.5 before publication.
5. **Agent:** declare protection in private `services/example-app/protection.yaml`
   with the `coordinated-monthly` profile, protected database/bucket/PVC references
   and the approved destination reference. The credential reconciler validates the
   binding and reports coverage: shared SQL/S3 volumes are covered by the data owner
   monthly export, while service PVCs report uncovered until separately verified.
   The backup-protection reconciler converges the accepted profiles plus bindings
   onto the recovery owners: host policy and timers apply only with a merged
   `{binding, plan}` approval in private `platform/recovery/approval.yaml`, and
   Longhorn coverage is verified by chart parity. Merging protection YAML never
   runs a restore. Run it with
   `docker compose --profile protection up -d backup-protection`.
   Declaring storage or protection is not a backup; protection claims need isolated
   restore evidence.

**Done when:** dependency requests, scoped references and secret custody are declared.

Implemented workload fields and their owners (services owner renders all):
`approval.egress` (ordinary only) renders namespace `platform-egress` from
declared destinations; `[]` or retired denies all.
`approval.composition.connections` renders per-workload peer AuthorizationPolicies;
retired empties them. `approval.composition.workloads[].preset` is exactly one of
`application-no-api`, `application-api-reader`, `controller-scoped`, `job-scoped`,
`system-exception`, resolving through the fixed composition Roles; `application-no-api`
and `system-exception` render no Role (fail-closed deny), and `job-scoped` stays
retired with empty rules while its Binding is retained. Ordinary services are
implicitly `application-no-api` and carry no field. No preset lets a workload self-grant RBAC verbs.
`approval.exceptions[]` (composition only) is the per-exception register
(`identity`, `owner`, `reason`, `scope`, `removal`); entries require a consuming
`system-exception` workload and `system-exception` requires a matching identity.
Composition podSpecs require named service accounts.

Credential map (vault item to container). Each credential flows from its vault
item to one app-namespace ExternalSecret to the approved container mount:
ordinary `approval.secretBindings[]`, composition `approval.composition.secrets[]`,
confidential OIDC (`identity.yaml`, `keycloak-client-secrets` item), and data
(`data.yaml`; database `username`/`password`, bucket `BUCKET`/`ACCESS_KEY_ID`/
`SECRET_ACCESS_KEY`/`ENDPOINT`/`REGION`). Operations: External Secrets syncs
read-only on a 24h interval; every target sets `creationPolicy: Owner`,
`deletionPolicy: Retain`, and guarded v2 templates that fail on missing or empty
fields; `dataApprovals` gates each data credential to its exact service, name,
and kind scope; foreign names, items, fields, or scopes fail the render before
reaching the cluster. Admission re-checks the owner store, shape, retention,
and single whole-item references. No secret values appear in Git or diagnostics.

Field ownership and deletion. Source: the accepted private catalog revision;
owner: the services renderer for all platform objects; reconciler: the
`cloudlab-services` Application (automated self-heal, no prune) plus per-entry
workload ApplicationSets (self-heal with prune) and native admission, CNI, and
mesh. `publication: retired` empties peer rules, preset Roles, and workload
renders in place while the namespace, quota, register, bindings, PVCs,
databases, buckets, and vault items stay retained. Removal sequence per the
catalog header: retire, verify absence, then remove the entry. Removing a
declaration never deletes vault items or persistent data.
Retired: the `serviceAccountName: default` default. The budget named GET keeps
both ResourceQuota and LimitRange: activation plus retirement GET every
declared receipt by name, so the LimitRange cannot go LIST-only.

### 6.3 Choose access — User, then Agent

1. **Agent:** ask the user to choose no ingress, private access, public access,
   or a public primary exposure with additional private views, unless already
   explicitly answered. Wait for the answer before configuring or publishing access.
   Source repo visibility and existing exposure settings are not consent for this choice.
2. **Agent:** set only the `definition.exposure.class` signal in private
   `services/catalog.json`: `private`, `public`, or `none` for no ingress.
   Ordinary catalog entries carry no hostname, access, path, port, or backend.
3. **Agent:** write the addresses in their owning files. For public access, add
   the service entry to public `services/exposures.yaml` with its hostname,
   `public`/`human`/`machine` access, backend workload name, path, and port.
   For private access, add entries to private `platform/access/policy.yaml`
   `privateDNS.services` with the DNS label, service, backend workload, path,
   and port. Public services may also take private views there.
   Match OIDC callback paths to these hosts.
4. **Agent:** configure the required identity and access policies through section 6.5.

An HTTPRoute does not create public DNS, tunnel routing or Access protection.
Do not change an existing exposure class through an ordinary catalog update;
use the service contract's retirement and migration procedure.

**Done when:** the exposure files and the catalog class signal match the user's
explicit service-access choice.

### 6.4 Review deployment configuration — Agent, then User

1. **Agent:** complete the entry's `approval` in private `services/catalog.json`:
   `name`, `repository`, exact source `revision`, `valuesPath`, `namespace`,
   `secretReferences` and `configMaps`. Set `visibility` explicitly and use
   `chartPath: charts/service` for the shared chart. For `example-app`, use
   namespace `cloudlab-app-example-app`.
2. **Agent:** check source paths and optional artifact approval against the
   [catalog schema](../platform/delivery/services/values.schema.json).
   `valuesPath` must identify an existing approved values source.
   If using artifact releases, review `approval.artifact` and
   `apps/releases/example-app.json` in the owning release GitOps repo.
   `approval.repository` must be that release GitOps repo;
   `approval.artifact.sourceRepository` identifies application source as `OWNER/REPO`.
3. **Agent:** set `publication: ready` for the new entry. Validate the definition
   and complete catalog using the [service contract](../charts/service/README.md).
   Open the private catalog PR through the existing reviewed GitOps process.
   **User:** review and merge through branch protection.
4. **Agent:** check platform `gitops/roots/public/values.yaml`.
   If `services.enabled` is false, propose enabling it through a separate platform PR.
   **User:** review and merge that PR through branch protection.
   The public root owns `cloudlab-services`; `services.revision` pins its catalog
   chart to an exact platform commit. Change that pin through a reviewed platform
   PR when upgrading the catalog chart. After merge, Argo advances catalog-owned
   platform sources without a service apply. Routine onboarding needs no changes to
   shared `charts/service/` code or the catalog Application.
   Routine application onboarding uses the designated private service catalog;
   it does not require an optional private GitOps root installer.
5. **Agent:** use `lab setup` through Compose only when
   prerequisites need convergence. Missing approved credential items are provisioned
   as empty placeholders by the credential reconciler after the catalog merge; fill
   them in 1Password. Initial native identity binding
   validates the complete catalog at the same immutable private revision before
   activating its source. Foreign namespaces, projects or ApplicationSets block
   activation; composition admission must already be ready. Existing installations
   require the read-only adoption guard before accepting the root-owned catalog.
   After acceptance, Argo reads private `services/catalog.json` from protected
   `main`, deploys supported changes and repairs drift without a service apply.
   Identity provisioning, data preparation and access publication still use their
   owning procedures below.

**Done when:** the approved workload has converged. Access publication still
requires the checks below.

### 6.5 Configure identity and access policies — User, then Agent

Use the existing identity, access, data and admission owners.
Keep private settings in their accepted inputs and secret values in 1Password.
Declare identity settings once in the catalog entry; the identity owner compiles
applications clients from the catalog plus approved exposure hosts. The reference
profile is retired. No settings change provisions missing credentials. Complete
the real browser and allowed/denied checks in section 6.6. Before retiring a
service, persist its client tombstone in the revocations registry, then verify
provider disablement. Active shared clients block retirement before exposure
changes; rotation/removal/recovery remain independently scoped.

1. **User:** decide whether the app needs Keycloak login.
   **Agent:** review `definition.oidc` in private `services/catalog.json`.
   Leave it disabled when unused. Otherwise set `realm: applications`, `client`,
   `public`, `callbackPaths`, `audience`, `scopes` and `roleMapping` using the
   [service schema](../charts/service/values.schema.json).
   Use Code + PKCE S256. Public clients have no secret.
   Confidential clients also require `secretReference`, an approved
   `definition.secrets` mount and `approval.secretReferences` entry.
   The identity owner keeps their secret in `keycloak-client-secrets/client_secrets`
   in CloudLab, at `client_secrets[realm][client-id]`; never put the value in Git.
   Confidential enrollment requires an existing string of at least 32 characters.
   The user supplies that value in 1Password; the reconciler creates the missing
   shared item with empty declared keys, never rewrites an existing item, and
   reports a missing or empty client key as pending. Pending confidential
   clients stay out of the realm import without blocking other clients.
   Guarded delivery requires a nonempty string at the selected realm/client and
   retains the last valid Secret until completion resumes through normal ESO refresh.
2. **Agent:** check exact HTTPS callbacks derived from approved exposure hosts
   and `callbackPaths`; web origins derive from those same hosts.
   Never use wildcard callbacks or unrelated origins.
   The service adapter does not expose logout callback settings. If the app needs
   registered logout redirects, report this unsupported service field to the identity
   owner and stop that integration. Logout redirects must stay on approved callback origins.
   Submit any changed service settings through the catalog PR flow in section 6.4.
   No hand-edit of the identity inventory is needed for applications clients;
   memberships and platform-realm clients stay hand-managed in private
   `identity/configmap.yaml`. User/group edits are private desired_state data
   only; no platform/identity code change is needed or allowed. Preserve PR
   reviews, the writer lease lock and revocations tombstones; never grant
   platform-admin or self-privilege through these edits. Verify a successful
   subsequent normal Keycloak
   writer run and the actual client configuration. The leased writer runs every
   five minutes.
   Keep the accepted identity installation pin; do not repin it to the advancing Root or service catalog revision.
   To retire a client, persist its ID in `data.revocations` JSON at
   `realms.applications.clients` and retire its catalog entry. Keep the tombstone;
   omission alone retains clients. Existing tokens do not become invalid immediately.
   Retain the guarded removal, rotation and recovery procedures in the
   [identity contract](../platform/identity/keycloak/contract.json); vault items are retained.
3. **User:** choose allowed application actions for each role.
   **Agent:** review `definition.oidc.roleMapping` and the application's existing
   authorization code; its filename depends on the app.
   Map app roles to schema group names `platform-admin`, `developer` or `viewer`;
   emitted group claims use full paths such as `/viewer`.
   Follow the [identity contract](../platform/identity/keycloak/contract.json) for claims.
   Verify tokens' signature, issuer, audience,
   expiry and required roles in the application. Login alone grants no automatic
   administrative permission. Also review `definition.data`, top-level
   `dataApprovals` and `approval.secretReferences` in private `services/catalog.json`:
   pods receive only scoped SQL/S3 credentials, never migration or administrator credentials.
4. **Agent:** match network protection to `definition.exposure`.
   Private `tailnet` access uses the accepted Tailscale policy; app authorization
   still applies. Public `human` access needs the approved human identity provider
   and explicit identity/group policy. Public `machine` access needs the approved
   service-token policy. Access class `public` permits anonymous ingress; app-level
   login requirements remain separate.
   The native access owner manages the exact Access application and policies in
   `${INFRA_PRIVATE_DIR}/cloudflare/desired.tfvars.json`; the default path is
   `../yasai-cloudlab-infra-inputs/cloudflare/desired.tfvars.json`.
   Use existing reviewed provider operations and the
   [access contract](../platform/connectivity/access/contract.json) for credential fields.
   Keep these private inputs outside Git; never broaden grants to make publication pass.
5. **Agent:** keep existing [admission rules](../platform/delivery/admission/policies/values.yaml)
   and restricted namespaces in force;
   routine apps need no admission exemptions. Review optional `approval.artifact`
   and its approved signing identities in private `services/catalog.json`.
   For a new artifact policy, use `Audit` before the
   [artifact verification](../verification/integration/application_release.py)
   passes; move to `Enforce` only through review, retaining rollback identities.
   Check client, credential and protection configuration before publication.
   Complete real browser login and allowed/denied action tests after the hostname
   is reachable, in section 6.6; configuration readiness alone does not prove them.

**Done when:** identity, application permissions and access policies match reviewed intent,
and their owning configuration has converged for readiness checks.

### 6.6 Verify, then publish access — Agent, then User

1. **Agent:** merge the exposure PRs from section 6.3 and the catalog PR from
   section 6.4. Argo renders routes from the exposure files and converges the
   workload; no publish command exists.
2. **Agent:** read readiness from the owners: Argo for routes and certificates,
   the identity writer for client convergence, and the connectivity reconciler
   status for DNS, tunnel, and protection. Confirm identity, scoped data access,
   backend health and TLS readiness. Stop on failure; report the blocked check
   and owning configuration. Make only corrections already within the agreed
   setup scope.
3. **Agent:** for public DNS, read the pending plan digest from the connectivity
   reconciler status and merge the `platform/access/cloudflare-approval.yaml`
   binding PR for the current main SHA. The standing loop applies the bound plan
   with no second command. Private DNS converges automatically after merge.
4. **User/Agent:** open the published hostname from an intended client.
   Verify login and permitted application actions. Check anonymous or unauthorized
   access is denied where required. Test each additional private view from the tailnet.
   **Agent:** complete these checks with existing authorized credentials when available.
   Request user action only for missing credentials or interactive MFA, such as a
   physical passkey. Never weaken authentication or enroll a new key to bypass that step.
   If the user explicitly waives a check, stop that check and report it as unverified.
5. **Agent:** run the service contract's relevant verification, including
   `docker compose run --build --rm lab prove` for setup changes.
   Never run disposable fixture retirement checks against the real service.

For class `none`, publication creates no ingress; verify the intended internal caller.
If interrupted, rerun with the same reviewed inputs. Preserve data and existing credentials.

**Done when:** intended clients can use the service, required denial checks pass,
and the owning publication state is verified.

### 6.7 Optional: enable canary deployment — Agent, then User

Use only for an exposed, stateless service with `definition.persistence.enabled: false`.
Public or private source visibility does not decide network exposure.

| Repo | File or location | Change |
| --- | --- | --- |
| Application | Existing metrics/instrumentation code; filename depends on the app | Export revision-labelled release metrics on `/metrics` at port `9091` |
| Private GitOps | `services/catalog.json` | Set `definition.rollouts.enabled: true`; add `http-metrics:9091` to `definition.ports`; budget resources |
| Public platform | `gitops/roots/public/values.yaml` | Enable root `rollouts.enabled` only if disabled |
| Owning release repo | `apps/releases/example-app.json` | Use normal reviewed image releases from section 7 |
| Public platform | `charts/service/templates/_workload.tpl`, `charts/service/templates/_analysis.tpl`, `charts/service/release-policy.json` | Shared strategy and gates; normally unchanged |

1. **Agent:** update the application's existing instrumentation.
   Export `cloudlab_http_requests_total`, `cloudlab_http_duration_seconds_bucket`
   and `cloudlab_http_duration_seconds_max` with `service`, `revision` and
   `traffic="release"` labels. Read `revision` from chart-supplied `CLOUDLAB_REVISION`;
   never set that environment variable manually in the catalog.
   Include HTTP `status` on request counters; initialize zero error counters.
   Retain the maximum latency for the
   120-second evaluation window. Keep synthetic release traffic separate from user SLOs.
2. **Agent:** confirm the Git-owned controller and pinned Gateway API plugin in
   [`platform/delivery/rollouts/values.yaml`](../platform/delivery/rollouts/values.yaml)
   are deployed. If root `rollouts.enabled` is false, propose its platform PR.
   Propose the private catalog fields above, preserving existing ports.
   Budget simultaneous stable/canary pods and surge within namespace quotas.
   The platform owns the shared metrics collector; respect its eight-target cap.
   **User:** review and merge required instrumentation and platform PRs through protection.
3. **Agent:** for an existing Deployment, prepare a staged migration before
   enabling the catalog change. **User:** review and merge the catalog PR only
   after any required migration plan is ready. **Agent:** run the Rollout alongside the existing
   Deployment, verify healthy stable traffic, then retire only the named superseded stateless
   Deployment through its reviewed owner operation. Preserve data and shared resources.
4. **Agent:** use the application's bounded synthetic traffic proof in a disposable
   fixture. The chart does not generate traffic. The shared strategy sends 50% to
   the canary, pauses 30 seconds, then runs inline analysis against that revision.
   Ensure the evaluated revision receives at least 230 samples within 120 seconds.
   The [release policy](../charts/service/release-policy.json) requires error rate
   `< 1%`, p95 latency `< 250 ms` and maximum latency `< 1 s`.
   Missing, invalid, non-finite, insufficient or failed metric queries fail closed;
   analysis aborts instead of promoting the release.
5. **Agent:** prove successful promotion and a deliberate bounded failed release
   that aborts while stable traffic remains healthy. Use approved signed fixture
   artifacts, retaining their images, signatures and signing identities.
   Keep injected failures isolated from real user traffic; each app supplies its
   own fixture and traffic proof. **User:** review results before relying on canaries.
   Subsequent releases use public platform `apps/releases/example-app.json` for
   public sources, or the same path in private GitOps for private sources.

**Done when:** stable migration, metrics, successful promotion and safe abort behavior
are verified. Canary enablement does not replace readiness or access checks in section 6.6.

## 7. Release an update and roll back

Use this flow after CI and service deployment work. The service must already have
`approval.artifact` configured in private `services/catalog.json` to follow
`apps/releases/example-app.json` in the owning release repo.
An image-only update uses that release file; it does not change the service catalog.

### 7.1 Change application source — Agent, then User

1. **Agent:** change source and tests in the application repo.
   Update application `Dockerfile` only when the build or runtime image needs changes.
   Keep `.github/workflows/ci.yaml` unchanged for ordinary application changes.
2. **Agent:** open the application PR without merging it.
   Dependency changes need a separately prepared, scanned environment from protected
   `main` and a reviewed `testing.image` update. If new code cannot run in the approved
   environment, the ordinary PR-first sequence is blocked: the environment producer
   accepts protected `main` only. Use an owner-approved compatible preparation transition
   where one exists; otherwise stop and report the blocked step to the CI/environment owner.
   Never build an environment in PR/dev tests, bypass checks or redesign the platform.
3. **Agent:** if workflow bytes changed, approve them before PR tests and application merge.
   For the supported public repository-owned workflow, read its current internal PR revision:

   ```sh
   gh api repos/OWNER/REPO/pulls/PR_NUMBER --jq '{state: .state, mergeable: .mergeable, merge_commit_sha: .merge_commit_sha, base: .base.ref, head_repo: .head.repo.full_name}'
   ```

   Require an open, mergeable internal PR targeting `main`. Replace `PR_NUMBER` and
   `PR_MERGE_SHA` below with that PR number and its current `merge_commit_sha`.
   Set `ci.approval.revision: PR_MERGE_SHA` and
   `ci.approval.pullRequest: PR_NUMBER` in the private registration, with
   test-only jobs, and re-derive `runner.json` from section 4.3.

   Review the updated registration and `runner.json` into the private PR.
   Preserve existing controller quotas and publisher configuration.
   **User:** review and merge this private approval PR before application tests or merge.
4. **Agent:** wait for the runner's Argo application to become Synced and Healthy.
   Rerun the eligible current PR workflow; changing approval does not retry failed jobs.
   If the PR head or base changes, refresh `merge_commit_sha` and recheck approval
   against that revision. **User:** merge the application PR only after required checks are green.
5. **Agent:** after merge, read the new protected `main` SHA and renew main approval
   using section 5.3; include the `publishing` block when publishing is enabled.
   **User:** review and merge required private runner/publisher changes.
   **Agent:** wait for Argo convergence and rerun the eligible main workflow as needed.
   Build and publishing jobs stay main-only. Private exact-revision approval has no PR jobs;
   it is not a workaround for the unsupported private branch-testing interface in section 5.1.

**Done when:** the application PR passed required tests before merge and protected-main
workflow/publishing approval is ready for the release run.

### 7.2 Let lab CI build the release — Agent

1. Observe the existing application `.github/workflows/ci.yaml` run on `main`.
   Confirm tests use `cloudlab-example-app` and publishing uses
   `cloudlab-example-app-publish`.
2. Confirm direct tests pass before main-only builds, image scan, publication and signing.
   Tests run the current source in the pinned dependency environment; they build no image.
   The publisher builds the reviewed component Dockerfiles and optional targets,
   or root `Dockerfile`'s `runtime` target for a single-image declaration.
   Ordinary releases need no edits to workflow or runner configuration files.
3. Find the release PR created by automatic promotion, or follow section 5.2's
   manual private promotion for a reviewer-submitted release PR. If a job fails,
   fix the owning application or approved configuration before retrying.

**Done when:** CI has published a signed digest and proposed its release record.

### 7.3 Review the release PR — User, then Agent

Automatic publication or reviewer-submitted manual promotion changes this file in the selected release repo:

| Application source visibility | Release file |
| --- | --- |
| Public, default destination | Public platform repo: `apps/releases/example-app.json` |
| Public, explicit private destination | Private GitOps repo: `apps/releases/example-app.json` |
| Private | Private GitOps repo: `apps/releases/example-app.json` |

1. **Agent:** check the PR changes only the expected release record.
   Verify `digest` matches the signed image, `source_revision` matches the approved
   application commit, and `workflow_run_id` identifies the successful publishing run.
   All three fields are strings. Validate the record against
   `platform/delivery/ci/release.schema.json`; the release proposer still
   enforces primary-component membership and digest equality.
   For component releases, verify every approved component digest and confirm
   `primary_component` selects the image recorded in `digest`.
   Run the trusted release verifier as the merge gate
   (`python platform/delivery/ci/publisher/release.py verify <registration.json>
   <release-file>`, registration rendered to JSON); a gate failure blocks the PR.
   Anything merged invalid is still denied at admission, and Argo keeps serving
   the prior merged release.
2. **User:** review and merge through the repository's configured review process.
   Automatic release Apps cannot merge; manual promotion only submits a PR.

**Done when:** the reviewed release record is on the owning repo's `main` branch.

### 7.4 Verify the deployed digest — Agent, then User

1. **Agent:** wait for Argo to read the merged `apps/releases/example-app.json`.
   Keep private `services/catalog.json` unchanged for this image-only release.
2. **Agent:** confirm the application becomes Synced and Healthy and running
   workloads use the approved image digest. Check Argo application annotations
   `cloudlab.io/artifact-digest`, `cloudlab.io/source-revision` and
   `cloudlab.io/workflow-run` against the release record.
3. **User/Agent:** verify health checks and intended client access, including
   login and required application actions. Let Argo converge from Git;
   routine releases need no local installation or access publication operation.

**Done when:** the approved digest runs and intended application behavior passes.

### 7.5 Roll back through a release PR — Agent, then User

1. **Agent:** select a previously reviewed, working version of
   `apps/releases/example-app.json` from the owning repo's Git history.
   Confirm its image, signatures and approved signing identities remain available.
2. **Agent:** check the previous image is compatible with current database schema
   and persisted data. Image rollback does not reverse migrations or restore data.
   If incompatible, stop and use the data owner's reviewed migration or recovery procedure.
3. **Agent:** renew the registration approval to that same historical revision first,
   then open a rollback PR restoring the complete previous release record:
   `digest`, `source_revision` and `workflow_run_id` from that same historical version.
   Use the recorded immutable digest; do not reconstruct it from a tag.
   The merge gate binds the record to the current approval, so the renewal is the rollback approval.
4. **User:** review and merge through branch protection.
   **Agent:** repeat section 7.4 against the restored record.

**Done when:** the previous approved digest is healthy and intended access works
with the current data state.

## 8. Add service monitoring and dashboards

Declare collection, alert rules and dashboards in private GitOps; controllers
converge them after merge. No Ansible run, SSH session, manual Helm install or
operator apply is part of this path. Nodes, Rollouts and the read-only
active-alerts view remain platform-owned; each service adds at most one focused
detail board. Boards are explicit declarations, not generated views: there is no
automatic overview or catalog watcher. Declared boards link from active-alerts.
Source repository visibility does not change this path.

### 8.1 Choose the service view — User, then Agent

1. **User:** name the questions the dashboard must answer.
   Start with service health and activity, then component resources and instance details.
   Use Grafana's [layout guidance](https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/)
   and Prometheus's [workload guidance](https://prometheus.io/docs/practices/instrumentation/).
   Add logs or traces only when their collection is already approved.
2. **Agent:** inspect the [observability contract](../platform/observability/contract.json)
   and actual collected metrics. Bind the view to an approved service label or explicit
   owned workload set; namespace alone is insufficient when several services share it.
   Do not assume application metrics already exist.
3. **Agent:** separate real user traffic from release tests, probes and synthetic
   traffic. User SLO panels must select user traffic only.
   Plan distinct states for valid zero requests, missing telemetry and insufficient evidence.
4. **Agent:** choose available signals for the workload type: request rate, errors
   and latency for APIs; backlog, in-flight work and last-processed freshness for workers;
   last success, duration and failures for batch jobs. CPU/memory describes resources,
   not successful application behavior. Report missing signals through section 8.2.

**Done when:** one service's questions, workload scope and real telemetry sources are identified.

### 8.2 Confirm telemetry coverage — Agent, then User

1. **Agent:** inspect the application's existing metrics/instrumentation code;
   its filename depends on the app. Require bounded, redacted metrics from their accepted owner.
2. **Agent:** inspect platform `platform/observability/templates/collector.yaml`
   for approved scrape coverage and `platform/observability/templates/network.yaml`
   for network access. Check operator scope in
   `platform/observability/prometheus/values.json` and policy in
   `platform/observability/policy.json`. Logs/traces also depend on approved
   `platform/observability/config.alloy` collection and filtering.
3. **Agent:** if the service lacks coverage, report the missing scrape/rule/network
   prerequisite and its telemetry owner. Any implementation needs separate explicit scope.
   Continue independent dashboard design, but do not claim its live data is verified.
   A dashboard file does not enable scraping or ingestion.
   Keep `definition.monitoring.enabled` false; do not add an application-owned ServiceMonitor.
4. **Agent:** use the owning service's accepted SLO thresholds and rules.
   Notes thresholds live in `apps/notes/slo.json` with
   `charts/service/release-policy.json`; their pinned rule file is
   `platform/observability/prometheus/notes-slo.json`, rendered through the
   explicit native include in `platform/observability/prometheus/templates/notes-slo.yaml`.
   Do not copy those expressions as a generic onboarding template.
   Request/error/latency panels require accepted instrumentation; readiness and resources
   alone do not establish application health. Alert counts require reliable service
   attribution and rule-evaluation coverage; otherwise leave them unavailable.

**Done when:** accepted collection supplies the metrics and rules required by the dashboard.

### 8.3 Declare collection, rules and dashboard JSON — Agent

1. In the private catalog selected by public `services.catalogPath`
   (`services/catalog.json` by default), set the service's `definition.monitoring`:
   `enabled`, `routes`, metrics (`profile: cloudlab-http` on the dedicated
   `http-metrics` port at `/metrics`) and/or logs (`profile: cloudlab-http-json-v1`).
   Only ordinary non-rollout `charts/service` workloads are supported; traces stay
   disabled. Enabled monitoring needs at least one signal; logs-only needs no
   metrics port. Retired entries are excluded from collection.
2. In private `platform/observability.yaml`, add the `serviceObservability` entry
   keyed by the approved catalog service name: native rule groups (alert names
   `Svc_<service>_...` and recording rules `svc_<service>:...`, with hyphens as
   underscores; severities `info`/`warning`/`critical`, default `warning`; the
   owner assigns service/namespace labels and investigation links) and the dashboard model
   (`uid: svc-<service>`, `editable: false`, at most 96KiB, provisioned data
   sources `metrics`/`logs`/`traces` only — never backend URLs).
3. Bind every query and
   [variable](https://grafana.com/docs/grafana/latest/visualizations/dashboards/variables/)
   to the approved service label or owned workload set; limit variables to that
   service's component, pod and container drilldowns. The detail board has no
   fleet tables. Keep its compact service status independent of selection; scope
   readiness, restarts, CPU/memory and instance panels to one component.
   Component options put unknown/unready components first using native query order.
   Pod/container selectors choose one instance. Filters are not access controls.
4. Arrange the agreed panels from summary to detail. Give each panel one question,
   clear units and a bounded legend. Do not overlay all pods or containers in one
   graph by default. Aggregate compatible replica counts and rates before computing
   ratios. Where histograms exist, combine compatible buckets before calculating
   percentiles; never average pod percentiles. Keep user SLOs separate from
   release/probe/synthetic traffic. Display valid zero activity as **No traffic**
   and missing evidence as **UNKNOWN** or **No data**; identify stale evidence
   separately. Do not turn missing series into healthy zero values.
5. Request delivery in the reviewed `platformNotifications` subscriptions in `platform/observability.yaml` (service,
   severities, approved receivers); services cannot invent destinations.
   Recurring maintenance uses declared `timeIntervals` with `muteWindows`;
   inhibition rules are likewise platform-owned in the same file.
   Incident silences stay authorized runtime operations, not Git state.
6. Keep secrets, endpoints and private deployment bindings out of public Git.
   Select one component, pod and container by default; filters are not authorization.

| Private Git path | Declaration | Effect |
| --- | --- | --- |
| selected private catalog | `definition.monitoring` | Scrape/log collection for the service |
| `platform/observability.yaml` | `serviceObservability` rules | `svc-<service>-*` PrometheusRules with alert links |
| `platform/observability.yaml` | `serviceObservability` dashboard | `svc-<service>.json` board with an active-alerts link |
| `platform/observability.yaml` | `platformNotifications` subscription | Firing/recovery delivery to approved receivers |

Prices is the first Git-driven lifecycle proof. Specify it offline in the same
shapes (private PR later): a `prices` catalog entry on the ordinary
`charts/service` chartPath, a `serviceObservability` entry whose rule groups
separate missing targets from failing targets, HTTP error/latency burn, and
insufficient-evidence states, a `svc-prices` dashboard, and a
`platformNotifications` subscription binding `prices` severities to an approved
receiver. Synthetic delivery fixtures stay on production-equivalent intervals
(at or above the 30s collection cadence); never use the schema minima
(`for: 1ms`, 1s group interval) on the 2-VM fleet.

**Done when:** the declarations use stable UIDs, the board links from
active-alerts, and selectors exclude unrelated workloads.

### 8.4 Review and deploy — Agent, then User

1. **Agent:** validate the declarations against
   `platform/observability/gitops/values.schema.json` and check PromQL with
   `promtool`. For independent public checks, validate
   `services/<name>/uptime.yaml` against
   `platform/observability/uptime.schema.json`; the host derives from the
   approved public exposure and hosted checks activate through separately
   authorized trusted execution. Confirm the catalog binding is current (not retired), receiver
   names resolve to declared receivers, and the aggregate stays within the
   chart's 192KiB bound. Preserve flat panels, bounded legends, private scope
   and explicit missing/stale states. Component/pod/container variables are
   single-select without All; fixed ownership scope still applies when URL
   selections change.
2. **Agent:** leave Grafana settings in `platform/observability/prometheus/values.json`
   unchanged; adding service monitoring does not require changing them.
3. **Agent:** review the selected private catalog and `platform/observability.yaml`
   changes in private GitOps. Commit each change through its owning protected PR flow.
   **User:** review and merge through branch protection.
4. Convergence runs through the native observability parent
   (`cloudlab-observability-gitops`). That parent is currently disabled and
   paused; a later reviewed public Git merge activates it only after all four
   activation gates pass: guarded writer handoff evidence, the private-source
   approval receipt, connection and access qualification through the workload
   and network owners, and the two-node environment with qualified storage.
   Until then, merged declarations do not converge; do not run local
   applies to force them. Never patch Applications manually or use UI-only writes.
   Run the live leg one scenario at a time (create, drift repair, firing and
   recovery, removal) with quiescence between steps; never run them back-to-back.
5. **Agent:** after activation, confirm Argo renders the six children from the
   accepted private revision and the `cloudlab-dashboards` ConfigMap carries the
   reviewed input digest. Check `/api/dashboards/uid/DASHBOARD_UID` through
   private Grafana access; require the service's own UID/title, matching
   panels/variables/links and `meta.provisioned: true` from its file provider.
   Argo repairs drift; accepted removal prunes only owned configuration while
   shared storage, application data and vault items are retained.

**Done when:** the reviewed declarations converge; the board is present in the
ConfigMap, mounted file and provisioned Grafana API.

### 8.5 Verify real data and reconciliation — User, then Agent

1. **User/Agent:** open Grafana through its existing private access and Keycloak login.
   Open the read-only active-alerts view and follow the service link.
   Confirm the detail has compact service status and selected-component panels, with no
   fleet tables. Defaults must exclude unrelated workloads, including a shared namespace.
2. **Agent:** where approved request metrics exist, compare a bounded sample with
   observed rate, errors and latency. Check readiness and resource panels against
   the selected workloads; do not claim unavailable HTTP metrics or functional health.
   Verify replica aggregates and units; confirm a failing replica stays visible.
   Verify **No traffic** and missing/stale telemetry states using focused queries
   or an isolated fixture; do not interrupt production collection for this test.
3. **Agent:** test component/pod/container drilldowns supported by this board.
   Confirm changes stay within the service and graphs remain readable.
   Verify optional log/trace links use only accepted redacted telemetry.
   Confirm no unrelated service data enters panels, variable options or links.
4. **Agent:** let normal reconciliation run and confirm the declarations remain correct.
   Make lasting edits in the selected private catalog or `platform/observability.yaml`
   and repeat its owning PR flow; UI-only changes are not durable. Confirm firing
   and recovery delivery through the subscribed receivers, not provider status alone.

**Done when:** the service's own provisioned board covers current workloads, keeps
other services out of its view, and passes aggregate, drilldown, zero/missing/stale
and Git reconciliation checks.

## 9. Retire a service safely

Retirement removes service access and its owned workload. It retains data.
Check all declared exposure hosts, regardless of source repo visibility.

| Repo or owner | Path | Retirement effect |
| --- | --- | --- |
| Public GitOps | `services/exposures.yaml` | Set the entry to `publication: retired`; routes, DNS, and tunnel/Access withdraw |
| Private GitOps | `platform/access/policy.yaml` | Remove the service entries; private DNS and routes withdraw |
| Private GitOps | `services/catalog.json` | Keep the entry with `publication: retired`; preserve its definition, approval and data bindings |
| Private identity owner | `identity/configmap.yaml` revocations | Persist the client tombstone; the writer disables the client |
| Private GitOps | `platform/ci/applications/example-app.yaml` | Keep the registration while the repo needs CI; removing it deletes owned pools — a separate explicit decision |
| Source and owning release repos | Application source, `.github/workflows/ci.yaml`, `apps/releases/example-app.json` | Preserve source, release history and recoverable artifacts; service retirement does not delete them |

### 9.1 Confirm the retirement scope — User, then Agent

1. **User:** name the service to retire, for example `example-app`.
   Retaining data is part of this operation; data disposal requires separate,
   explicit resource and data scope.
2. **Agent:** read its current catalog entry and exposure entries. Preserve the
   entry, other services and top-level `dataApprovals`. Record which public and
   private hosts and OIDC client belong to this service.

**Done when:** the service, exposure hosts and retained data are unambiguous.

### 9.2 Withdraw reachability — Agent, then User

No retire command exists; owners converge from merged Git intent.

1. **Agent:** set the public entry to `publication: retired` and merge its PR.
   Keep private `platform/access/policy.yaml` entries until §9.4: remove them
   only in the single atomic private PR that also retires the catalog entry.
   For public DNS changes, merge the plan-approval binding PR the
   connectivity reconciler reports.
2. **Agent:** confirm Argo withdrew the retired public routes and the reconciler
   withdrew DNS, tunnel entries, and exposure-specific Access protection, then
   verified authoritative withdrawal plus route absence in its retirement status.
   Private withdrawal is confirmed after the §9.4 atomic PR merges.

Shared Access protection is retained; do not delete it to retire one service.

**Done when:** DNS/tunnel/HTTPRoute reachability is withdrawn for the retired service.

### 9.3 Retire the OIDC client, if enabled — Agent, then User

Persist the client ID in the private revocations registry and merge the scoped
identity PR. The normal leased writer converges the provider client to disabled.

**User:** review and merge the scoped identity PR.
**Agent:** verify the provider client is disabled before proposing removal.
Preparing removal does not skip the token/session grace period or revoke issued
JWTs instantly. The vault value and persistent retirement tombstones remain.

**Done when:** disablement has converged and the reviewed removal intent is available.
Skip this step when `definition.oidc.enabled` is false.

### 9.4 Complete workload retirement — Agent

Set the catalog entry to `publication: retired`, remove its private policy
entries in the same atomic private PR, and merge with its rotated acceptance.
Argo removes only tracked service-owned workload resources, including its
Deployment/Rollout, Service and routes, without cascading into retained
resources. This is workload removal, not merely scaling replicas to zero.
Prune order follows sync waves: workload objects first, then wave -1 policies
and bindings, then wave -2 namespace, quota and exception register, which stay
until the retired entry itself is removed.

Namespaces, quotas, credentials, PVCs, databases, buckets and shared resources remain.
Runner pools are separate resources; this operation does not retire them.
If interrupted, re-merge with the same reviewed inputs. Preserve existing credentials
and provider state; resolve the reported owner prerequisite before continuing.

**Done when:** the workload and routes are absent and retained resources remain.

### 9.5 Verify retirement and retention — Agent, then User

1. **Agent:** confirm private `services/catalog.json` still contains `example-app`
   with `publication: retired`. Never remove the entry to represent retirement.
2. **User/Agent:** check the old primary and additional hostnames from their former
   public or tailnet clients. Confirm they no longer reach this application.
   For class `none`, verify the former internal caller cannot reach its removed Service.
3. **Agent:** confirm the scoped workload and routes are absent, retained claims
   and data resources remain, and unrelated services stay healthy.
   Use non-destructive owner checks only. K3s ships no API audit log; verify
   absence through Argo sync status and namespace inventory, not apiserver audit.
4. **User:** decide separately whether CI pools, App repo grants or source activity
   should stop. Preserve approved images, signatures and recovery material until
   their separate retention or disposal scope is agreed.

**Done when:** the service is unreachable, its workload is retired and retained data
and shared resources remain available to their owners.
