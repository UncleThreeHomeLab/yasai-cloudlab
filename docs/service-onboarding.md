# Add a service

Follow these steps for an application built on lab runners.
Use the [service contract](../charts/service/README.md) for deployment inputs.

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

## 2. Protect main manually

1. **User:** open the repo's **Settings > Branches**. Add a branch protection rule
   for `main`, or inspect an existing rule before changing it.
2. **User:** require a pull request before merging. Set approval requirements
   to match available reviewers.
3. **User:** leave force pushes and branch deletion disabled. Save the rule.
4. **Agent:** confirm GitHub reports `main` as protected. Check the saved rule
   requires PRs and blocks force pushes and deletion.
5. **User:** after CI produces its first successful test check, add that check
   as a required status check. Do not require a check that has never run.

**Done when:** protection is active. Required CI checks must be added once CI works.

If protection is unavailable for a private repo, stop normal runner registration.
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

When publishing is enabled, release Apps propose image-update PRs in the owning GitOps repo.
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

1. Use a clean checkout of a reviewed, published platform revision.
   The generator rejects a dirty checkout or unpublished history.
2. Check `ci.enabled: true` in
   [`gitops/roots/public/values.yaml`](../gitops/roots/public/values.yaml).
   Confirm Argo has deployed the CI ApplicationSets.
3. Confirm CI tool images were published and qualified on both nodes.
   Registration reads `/infra-work/harbor/ci/qualified.json` from the existing
   Compose `harbor_infra_work` volume. Do not create or edit this receipt manually.
4. Check ignored `.env` contains the existing VM access inputs and
   `PRIVATE_CONFIG_REPOSITORY`. Use the same Compose project as CI bootstrap,
   so registration can read its retained volume.
5. Confirm local `gh` authentication can read the application repo.
   The application must belong to the same owner as the public platform repo.

If prerequisites are missing, stop. Use the
[CI platform setup](../ansible/README.md) before onboarding the application.
Do not rebuild or requalify working CI tools for each new repo.

### 4.2 Write the application input in private GitOps — Agent

Open a checkout of the private repo named by `PRIVATE_CONFIG_REPOSITORY` in `.env`.
The commands below assume that checkout is `../cloudlab-config`, beside this
platform checkout. Substitute your actual checkout path if different.

Create a branch in the private checkout:

```sh
git -C ../cloudlab-config switch -c onboard/example-app
```

Create `platform/ci/pools/example-app/application.json` in that private checkout:

```json
{
  "name": "example-app",
  "repository": "https://github.com/OWNER/REPO.git",
  "visibility": "public"
}
```

Replace `example-app` and `OWNER/REPO`. Set `visibility` to `public` or `private`
to match GitHub. Keep the full HTTPS URL ending in `.git`.
Use the same application name in paths and commands below.

This file is the versioned registration input. Keep it alongside generated
`controller.json` and, after workflow approval, `runner.json` and `publisher.json`.
Do not recreate it as an untracked local input.
The generator reads `application.json`; Argo deploys the generated files.

### 4.3 Generate controller configuration — Agent

In the platform checkout, create `.infra-private/onboarding/` for temporary output.
Run this single command. It mounts the private application directory read-only
and passes the existing GitHub token through stdin:

```sh
gh auth token | docker compose --profile ci run --build -T --rm --volume ../cloudlab-config/platform/ci/pools/example-app:/application:ro --volume ./.infra-private/onboarding:/generated --entrypoint python ci-bootstrap -m playbooks.ci.files.configuration --application-file /application/application.json --output /generated/example-app/controller-first
```

If `.env` already supplies `GITHUB_PROVISION_TOKEN`, the generator uses that token.
Never put tokens in command arguments or print them.

Expected result:

```json
{"configuration_generated": true, "application_documents": 1, "credentials_created": 0}
```

Output: `.infra-private/onboarding/example-app/controller-first/controller.json`
in the platform checkout. Only generated output is temporary; `application.json`
remains in private GitOps.
The generator reads GitHub and cluster endpoints; it writes local configuration.
It does not deploy the controller or create GitHub credentials.

On failure, preserve existing files. Check prerequisites and input values.
The command reports only a generic error. If inputs change, choose a fresh
output directory instead of overwriting the previous result.

### 4.4 Propose the controller in private GitOps — Agent, then User

1. **Agent:** copy
   `.infra-private/onboarding/example-app/controller-first/controller.json`
   from the platform checkout to
   `../cloudlab-config/platform/ci/pools/example-app/controller.json`.
2. **Agent:** confirm `application.json` and `controller.json` are together
   in the private repo's `platform/ci/pools/example-app/` directory.
   Do not copy either file into this public repo.
3. **Agent:** review the file before opening a PR. Confirm application name,
   visibility namespace, pinned controller image and discovered network addresses.
   For this example, the controller name is `cloudlab-example-app-controller`;
   its watched namespace is `cloudlab-ci-public-example-app` for public repos,
   or `cloudlab-ci-private-example-app` for private repos.
4. **Agent:** commit both files, push `onboard/example-app` and open a PR
   targeting private `main`.
   Preserve existing files for other applications. If this application already
   has configuration, review its diff instead of treating it as a new installation.
5. **User:** review and merge through branch protection.

Do not add `runner.json` or `publisher.json` yet. Those files require approved
workflow inputs. Do not manually create runner pods or apply generated manifests.

### 4.5 Verify Argo deployment — Agent

Use the existing private Argo/Kubernetes access to check:

| Check | Expected result for `example-app` |
| --- | --- |
| Argo application | `cloudlab-ci-example-app-controller` exists; Synced and Healthy |
| Controller Deployment | `cloudlab-example-app-controller` is Available in `cloudlab-ci-system` |
| Watched namespace | Matches the visibility namespace from step 4.4 |
| GitOps source | Tracks private `main` containing the merged controller file |

Argo reads `platform/ci/pools/*/controller.json` automatically.
If the application is missing, inspect the
`cloudlab-ci-application-controller` ApplicationSet and its private source access.
If deployment fails, inspect Argo conditions and controller events before changing inputs.
Keep credentials and diagnostic dumps out of tracked files.

`ci.poolEnabled` controls the older shared fixture pool. Leave it unchanged
when adding these application-specific controllers and pools.

**Done when:** the repo's controller is healthy. Jobs remain disabled until
workflow approval produces `runner.json` and, when needed, `publisher.json`.
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
2. **Agent:** prepare a dependency-only test environment separately from reviewed,
   protected application `main`, using the procedure below.
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
| Private | Requires an accepted direct-test workflow interface before enabling this policy | Do not substitute the legacy image-building shared test workflow |

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
`python3 -I -S platform/ansible/playbooks/ci/files/publisher.py`.

The legacy [application-test.yaml](../.github/workflows/application-test.yaml)
builds an image to run tests. Do not approve it for PR/non-main testing under this policy.
Private repository-owned direct workflows are not accepted by the current registration
interface; resolve an accepted direct-test interface with its owner before enabling them.
Use [application-publish.yaml](../.github/workflows/application-publish.yaml)
as the reference for main-only publishing layout and permissions.
Public signing requires `id-token: write`. The shared publishing workflow also
requests that permission. Test jobs use Contents and Pull requests read access.

#### Prepare and approve the dependency environment — Agent, then User

Run these operations from a normal, clean, published platform clone using the same
Compose project and retained CI volume as section 4. Its `.git` must be a directory,
not a linked worktree file pointing outside the container.
Use the reviewed application's actual dependency recipe and complete test entrypoint;
the examples below use `deploy/docker/tests.Dockerfile`, target `test-environment`,
and `deploy/testing/run_tests.sh`.

1. **Agent:** confirm the recipe and test entrypoint are reviewed on protected public
   `main`. Read its current SHA:

   ```sh
   gh api repos/OWNER/REPO/branches/main --jq '{protected: .protected, sha: .commit.sha}'
   ```

   Require `protected: true`. Replace `ENV_MAIN_SHA` below with that exact SHA.
   Create fresh ignored `.infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/tracked-source/`.
   This environment revision is separate from the later workflow-approval SHA.
2. **Agent:** create a normal Linux clone inside the existing protected client volume.
   It avoids Windows checkout line-ending differences without changing host Git settings:

   ```sh
   docker compose --profile ci run --build --rm --entrypoint git ci-bootstrap -c credential.helper= clone --config core.autocrlf=false --branch main --single-branch https://github.com/OWNER/REPO.git /infra-work/harbor/ci/environment-sources/example-app/ENV_MAIN_SHA/source
   docker compose --profile ci run --rm --entrypoint git ci-bootstrap -C /infra-work/harbor/ci/environment-sources/example-app/ENV_MAIN_SHA/source rev-parse HEAD
   docker compose --profile ci run --rm --entrypoint git ci-bootstrap -C /infra-work/harbor/ci/environment-sources/example-app/ENV_MAIN_SHA/source status --porcelain --untracked-files=all
   ```

   Require the recorded SHA and empty status. Reuse an existing clone only after
   these checks pass. Export that revision's tracked source through the Linux client:

   ```sh
   docker compose --profile ci run --rm --volume ./.infra-private/onboarding:/workspace/.infra-private/onboarding --entrypoint sh ci-bootstrap -ec 'git -C /infra-work/harbor/ci/environment-sources/example-app/ENV_MAIN_SHA/source archive --format=tar --output=/workspace/.infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/source.tar ENV_MAIN_SHA; tar -xf /workspace/.infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/source.tar -C /workspace/.infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/tracked-source'
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
5. **Agent:** scan and publish that unchanged archive through the existing owner:

   ```sh
   gh auth token | docker compose --profile ci run --build -T --rm --volume ../cloudlab-config/platform/ci/pools/example-app:/application:ro --volume ./.infra-private/onboarding:/workspace/.infra-private/onboarding ci-bootstrap --test-environment-archive /workspace/.infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/environment.tar --application-file /application/application.json --source-checkout /infra-work/harbor/ci/environment-sources/example-app/ENV_MAIN_SHA/source --output /workspace/.infra-private/onboarding/example-app/environment-ENV_MAIN_SHA/reference.json
   ```

   Require the current locked scan to pass unchanged; never weaken its gate.
   If protected `main` advances before publication, stop and rebuild/retest from its new SHA.
   Never relabel an old archive to match a newer revision.
   Read ignored `reference.json`, whose shape is `{"image": "<immutable registry reference>"}`.
   Set `testing` in private `platform/ci/pools/example-app/application.json` to that object,
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
3. Confirm the matching release App can propose PRs in the destination below.
   Use the [Harbor installation contract](../ansible/playbooks/harbor/files/contract.json)
   for App fields and grants. Keep App keys in 1Password.
4. Confirm the destination has the required server-enforced release merge guard:
   approved administrators merge through PRs; release Apps cannot merge.
   Use the existing [workflow policy owner](../infra/github-workflows/merge-guard.tf).
   Private exact-revision approval does not waive this guard. If the destination
   cannot enforce it, stop publishing rather than bypassing the check.
5. For private signing, confirm CloudLab items `ci-private-signer/private_key`
   and `ci-private-verifier/public_key` exist. If missing, use the existing
   [signing owner](../ansible/playbooks/ci/files/signing.py) through
   `docker compose --profile ci run --build --rm ci-signing`.
   The local provisioning token stays local. Never put secret values in GitOps JSON.

| Source repo | Release App credential | Release file destination |
| --- | --- | --- |
| Public | `github-release-public` | Public platform repo: `apps/releases/example-app.json` |
| Private | `github-release-private` | Private GitOps repo: `apps/releases/example-app.json` |

**Done when:** registry credentials, signing inputs and protected release destination
are available through their existing owners.

### 5.3 Generate runner configuration — Agent

Read the existing private input:
`../cloudlab-config/platform/ci/pools/example-app/application.json`.
Keep application name, source URL and visibility consistent with section 4.
Include the reviewed `testing.image` pin from section 5.1. The generator must include
direct-test support and accept the matching two-node qualification before use.

Run from the clean, published platform checkout. Replace `REVIEWED_MAIN_SHA`
with the exact 40-character application `main` commit from section 5.1.
Use a fresh output directory; do not overwrite section 4's output.

For public repository-owned CI without publishing:

```sh
gh auth token | docker compose --profile ci run --build -T --rm --volume ../cloudlab-config/platform/ci/pools/example-app:/application:ro --volume ./.infra-private/onboarding:/generated --entrypoint python ci-bootstrap -m playbooks.ci.files.configuration --application-file /application/application.json --approve-repository-workflow --workflow-revision REVIEWED_MAIN_SHA --output /generated/example-app/ci-first
```

This command supports public repository-owned direct tests and main-only builds.
Private registration still rejects `--approve-repository-workflow`; its legacy shared
test workflow builds an image and does not meet this policy. Do not enable private
PR/dev testing until an accepted direct-test interface exists.
Private exact-revision approval remains main-only and is not a workaround for branch tests.

Without publishing, output is `application_documents: 2`, containing `controller.json` and
`runner.json`. The controller normally remains unchanged; no second-pool quota is needed.
Only for publishing, complete section 5.2 and add `--publish` to the generator command.
That produces `application_documents: 3`. Generated files are under
`.infra-private/onboarding/example-app/ci-first/`:

| Generated file | Purpose |
| --- | --- |
| `controller.json` | Controller configuration; publishing updates quota to `values.runnerPools: 2` |
| `runner.json` | Approves direct tests and any main-only build job on `cloudlab-example-app`; pins the test environment |
| `publisher.json`, publishing only | Approves publishing and assigns `cloudlab-example-app-publish` |

The generator binds workflow approval and, when publishing, the release destination; it does not
deploy runners, create registry credentials or publish an application image.

**Done when:** the required files are generated from the reviewed application revision.

### 5.4 Deploy the approved pools — Agent, then User

1. **Agent:** copy generated files into private
   `platform/ci/pools/example-app/`, alongside the existing `application.json`.
   Review `controller.json`; tests and main-only builds normally leave it unchanged.
   For publishing, include its regenerated quota for the second pool and `publisher.json`.
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
   When enabled, publishing builds root `Dockerfile`'s `runtime`
   target, scans the image, pushes it to the matching Harbor project and signs
   the digest. It then proposes `apps/releases/example-app.json` in the destination
   from section 5.2.
3. **User:** if publishing, review and merge the release PR through branch protection.
   **Agent:** verify the release file records the expected `digest`,
   `source_revision` and `workflow_run_id`. The release App never merges its own PR.
4. **User:** where branch protection is supported, add the successful test check on application
   `main`, using the actual check name shown by GitHub.
   **Agent:** confirm the saved rule. Keep manual protection changes with the user.
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

1. **Agent:** update the same entry in private `services/catalog.json`.
   Declare required SQL/S3 resources in `definition.data`, storage in
   `definition.persistence`, secret mounts in `definition.secrets`, and login in
   `definition.oidc`. Leave unused features disabled or empty.
2. **Agent:** add scoped data bindings to the catalog's top-level `dataApprovals`.
   Match the service, resource name and credential reference. Include the database
   migration item when needed. Approve required references in
   `approval.secretReferences`; never grant application pods privileged data credentials.
3. **User/Agent:** keep secret values in 1Password's CloudLab vault.
   Use the [service contract](../charts/service/README.md) for required item fields
   and credential provisioning. Preserve existing secrets on repeat runs.
4. **Agent:** configure optional login through section 6.5 before publication.
5. **Agent:** confirm backup coverage before storing important data.
   Service PVCs require separate verified backup coverage; declaring storage is not a backup.

**Done when:** dependency requests, scoped references and secret custody are declared.

### 6.3 Choose access — User, then Agent

1. **Agent:** ask the user to choose no ingress, private access, public access,
   or a public primary exposure with additional private views, unless already
   explicitly answered. Wait for the answer before configuring or publishing access.
   Source repo visibility and existing exposure settings are not consent for this choice.
2. **Agent:** set `definition.exposure` in private `services/catalog.json`.
   For private access, use class `private`, an `internal` hostname and `tailnet`
   access. For public access, use class `public` and classify access as `public`,
   `human` or `machine`. Use class `none` for no ingress.
3. **Agent:** set the hostname, path and backend port for exposed services.
   Use `definition.additionalExposures` only for required additional private views.
   Match OIDC callback paths to these hosts.
4. **Agent:** configure the required identity and access policies through section 6.5.

An HTTPRoute does not create public DNS, tunnel routing or Access protection.
Do not change an existing exposure class through an ordinary catalog update;
use the service contract's retirement and migration procedure.

**Done when:** the catalog's exposure hosts and access classes match the user's
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
   If already true, leave it unchanged. Routine onboarding needs no changes to
   shared `charts/service/` code.
5. **Agent:** use `lab data-credentials` and `lab setup` through Compose when
   prerequisites need provisioning or convergence. Wait for Argo to read private
   `services/catalog.json` from protected `main` and deploy the service.

**Done when:** the approved workload has converged. Access publication still
requires the checks below.

### 6.5 Configure identity and access policies — User, then Agent

Use the existing identity, access, data and admission owners.
Keep private settings in their accepted inputs and secret values in 1Password.

1. **User:** decide whether the app needs Keycloak login.
   **Agent:** review `definition.oidc` in private `services/catalog.json`.
   Leave it disabled when unused. Otherwise set `realm: applications`, `client`,
   `public`, `callbackPaths`, `audience`, `scopes` and `roleMapping` using the
   [service schema](../charts/service/values.schema.json).
   Use Code + PKCE S256. Public clients have no secret.
   Confidential clients also require `secretReference`, an approved
   `definition.secrets` mount and `approval.secretReferences` entry.
   The identity owner keeps their secret in `keycloak-client-secrets/client_secrets`
   in CloudLab; never put the value in the catalog.
2. **Agent:** check exact HTTPS callbacks derived from declared exposure hosts
   and `callbackPaths`; public-client web origins derive from those same hosts.
   Never use wildcard callbacks or unrelated origins.
   The service adapter does not expose logout callback settings. If the app needs
   registered logout redirects, report this unsupported service field to the identity
   owner and stop that integration. Logout redirects must stay on approved callback origins.
   Submit any changed service settings through the catalog PR flow in section 6.4.
   Then use the current reviewed lifecycle bundle with the
   [service contract](../charts/service/README.md) command
   `service identity-provision <bundle>` through Compose.
   **User:** review and merge its scoped private identity PR.
   **Agent:** run `docker compose run --build --rm lab identity-scoped` and verify
   client configuration. The owner generates `identity/configmap.yaml` and changes
   `identity/argo-values.yaml` only when its integration requires it.
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

1. **Agent:** use the current approved service lifecycle bundle.
   See the [service contract](../charts/service/README.md) for its fields and
   Compose commands. The bundle must match the merged catalog entry.
2. **Agent:** run `service ready <bundle>` through Compose.
   Confirm identity, scoped data access, backend health and TLS readiness.
   Stop publication on failure; report the blocked check and owning configuration.
   Make only corrections already within the agreed setup scope.
3. **Agent:** run `service publish <bundle>` through Compose.
   It verifies protection and routing before DNS publication and reachability checks.
   Public stages maintain the existing native Cloudflare inputs and state.
   When private exposures exist, publication also writes catalog
   `publication: published` through a private PR and attempts its protected merge.
   If blocked, **User:** review and merge that PR; **Agent:** rerun publication.
   Public-only publication uses native provider state and does not automatically
   change the catalog entry to `published`.
4. **User/Agent:** open the published hostname from an intended client.
   Verify login and permitted application actions. Check anonymous or unauthorized
   access is denied where required. Test each additional private view from the tailnet.
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
   `PR_MERGE_SHA` below with that PR number and its current `merge_commit_sha`:

   ```sh
   gh auth token | docker compose --profile ci run --build -T --rm --volume ../cloudlab-config/platform/ci/pools/example-app:/application:ro --volume ./.infra-private/onboarding:/generated --entrypoint python ci-bootstrap -m playbooks.ci.files.configuration --application-file /application/application.json --approve-repository-workflow --workflow-revision PR_MERGE_SHA --pull-request PR_NUMBER --output /generated/example-app/pr-PR_NUMBER-PR_MERGE_SHA
   ```

   Review generated `runner.json` into private `platform/ci/pools/example-app/runner.json`.
   Preserve existing controller quotas and publisher configuration.
   **User:** review and merge this private approval PR before application tests or merge.
4. **Agent:** wait for the runner's Argo application to become Synced and Healthy.
   Rerun the eligible current PR workflow; changing approval does not retry failed jobs.
   If the PR head or base changes, refresh `merge_commit_sha` and recheck approval
   against that revision. **User:** merge the application PR only after required checks are green.
5. **Agent:** after merge, read the new protected `main` SHA and regenerate main approval
   using section 5.3; include `--publish` when publishing is enabled.
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
   The main build job uses approved application Dockerfiles; the existing publisher
   builds root `Dockerfile`'s `runtime` target.
   Ordinary releases need no edits to workflow or runner configuration files.
3. Find the release PR created by the publisher. If a job fails, fix the owning
   application or approved configuration before retrying.

**Done when:** CI has published a signed digest and proposed its release record.

### 7.3 Review the release PR — User, then Agent

The publisher changes this file in the owning release repo:

| Application source visibility | Release file |
| --- | --- |
| Public | Public platform repo: `apps/releases/example-app.json` |
| Private | Private GitOps repo: `apps/releases/example-app.json` |

1. **Agent:** check the PR changes only the expected release record.
   Verify `digest` matches the signed image, `source_revision` matches the approved
   application commit, and `workflow_run_id` identifies the successful publishing run.
   All three fields are strings.
2. **User:** review and merge through branch protection. The release App proposes
   the PR; it cannot merge it.

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
3. **Agent:** open a rollback PR restoring the complete previous release record:
   `digest`, `source_revision` and `workflow_run_id` from that same historical version.
   Use the recorded immutable digest; do not reconstruct it from a tag.
4. **User:** review and merge through branch protection.
   **Agent:** repeat section 7.4 against the restored record.

**Done when:** the previous approved digest is healthy and intended access works
with the current data state.

## 8. Add a service dashboard in Grafana

Dashboards belong to the platform's Git provisioning owner.
Public and private application sources use the same dashboard location below.
If content cannot safely enter public Git, stop and agree an accepted private
input with the observability owner; do not invent a separate provisioning path.

### 8.1 Choose the service view — User, then Agent

1. **User:** name the questions the dashboard must answer.
   Start with request rate, errors, latency, health and CPU/memory usage.
   Add logs or traces only when their collection is already approved.
2. **Agent:** inspect the [observability contract](../platform/observability/contract.json)
   and actual collected metrics. Identify service and namespace labels before
   writing queries; do not assume application metrics already exist.
3. **Agent:** separate real user traffic from release tests, probes and synthetic
   traffic. User SLO panels must select user traffic only.
   Plan distinct states for valid zero requests, missing telemetry and insufficient evidence.

**Done when:** required panels and their real telemetry sources are identified.

### 8.2 Confirm telemetry coverage — Agent, then User

1. **Agent:** inspect the application's existing metrics/instrumentation code;
   its filename depends on the app. Use [Notes instrumentation](../apps/notes/telemetry.py)
   as a reference for bounded, redacted metrics, not as a generic app installer.
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
4. **Agent:** for SLOs, use the owning service's approved definition and rules.
   Existing `apps/notes/slo.json` and `ansible/playbooks/observability/files/slo.py`
   belong to Notes. Their generated
   `platform/observability/prometheus/templates/notes-slo.json` is a PrometheusRule,
   not a Grafana dashboard or generic SLO onboarding interface.

**Done when:** accepted collection supplies the metrics and rules required by the dashboard.

### 8.3 Write the dashboard JSON — Agent

1. Create public platform
   `platform/observability/prometheus/dashboards/example-app.json`.
   Use existing [nodes.json](../platform/observability/prometheus/dashboards/nodes.json)
   and [releases.json](../platform/observability/prometheus/dashboards/releases.json)
   as references. Choose a unique, stable dashboard UID and title.
2. Use provisioned data sources: Prometheus UID `metrics`, Loki UID `logs`
   and Tempo UID `traces`. Reference their UIDs; do not embed backend URLs.
   Scope queries with namespace and service variables using actual metric labels.
3. Add the agreed panels. Keep user SLOs separate from release/probe/synthetic traffic.
   Display valid zero activity as **No traffic** and missing evidence as **UNKNOWN**
   or **No data**. Do not turn missing series into healthy zero values.
4. Keep secrets, private names, endpoints and saved private variable selections
   out of the JSON. Use generic defaults and label variables.
   Set `editable: false` to match the existing provisioned dashboards.

**Done when:** the JSON defines scoped, readable panels without private deployment details.

### 8.4 Review and deploy the dashboard — Agent, then User

1. **Agent:** validate JSON and run focused checks of the owning chart.
   Confirm the rendered `cloudlab-dashboards` ConfigMap includes `example-app.json`.
   Platform `platform/observability/prometheus/templates/dashboards.yaml` already
   imports `dashboards/*.json`; routine dashboard additions need no template edit.
2. **Agent:** leave existing `dashboardProviders` and `dashboardsConfigMaps` in
   `platform/observability/prometheus/values.json` unchanged.
   `ansible/playbooks/observability/files/configuration.py` owns Grafana settings;
   adding a service dashboard does not require changing them.
3. **Agent:** commit the dashboard to a platform branch and open its PR.
   **User:** review and merge through branch protection.
4. **Agent:** wait for Argo to reconcile the chart and dashboard ConfigMap.
   Grafana's existing `cloudlab` file provider provisions the dashboard in its
   **CloudLab** folder from `/var/lib/grafana/dashboards/cloudlab/example-app.json`.

**Done when:** the merged dashboard appears through the existing Git provisioning path.

### 8.5 Verify real data and reconciliation — User, then Agent

1. **User/Agent:** open Grafana through its existing private access and Keycloak login.
   Select the intended service and namespace; check panels against actual metrics.
2. **Agent:** compare a bounded request sample with observed rate, errors and latency.
   Check health and resource panels against the selected workloads.
   Verify **No traffic** and missing/stale telemetry states using focused queries
   or an isolated fixture; do not interrupt production collection for this test.
3. **Agent:** verify optional log/trace links use only accepted redacted telemetry.
   Confirm no unrelated service data enters the selected view.
4. **Agent:** let normal reconciliation run and confirm the dashboard remains correct.
   Make lasting edits in the JSON and repeat its PR flow; UI-only changes are not durable.

**Done when:** real data, zero/missing behavior and Git reconciliation all behave as intended.

## 9. Retire a service safely

Retirement removes service access and its owned workload. It retains data.
Check all declared exposure hosts, regardless of source repo visibility.

| Repo or owner | Path | Retirement effect |
| --- | --- | --- |
| Private GitOps | `services/catalog.json` | Keep the entry with `publication: retired`; preserve its definition, approval and data bindings |
| Private identity owner | `identity/configmap.yaml`, `identity/argo-values.yaml` | Owner prepares disabled-client state and removal tombstones; preserve the shared overlay |
| Native Cloudflare owner | `${INFRA_PRIVATE_DIR}/cloudflare/desired.tfvars.json` | Withdraw service DNS and tunnel routing through existing operations; keep inputs outside Git |
| Private GitOps | `platform/ci/pools/example-app/` | Runner configuration stays; CI retirement needs a separate explicit decision |
| Source and owning release repos | Application source, `.github/workflows/ci.yaml`, `apps/releases/example-app.json` | Preserve source, release history and recoverable artifacts; service retirement does not delete them |

### 9.1 Confirm the retirement scope — User, then Agent

1. **User:** name the service to retire, for example `example-app`.
   Retaining data is part of this operation; data disposal requires separate,
   explicit resource and data scope.
2. **Agent:** read its current private `services/catalog.json` entry and approved
   lifecycle bundle. Preserve the entry, other services and top-level `dataApprovals`.
   Record which primary/additional hosts and OIDC client belong to this service.
3. **Agent:** use the [service contract](../charts/service/README.md) for the
   bundle fields and existing Compose mounts. Commands below run from the platform
   checkout. Replace `BUNDLE` with that bundle's container-visible path.
   Keep the same reviewed definition and approval throughout retirement.

**Done when:** the service, exposure hosts and retained data are unambiguous.

### 9.2 Withdraw reachability — Agent, then User

Run the existing lifecycle operation with its GitHub writer supplied through stdin:

```sh
gh auth token | docker compose --profile services run --build -T --rm service retire BUNDLE
```

It withdraws DNS and routing, then checks route absence before identity or workload removal.
For public access, native operations update
`${INFRA_PRIVATE_DIR}/cloudflare/desired.tfvars.json`; the default path is
`../yasai-cloudlab-infra-inputs/cloudflare/desired.tfvars.json`.
For private access, the owner withdraws private service DNS.
The lifecycle writes catalog `publication: retired` through a protected private PR.
**User:** review and merge a blocked catalog PR. **Agent:** rerun the same operation.

An OIDC service can stop here pending the identity stages below.
A service without OIDC can complete workload retirement in this first call.
Shared Access protection is retained; do not delete it to retire one service.

**Done when:** DNS/tunnel/HTTPRoute reachability is withdrawn for the retired service.

### 9.3 Retire the OIDC client, if enabled — Agent, then User

First propose client disablement:

```sh
gh auth token | docker compose --profile services run --build -T --rm service identity-retire BUNDLE
```

**User:** review and merge the scoped identity PR.
**Agent:** run `docker compose run --build --rm lab identity-scoped` and verify
the client is disabled before proposing removal:

```sh
gh auth token | docker compose --profile services run --build -T --rm service identity-remove BUNDLE
```

**User:** review and merge the removal-tombstone PR.
**Agent:** converge the scoped identity source again.
The identity owner prepares these changes in private `identity/configmap.yaml`;
preserve `identity/argo-values.yaml` unless its owner explicitly proposes a change.
The next retirement run enforces the token/session grace period before actual client
deletion. Preparing the removal PR does not skip that wait or revoke issued JWTs instantly.
The vault value and persistent retirement tombstones remain.

**Done when:** disablement has converged and the reviewed removal intent is available.
Skip this step when `definition.oidc.enabled` is false.

### 9.4 Complete workload retirement — Agent

Rerun the same `service retire BUNDLE` Compose command from section 9.2.
For OIDC, let the identity owner complete its enforced grace and client removal.
The lifecycle then verifies retired catalog intent and removes only tracked
service-owned workload resources, including its Deployment/Rollout, Service and routes.
It removes the scoped Argo Application without cascading into retained resources.
This is workload removal, not merely scaling replicas to zero.

Namespaces, quotas, credentials, PVCs, databases, buckets and shared resources remain.
Runner pools are separate resources; this operation does not retire them.
If interrupted, rerun with the same reviewed inputs. Preserve existing credentials
and provider state; resolve the reported owner prerequisite before continuing.

**Done when:** the lifecycle reports `operation: retire` and `verified: true`.

### 9.5 Verify retirement and retention — Agent, then User

1. **Agent:** confirm private `services/catalog.json` still contains `example-app`
   with `publication: retired`. Never remove the entry to represent retirement.
2. **User/Agent:** check the old primary and additional hostnames from their former
   public or tailnet clients. Confirm they no longer reach this application.
   For class `none`, verify the former internal caller cannot reach its removed Service.
3. **Agent:** confirm the scoped workload and routes are absent, retained claims
   and data resources remain, and unrelated services stay healthy.
   Use non-destructive owner checks; never run `service fixture-proof` against this service.
4. **User:** decide separately whether CI pools, App repo grants or source activity
   should stop. Preserve approved images, signatures and recovery material until
   their separate retention or disposal scope is agreed.

**Done when:** the service is unreachable, its workload is retired and retained data
and shared resources remain available to their owners.
