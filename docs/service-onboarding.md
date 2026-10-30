# Add a service

Follow these steps for an application built on lab runners.
Use the [service contract](../charts/service/README.md) for deployment inputs.

**User:** make manual GitHub changes and review PRs.
**Agent:** prepare configuration, open PRs and verify deployment.
Keep application inputs in private GitOps. Never put private repo details,
credentials or diagnostic dumps in this public repo.

## 1. Create the application repo

1. **User:** create a GitHub repo, or select an existing repo you administer.
2. **User:** choose public or private visibility. This selects the CI trust boundary.
   Service network access is a separate choice.
3. **User:** push an initial commit. Set `main` as the default branch.
4. **Agent:** confirm the repo is active, is not a fork, and has the expected visibility.
5. **Agent:** collect the application name, `OWNER/REPO`, and visibility for registration.
   Use a name starting with a lowercase letter, followed by lowercase letters,
   digits or hyphens; maximum 35 characters.

**Done when:** the repo has a `main` commit and its identity is confirmed.

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

Select the existing App installation matching the source repo's visibility.
The names below identify lab credentials; confirm the matching installed App.

| Source repo | Runner App credential |
| --- | --- |
| Public | `github-arc-public` |
| Private | `github-arc` |

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
App access alone does not register runners or approve workflows.

See GitHub's [installed App instructions](https://docs.github.com/en/apps/using-github-apps/reviewing-and-modifying-installed-github-apps).

### Keep release access separate

Release Apps propose image-update PRs in the owning GitOps repo.
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
The workflow will select `cloudlab-example-app` for tests and
`cloudlab-example-app-publish` for publishing; it must not select GitHub-hosted runners.
