# Dependency maintenance

Local Compose runs Renovate proposals and existing verification without lab CI.
[Owners](../../../platform/delivery/dependencies/owners.json) define compatible
groups, writable pins, generated companions and required checks. Native proposals
only create drafts. Artifact repair and tests run separately without credentials,
private configuration, backend state or a Docker socket.

Credentialed operations require clean, anonymously published platform `main`.
The existing `CloudLab/github-release-public` item supplies `APP_ID`,
`INSTALLATION_ID` and `PRIVATE_KEY`; `OP_SERVICE_ACCOUNT_TOKEN` reads the vault.
The local control process derives one-repository installation tokens with Contents
and Pull requests write and Metadata read, then revokes them after each operation.
Keys stay local. No additional GitHub grants are required.

Run commands from the repository root. Use one operation at a time for the
repository. Work defaults to `docs/local/dependency-work`; optional
`DEPENDENCY_WORK_DIR` selects an absolute host directory. Substitute its host path
where commands below name the default work directory. Keep receipts, candidate
files and raw reports private. A shared local lock rejects concurrent credentialed
controllers before vault access, including across Compose projects.

## Draft, repair and verify

Run credential-free checks, then request a selected native proposal:

```sh
docker compose -f ansible/playbooks/dependencies/compose.yaml run --build --rm checks
echo '{"base":"main","owners":["tool:tofu"]}' | docker compose -f ansible/playbooks/dependencies/compose.yaml run --rm -T propose
```

Replace `123` with the owned draft number and `<reviewed-version>` with its reviewed
target version. Export validates the entire initial diff before candidate code runs:

```sh
echo '{"base":"main","number":123,"owners":["tool:tofu"]}' | docker compose -f ansible/playbooks/dependencies/compose.yaml run --rm -T control export
echo '{"version":"<reviewed-version>"}' | docker compose -f ansible/playbooks/dependencies/compose.yaml run --rm -T maintain tool tofu
docker compose -f ansible/playbooks/dependencies/compose.yaml build candidate-runner
docker image inspect cloudlab-maintenance-candidate:local --format '{{json .Id}}' | docker compose -f ansible/playbooks/dependencies/compose.yaml run --rm -T record-toolchain candidate-runner
docker compose --env-file docs/local/dependency-work/control/toolchain.env -f ansible/playbooks/dependencies/compose.yaml run --rm verify
```

The native image inspection records its immutable ID. Verification checks the
embedded recipe, tool versions and provider packages against the candidate.
Git file modes remain validated and preserved on hosts without Unix permissions.
Follow any additional qualification required by the selected owner before verify.

Publish the complete repaired patch into the draft:

```sh
echo '{"base":"main","number":123}' | docker compose -f ansible/playbooks/dependencies/compose.yaml run --rm -T control publish
```

Re-export the same PR, then repeat toolchain recording and verification against
its exact published head. Perform applicable qualification again if its inputs or
receipt changed. Only then promote the verified draft:

```sh
echo '{"base":"main","number":123}' | docker compose -f ansible/playbooks/dependencies/compose.yaml run --rm -T control ready
```

Every owner write invalidates receipts and confirms draft state first. Head/base
changes refuse promotion. A collaborator push requires fresh export and
verification; merge only the exact tested SHA through existing protection.
Automatic merging and native branch pruning are disabled.

## Owner qualifications

The [maintenance entry point](files/command.py) accepts explicit JSON requests on
stdin. It reports pending builds rather than treating an unbuilt pin as verified.

| Update | Required companion work |
| --- | --- |
| Tools and native providers | Rebuild `candidate-runner`; `maintain registry NAME` regenerates ordinary registry locks without credentials. Existing OpenTofu format, readonly init, validate and tests remain mandatory. Fork source/compiler changes require a new package version, deterministic package review and native checksums in every owning root. |
| Charts and images | Refresh archives, checksums, native Helm locks and generated values together. A new Helm binary requires `finalize-helm` before recording; it requalifies all eight chart metadata companions. `maintain tool cmctl` and `maintain tool gateway-api-plugin` own their separate binary pins. PostgreSQL patch updates retain major version and distribution. |
| CI tools and runner | Preserve Go overlays, security packages and all NuGet locks. Build `candidate-ci-controller`, `candidate-ci-builder` and `candidate-ci-runner`; record each immutable ID as `ci-controller`, `ci-builder`, `ci-runner`. Save their original images as `controller.tar`, `builder.tar`, `runner.tar` under the work directory's `archives/`. Run `ci-build-proof` with `--build`, then `ci-scan`; the existing pinned database and HIGH/CRITICAL policy remain mandatory. |
| Browser | `maintain browser playwright` updates matching package, lock and image pins. Build `identity-browser`, record its ID as `identity-browser`, then run `verify-browser` with the generated env file before general verification. |
| Keycloak | `maintain chart identity/keycloak` requires `operator`, `server`, `configCli`, `configCliServer`. Changed artifacts reset qualification. Run `qualify-keycloak` with the generated env file, then record the candidate again and verify. This uses the existing isolated fixture, never production identity settings. |
| Renovate image | After recording the candidate, run `verify-renovate` with the generated env file. Strict native configuration, extraction and compatible groups must pass before general verification. |

Python wheel updates retain compatible, hash-locked closures across their owning
files. Reviewed BuildKit profile updates cannot expand syscall or AppArmor
permissions. Rebuild generated Notes/preview packages through their existing
owners after changing their inputs. Infrastructure credentials, encrypted state,
reviewed-plan gates and interrupted-operation recovery keep their existing owners.

## Application Actions pins

Actions pins use a separate, credential-free maintainer path. Supply the exact
current stable official checkout release commit on stdin to `maintain-actions`, build and record
`candidate-runner`, then run `verify-actions` with the generated env file. The
validated patch is `control/actions.patch`; deliver it through the authorized
maintainer session and existing PR protection. The release App rejects workflow
publication. Changed workflow bytes retain their existing execution approval gate.

After all owned jobs finish, run
`docker compose -f ansible/playbooks/dependencies/compose.yaml down` to remove disposable local services.
It preserves work files, named proof volumes and the shared control lock. Remove only explicitly owned
fixtures, branches and reviewed local data; never run general Docker pruning.
For an interrupted operation, stop its owned services and preserve its reports.
Restart with a new empty work directory and distinct Compose project; never reuse
old receipts to qualify a changed candidate.
