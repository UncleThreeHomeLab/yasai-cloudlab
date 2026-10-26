# Private previews

The [contract](../../../platform/delivery/previews/contract.json) owns limits and
credential fields. Previews use a fixed platform chart, private gateway, restricted
namespace and per-instance PKCE client. The existing leased identity writer owns
client creation, disable and physical removal. No realm credential enters the
preview controller or workload.

Enable `previews.enabled` in the public root after reviewing its private inputs.
Declare one private hostname label through `PRIVATE_ACCESS_HOSTS` in `.env`; the
existing access owner supplies DNS and TLS. Keep `previews/catalog.json` in the
designated private configuration repository as `{"catalog": {...}}`, with:

- `hostname`, canonical applications `issuer`, and `privateDiscovery`.
- `approvals`: immutable records containing `instance`, `repository`,
  `repositoryId`, `pullRequest`, `sourceSha`, `sourcePath`, `sourceDigest`,
  `definition`, `image`, `platformRevision`, `createdAt`, `expiresAt`.
- `ownership`: namespace to `instance:approvalDigest` authorizations. Retain each
  entry until its namespace is verified absent. Removing execution approval alone
  triggers orphan retirement; authorization alone never starts execution.
- `artifacts`: image repository to exact `subject`, `issuer`, `sourceRepository`
  and `public: true` trust. Existing signing must bind the image to `sourceSha`.

Plain public rendering grants only the public project source. Private source
authorization and its credential require the accepted native identity overlay.
Setup checks that handoff, current retired scoped identity and exact ready source
ownership before discovery delivery or controller configuration; rendering alone
does not establish readiness.

The PR file `previews/definition.json` selects one profile:

- `{"profile":"synthetic","message":"synthetic data"}` uses the fixed pinned
  platform image. This proves configuration binding, not a build from the PR.
- `application` requires `profile`, `port`, `healthPath: "/healthz"`,
  `environment` and bounded `resources.requests/limits`. Environment keys start
  with `PREVIEW_` and contain synthetic non-secret settings. The platform supplies
  `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_AUDIENCE`, `OIDC_REDIRECT_URI`,
  `OIDC_CALLBACK_PATH`, `CLOUDLAB_PREVIEW_PATH` and `CLOUDLAB_SOURCE_SHA`.
  The image uses its approved entry point; source files cannot supply commands,
  mounts, credentials, storage, additional routes or chart overrides.

Image selection belongs to administrator approval, outside the source blob. This
lets an existing trusted build sign that exact commit before its digest is approved.
The catalog label is at most 30 characters. Each browser origin is
`https://<label>-<32hex-instance>.internal.<zone>`; callbacks retain the exact
`/previews/<instance>/callback` path. Legacy shared-origin records retire before
execution or client repair. Synthetic
callbacks are empty landing endpoints for an external Code+PKCE verifier. Application
images must support the supplied callback and base path. Audience checks occur at
the namespace waypoint; direct pod/service access cannot bypass that waypoint.

Use `lab preview prepare docs/local/request.json` with `repository`, `pullRequest`,
`image`, `platformRevision`, `lifetimeSeconds` and `private`. The approved record is
written privately under `/recovery`. `lab preview catalog-propose
docs/local/catalog.json` requires `catalog` and the inspected main SHA as
`expectedBase`; it opens the owning private PR. Review and merge explicitly.
Neither operation enables automatic merging. Public discovery is anonymous.
Private discovery uses the existing `github-release-private` App only on the
trusted local Compose executor. It derives an exact-repository Contents/PR read
token; App keys never enter the host, controller or workload. Private approvals
last at most 3000 seconds and expire at least 300 seconds before their token.
Bootstrap preserves an owned valid token on repeat apply. Superseded tokens
expire naturally within their issuer-enforced one-hour lifetime. Missing or
expired tokens block activation while local expiry and cleanup continue.
Anonymous discovery checks every fifteen minutes to fit GitHub's public API budget;
authenticated discovery checks every minute. Expiry checks remain every minute.

Run credential-free `docker compose run --rm lab preview check`. Apply and verify
with `docker compose run --rm lab preview prove`; it applies twice and requires
zero changes on both nodes on the second apply. Bootstrap qualifies native
admission with privileged impersonation and server dry runs before enabling
controller permissions. Actual service-account RBAC is checked separately.
The explicitly invoked `playbooks.previews.tests.native_admission --live` fixture
qualifies isolated copies of these policies through Compose and existing SSH;
it creates no controller grants and removes only its owned resources.
PR revision, positive OIDC, close, expiry and orphan acceptance use owned fixtures;
ordinary component verification does not claim those checks passed.
Explicit fixture journals use the existing private Linux recovery volume at
`/recovery/previews/<fixture-nonce>/journal.json`, with mode 0600, durable writes
and digest-checked updates. Keep journals until owned resources are absent;
never clear the shared recovery volume.
Run the isolated browser fixture from a clean checkout without `.env`:

```sh
echo '["https://preview-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.internal.example.invalid","https://preview-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.internal.example.invalid"]' | docker compose -f ansible/playbooks/previews/tests/compose.browser-origins.yml run --build --rm -T browser
```

Input accepts only two distinct synthetic nonce origins in `internal.example.invalid`.
The existing pinned browser recipe checks DOM, storage, host cookies and CORS
using ephemeral local HTTPS. It proves no live TLS or OIDC behavior.

`lab preview dns` applies only the existing host DNS owner after validating the
enabled catalog and reserved private prefix. It changes no external grants or
public records. `lab preview withdraw docs/local/withdraw.json` takes a journaled
`stateUID` and `entries` map of instance to approval digest. It irreversibly
withdraws only those entries using native resource-version checks, without Git
or discovery credentials; the running lifecycle owners finish cleanup.

Close, a new commit, expiry or missing approval irreversibly withdraws execution.
Client removal follows verified disable plus 600 seconds, across bounded jobs.
Git outages block new activation; absolute expiry continues from cluster state.
Cleanup uses exact resource UIDs and orphan propagation for Argo objects. Complete
namespace inventory precedes cascading workload/gateway deletion. Unexpected PVCs,
secrets, retained objects or foreign ownership leave quarantined resources for
operator review; route withdrawal and identity retirement continue. Persistent
applications, private roots, vault items and external data are never removed.
After withdrawing private approvals and removing their ApplicationSets, run
`lab preview credentials-retire` to revoke and UID-guard deletion of only the
owned operational discovery Secret. No vault item or App key changes.

Explicit fixture stages run through `docker compose run --rm --entrypoint python
lab -m playbooks.previews.tests.live_acceptance <stage> --nonce <32hex> --live`.
Use `inspect`, then `viewer-provision`, `viewer-stage`, `viewer-propose`,
`viewer-merge`, and `viewer-enroll`. Publication and protected merge are separate
stages. `viewer-observe`, `offboard-propose`, `offboard-merge`, `viewer-offboard`
retain the viewer tombstone and vault item. Synthetic PR stages are `pr-create`,
`pr-advance` and `pr-cleanup`, with `--slot a|b|c|d`. No PR merges release code.
An interrupted `approval-prepare` may use `approval-abandon` after its saved
preparations expire. Original records remain immutable; the journal then permits
only observation and cleanup that reduces authority. Offboarding and closing owned
source PRs need no activation proof. Catalog ownership still requires actual absence.
Each invocation requires clean published main and a serialized private journal;
the original platform revision must remain its ancestor. Runtime viewer changes
use the versioned fixture Ansible entry point and existing identity owners.

`approval-prepare --batch ab|cd --lifetime <seconds>` reserves immutable private
approvals and artifacts after fresh owner/viewer checks. `catalog-prepare` accepts
the same batch with `--mode approve|withdraw|cleanup|finalize`; publication requires
separate `catalog-propose`, `catalog-review` and `catalog-merge` stages. Stale bases
use `catalog-reprepare`, preserving old proposal receipts. `lifecycle-observe`
records exact resource/client identities, confirmed disable time and final absence;
cleanup cannot remove ownership before that evidence. `catalog-retire` closes and
atomically deletes only proposal refs with recorded creation intents. Historical
unjournaled refs remain retained. Approval retries never extend expiry.

The explicit `browser` stage uses `tests/compose.browser-live.yml`: start its
`browser` service, then run `controller --nonce <32hex> --live`. Only controller
mounts local inputs and private recovery. The journal must contain two exact
`instances` and `browserApprovals` entries `a`/`b`, each with `instance` and
`approvalDigest`, matching its owned PR receipts and current catalog. Missing
receipts refuse execution; this stage never creates execution approvals.
The browser keeps credentials and sessions in memory, captures authorization
callbacks before dispatch, and uses verified private TLS. After WebAuthn failure,
retain the journal and use existing offboarding; automatic viewer reset is unsupported.
Pre-enrollment failures remain retryable. A durable attempt marker precedes the
first credential frame; subsequent failures permit offboarding only. The browser
waits at most ten minutes for controller preflight, then bounds the proof to four minutes.
After process interruption, `offboard-propose` can replace only the exact consumed
browser intent under the journal lock; other interrupted operations still require resume.

Credential-free browser checks: `docker compose -f
ansible/playbooks/previews/tests/compose.browser-live.yml --profile offline run
--build --rm -T offline`; replace `offline` with `checks` for controller tests.
The isolated synthetic CA checks real TLS validation and browser isolation;
it establishes no live identity, gateway or application-build result.
