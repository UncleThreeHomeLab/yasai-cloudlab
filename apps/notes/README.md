# Notes

Two services: a static web frontend and a bearer-token API. PostgreSQL stores notes;
S3 stores immutable text attachments. The public view requires OIDC to read or write.
The private operations view additionally requires the `operator` role and private
hostname. Tokens stay in browser memory; reloading starts another PKCE/SSO transaction.

Use the [service contract](../../charts/service/README.md) for onboarding. The
administrator selects `approval.chartPath: apps/notes` and supplies one `notes`
definition with its public exposure and one private operations exposure. The compiler
derives both workloads, callbacks, origins and route paths from that definition.
Use `reader`, `writer` and `operator` client roles with explicit group mappings.
Request the existing notes database/bucket through their scoped references.

For the verified lab owner, run `lab identity-owner-credentials`, then
`identity-owner-stage`, `identity-owner-publish`, and `identity-owner-enroll`.
Credentials and private publication use the existing scoped provisioning inputs.
Merge the reviewed private identity PR before enrollment. Staging pauses the sole
writer before declaring the membership; enrollment creates only the owned applications
account, then resumes reconciliation. Repeat enrollment preserves credentials.
Use `keycloak-applications-owner-login` in 1Password to sign in to Notes. Complete
the required passkey registration in your personal vault. Applications roles grant
Notes access; they do not grant Keycloak realm administration.

The data owner applies [the schema](schema.sql) and creates a synthetic welcome note
only when absent. Repeat apply preserves edited notes and existing objects. The web
pod receives no SQL/S3 credentials; the API receives only its application credentials
and the existing public database CA. Shared operators and Secret values are never
installed by this chart.

Public `/health` checks the API's SQL/S3 readiness without credentials or caching.
`/monitoring-proof/ready` and `/monitoring-proof/failed` return generic 200/503
responses for disposable external notification checks; they do not change app state.

The shared [SLO definition](slo.json) generates user rules and dashboards. Release
traffic uses `/api/release/notes` and stays outside user indicators. Prepare a
disposable applications viewer with `gh auth token | docker compose run -T --rm
lab observe baseline-prepare`. Then run `gh auth token | docker compose -f
automation/observability/compose.baseline.yaml run --build -T --rm
baseline-controller`. The pinned browser registers a disposable passkey; pinned
k6 measures bounded authenticated reads. Successful measurement offboards the
viewer. Keep the private recovery checkpoint on failure and repeat to resume.
The redacted result remains in the recovery volume. Primary accounts stay unchanged.

Python and dependency wheels are pinned. The API installs hash-checked wheels into
a bounded ephemeral volume during startup. Regenerate first-party artifacts with
`python -m automation.services.package build`; `lab service-check` verifies source
parity and deterministic rendering. Dependency changes require repeating these checks.
