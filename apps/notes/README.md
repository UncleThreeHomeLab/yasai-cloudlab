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

The data owner applies [the schema](schema.sql) and creates a synthetic welcome note
only when absent. Repeat apply preserves edited notes and existing objects. The web
pod receives no SQL/S3 credentials; the API receives only its application credentials
and the existing public database CA. Shared operators and Secret values are never
installed by this chart.

Python and dependency wheels are pinned. The API installs hash-checked wheels into
a bounded ephemeral volume during startup. Regenerate first-party artifacts with
`python -m automation.services.package build`; `lab service-check` verifies source
parity and deterministic rendering. Dependency changes require repeating these checks.
