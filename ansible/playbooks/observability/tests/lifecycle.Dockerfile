ARG RUNNER_IMAGE
FROM quay.io/argoproj/argocd:v3.5.3@sha256:dd3f47d5a5e4da563a7a398506e892481b358a7cec50abdf320c71aa55904bfa AS argocd
FROM ${RUNNER_IMAGE}
COPY --from=argocd /usr/local/bin/argocd /usr/local/bin/argocd
