FROM docker.io/grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8 AS k6

FROM cgr.dev/chainguard/cosign@sha256:7fd4ddec6f62e877be6f47c0a3b743017ef0c709d5e395963ab3e82aa551fd58 AS cosign

FROM docker.io/aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb AS trivy

FROM reg.kyverno.io/kyverno/kyverno-cli:v1.19.2@sha256:322ec5044d600930cb3af0e56dc33154a2d1d1fba58f4cadad3f47be7e78b11c AS kyverno

FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72 AS provider-build
COPY debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY cloudflare-provider.lock.json cloudflare-legacy.patch build_cloudflare.py /opt/provider-build/
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build python /opt/provider-build/build_cloudflare.py
COPY harbor-provider.lock.json harbor-quota.patch build_harbor.py /opt/provider-build/
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build python /opt/provider-build/build_harbor.py

FROM provider-build AS crane
WORKDIR /build/crane
ADD --checksum=sha256:a52cc7d61f8b2f043b7f0be1febecead5fceb791543c4790d699440f12d6b370 https://codeload.github.com/google/go-containerregistry/tar.gz/refs/tags/v0.22.1 /tmp/crane.tgz
RUN tar -xzf /tmp/crane.tgz --strip-components=1 && rm /tmp/crane.tgz
COPY --from=ci-source tools/crane/go.mod tools/crane/go.sum ./
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=2 /build/compiler/go/bin/go build -mod=readonly -trimpath \
      -ldflags '-s -w -X github.com/google/go-containerregistry/cmd/crane/cmd.Version=v0.22.1-cloudlab.1' -o /out/crane ./cmd/crane

FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72

COPY --from=k6 /usr/bin/k6 /usr/local/bin/k6
COPY --from=cosign /usr/bin/cosign /usr/local/bin/cosign
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=crane /out/crane /usr/local/bin/crane
COPY --from=kyverno /ko-app/kubectl-kyverno /usr/local/bin/kyverno
COPY debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client sshpass git \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/runner/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /opt/runner/requirements.txt
COPY helm.lock.json install_helm.py /opt/runner/
RUN python /opt/runner/install_helm.py
COPY tools.lock.json install_tools.py /opt/runner/
RUN python /opt/runner/install_tools.py
COPY --from=provider-build /provider-mirror /opt/providers
COPY --from=ci-source tools/source.lock.json /opt/runner/ci-tools.lock.json
COPY providers.tfrc /opt/runner/providers.tfrc
COPY Dockerfile /opt/runner/Dockerfile
COPY run.py /opt/runner/run.py
ENV ANSIBLE_CONFIG=/workspace/ansible/ansible.cfg \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/workspace/ansible:/workspace
WORKDIR /workspace/ansible
ENTRYPOINT ["python", "/opt/runner/run.py"]
