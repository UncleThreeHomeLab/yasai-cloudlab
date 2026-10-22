FROM docker.io/grafana/k6:2.3.0@sha256:9c2dee7f8ed74d317e4027c06a10f169b625638189de8d4555d0b3486a5aeb34 AS k6

FROM cgr.dev/chainguard/cosign@sha256:3fad8be83b93869051c08bb98f36612afe81dabe06c288e70e41ce09a037ba18 AS cosign

FROM docker.io/aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222 AS trivy

FROM reg.kyverno.io/kyverno/kyverno-cli:v1.19.1@sha256:ced7b2be0b04250cabfe695f15307f69eb715fe23234816388af4f3812915b2a AS kyverno

FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed AS provider-build
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

FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed AS bootstrap-tools
COPY debian.sources /etc/apt/sources.list.d/debian.sources
# Archive utilities stay in this build stage; Compose declares linux/amd64.
RUN apt-get update && apt-get install -y --no-install-recommends unzip bzip2 && rm -rf /var/lib/apt/lists/*
WORKDIR /tmp/tools
ADD --checksum=sha256:86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb https://get.helm.sh/helm-v4.3.0-linux-amd64.tar.gz helm.tar.gz
ADD --checksum=sha256:8ccbc6f8ee21d2827715f3c6e08a9b3e0209b1e62057c05067ef117e047c1a80 https://github.com/opentofu/opentofu/releases/download/v1.13.1/tofu_1.13.1_linux_amd64.zip tofu.zip
ADD --checksum=sha256:198b05dcf9a0972778ce5a4e262c459979b0c837257b5da65e2fba6187734226 https://cache.agilebits.com/dist/1P/op2/pkg/v2.34.0/op_linux_amd64_v2.34.0.zip op.zip
ADD --checksum=sha256:f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c https://github.com/restic/restic/releases/download/v0.19.1/restic_0.19.1_linux_amd64.bz2 restic.bz2
RUN mkdir /out \
    && tar -xzf helm.tar.gz --no-same-owner linux-amd64/helm \
    && test -f linux-amd64/helm && test ! -L linux-amd64/helm \
    && install -m 0755 linux-amd64/helm /out/helm \
    && unzip -p tofu.zip tofu > /out/tofu \
    && unzip -p op.zip op > /out/op \
    && bzip2 -dc restic.bz2 > /out/restic \
    && chmod 0755 /out/tofu /out/op /out/restic

FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed

COPY --from=k6 /usr/bin/k6 /usr/local/bin/k6
COPY --from=cosign /usr/bin/cosign /usr/local/bin/cosign
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=crane /out/crane /usr/local/bin/crane
COPY --from=kyverno /ko-app/kubectl-kyverno /usr/local/bin/kyverno
COPY --from=bootstrap-tools /out/ /usr/local/bin/
COPY debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client sshpass git \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /opt/runner/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /opt/runner/requirements.txt
COPY --from=provider-build /provider-mirror /opt/providers
COPY providers.tfrc /opt/runner/providers.tfrc
COPY run.py /opt/runner/run.py
ADD --checksum=sha256:46915a47dc933469dcd44cbb4e722203876ff7777d2a9b3e81c93060c662ce49 https://galaxy.ansible.com/api/v3/plugin/ansible/content/published/collections/artifacts/kubernetes-core-6.6.0.tar.gz /opt/runner/kubernetes-core.tar.gz
RUN mkdir -p /usr/share/ansible/collections/ansible_collections/kubernetes/core \
    && tar -xzf /opt/runner/kubernetes-core.tar.gz -C /usr/share/ansible/collections/ansible_collections/kubernetes/core
ENV ANSIBLE_CONFIG=/workspace/ansible/ansible.cfg \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/workspace/ansible:/workspace
WORKDIR /workspace/ansible
ENTRYPOINT ["python", "/opt/runner/run.py"]
