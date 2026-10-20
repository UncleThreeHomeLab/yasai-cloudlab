FROM docker.io/library/golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS compiler
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOMAXPROCS=2

FROM compiler AS buildkit
WORKDIR /source
RUN curl -fsSL --retry 3 https://codeload.github.com/moby/buildkit/tar.gz/refs/tags/v0.34.0 -o /tmp/source.tgz \
    && echo 'b51e3a6bb7e0a0381adef47bffb8527817409f477fc5d26054517af29a11ff65  /tmp/source.tgz' | sha256sum -c - \
    && tar -xzf /tmp/source.tgz --strip-components=1
COPY tools/buildkit/go.mod tools/buildkit/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify \
    && go build -mod=readonly -trimpath -ldflags '-s -w -X github.com/moby/buildkit/version.Version=v0.34.0-cloudlab.1' -o /out/buildctl ./cmd/buildctl \
    && go build -mod=readonly -trimpath -tags 'osusergo netgo static_build seccomp' -ldflags '-s -w -X github.com/moby/buildkit/version.Version=v0.34.0-cloudlab.1' -o /out/buildkitd ./cmd/buildkitd

FROM compiler AS cosign
WORKDIR /source
RUN curl -fsSL --retry 3 https://codeload.github.com/sigstore/cosign/tar.gz/refs/tags/v3.1.3 -o /tmp/source.tgz \
    && echo 'ab8fcb8e0b4c0b8d01aefa37790cdd5ad099366b2efb8636b7a0250915b93362  /tmp/source.tgz' | sha256sum -c - \
    && tar -xzf /tmp/source.tgz --strip-components=1
COPY tools/cosign/go.mod tools/cosign/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify \
    && go build -mod=readonly -trimpath -ldflags '-s -w -X sigs.k8s.io/release-utils/version.gitVersion=v3.1.3-cloudlab.1' -o /out/cosign ./cmd/cosign

FROM compiler AS crane
WORKDIR /source
RUN curl -fsSL --retry 3 https://codeload.github.com/google/go-containerregistry/tar.gz/refs/tags/v0.22.1 -o /tmp/source.tgz \
    && echo 'a52cc7d61f8b2f043b7f0be1febecead5fceb791543c4790d699440f12d6b370  /tmp/source.tgz' | sha256sum -c - \
    && tar -xzf /tmp/source.tgz --strip-components=1
COPY tools/crane/go.mod tools/crane/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify \
    && go build -mod=readonly -trimpath -ldflags '-s -w -X github.com/google/go-containerregistry/cmd/crane/cmd.Version=v0.22.1-cloudlab.1' -o /out/crane ./cmd/crane

FROM compiler AS runc
COPY --from=cloudlab-bootstrap debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update && apt-get install -y --no-install-recommends libseccomp-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
RUN curl -fsSL --retry 3 https://codeload.github.com/opencontainers/runc/tar.gz/refs/tags/v1.5.2 -o /tmp/source.tgz \
    && echo 'b5af44864a830c7032cf4a72efa0c6d44f701873d9507b127be31ad4d1d42ff3  /tmp/source.tgz' | sha256sum -c - \
    && tar -xzf /tmp/source.tgz --strip-components=1
COPY tools/runc/go.mod tools/runc/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify \
    && CGO_ENABLED=1 go build -mod=readonly -trimpath -tags 'apparmor seccomp netgo cgo static_build osusergo' \
      -ldflags '-s -w -extldflags -static -X main.version=1.5.2-cloudlab.1' -o /out/buildkit-runc .

FROM compiler AS rootlesskit
WORKDIR /source
RUN curl -fsSL --retry 3 https://codeload.github.com/rootless-containers/rootlesskit/tar.gz/refs/tags/v3.2.0 -o /tmp/source.tgz \
    && echo '75e990eabaa699d86557bfab635b76e430fe91f37bbbb134bc70079e53c3f88d  /tmp/source.tgz' | sha256sum -c - \
    && tar -xzf /tmp/source.tgz --strip-components=1
COPY tools/rootlesskit/go.mod tools/rootlesskit/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify \
    && go build -mod=readonly -trimpath -ldflags '-s -w' -o /out/rootlesskit ./cmd/rootlesskit

FROM compiler AS arc
WORKDIR /source
RUN curl -fsSL --retry 3 https://codeload.github.com/actions/actions-runner-controller/tar.gz/refs/tags/gha-runner-scale-set-0.15.0 -o /tmp/source.tgz \
    && echo '8914e637dea6e2f2f0c2bee8261a86ca7fa8b59ac9decc2df2ba4a5514ba6aa3  /tmp/source.tgz' | sha256sum -c - \
    && tar -xzf /tmp/source.tgz --strip-components=1
COPY tools/arc/go.mod tools/arc/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify \
    && go test -mod=readonly ./apis/actions.github.com/v1alpha1 ./cmd/ghalistener/config \
    && go build -mod=readonly -trimpath -ldflags '-s -w -X github.com/actions/actions-runner-controller/build.Version=0.15.0 -X github.com/actions/actions-runner-controller/build.CommitSHA=1945b42820760eb50893c8da77fdfc42cf8dad45' -o /out/manager . \
    && go build -mod=readonly -trimpath -ldflags '-s -w -X github.com/actions/actions-runner-controller/build.Version=0.15.0 -X github.com/actions/actions-runner-controller/build.CommitSHA=1945b42820760eb50893c8da77fdfc42cf8dad45' -o /out/ghalistener ./cmd/ghalistener \
    && go build -mod=readonly -trimpath -ldflags '-s -w' -o /out/github-webhook-server ./cmd/githubwebhookserver \
    && go build -mod=readonly -trimpath -ldflags '-s -w' -o /out/actions-metrics-server ./cmd/actionsmetricsserver \
    && go build -mod=readonly -trimpath -ldflags '-s -w' -o /out/sleep ./cmd/sleep

FROM ghcr.io/actions/gha-runner-scale-set-controller:0.15.0@sha256:162dfb5bfbda9e7e49fbed67d428994c9ced55b41a37a18b75b46dab0aa98d37 AS controller
COPY --from=arc /out/manager /out/ghalistener /out/github-webhook-server /out/actions-metrics-server /out/sleep /
COPY --from=arc /source/LICENSE /usr/share/doc/cloudlab-arc/LICENSE

FROM scratch AS tools
COPY --from=buildkit /out/ /usr/local/bin/
COPY --from=cosign /out/cosign /usr/local/bin/cosign
COPY --from=crane /out/crane /usr/local/bin/crane
COPY --from=runc /out/buildkit-runc /usr/local/bin/buildkit-runc
COPY --from=rootlesskit /out/rootlesskit /usr/local/bin/rootlesskit
COPY --from=buildkit /source/LICENSE /usr/share/doc/buildkit/LICENSE
COPY --from=cosign /source/LICENSE /usr/share/doc/cosign/LICENSE
COPY --from=crane /source/LICENSE /usr/share/doc/crane/LICENSE
COPY --from=runc /source/LICENSE /usr/share/doc/runc/LICENSE
COPY --from=rootlesskit /source/LICENSE /usr/share/doc/rootlesskit/LICENSE

FROM docker.io/moby/buildkit:v0.34.0-rootless@sha256:65eca3c01cd1180c8f64565c4e3c5983af5145818b0e6fa863385d099eb73855 AS builder
USER root
ADD --checksum=sha256:42a1cb48e3ef0b5d1744f2b341120369d0c045038cdb6c9d5a6dd5ba7d421910 https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/libexpat-2.9.0-r0.apk /tmp/libexpat.apk
RUN apk add --no-network /tmp/libexpat.apk \
    && rm /tmp/libexpat.apk \
    && rm -f /usr/bin/buildkit-cni-bridge /usr/bin/buildkit-cni-firewall \
      /usr/bin/buildkit-cni-host-local /usr/bin/buildkit-cni-loopback
COPY --from=tools /usr/local/bin/buildctl /usr/local/bin/buildkitd /usr/local/bin/buildkit-runc /usr/local/bin/rootlesskit /usr/bin/
COPY --from=tools /usr/share/doc/ /usr/share/doc/
USER 1000:1000

FROM mcr.microsoft.com/dotnet/sdk:8.0.426-bookworm-slim@sha256:f7e28a0a3f6f9235929ec19274fd0ddf8534e9159f99fac602ac73304f1ce99f AS source
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
WORKDIR /source/runner
RUN curl -fsSL --retry 3 https://codeload.github.com/actions/runner/tar.gz/refs/tags/v2.338.0 -o /tmp/runner.tgz \
    && echo 'f9ad169b07995dad7964a4f9ce95673a153317a4888ba8d540ecead71def725a  /tmp/runner.tgz' | sha256sum -c - \
    && tar -xzf /tmp/runner.tgz --strip-components=1
COPY --chmod=0644 runner/runner.patch /tmp/runner.patch
RUN git apply --check /tmp/runner.patch && git apply /tmp/runner.patch
COPY --chmod=0644 runner/TrustedWorkflow.cs src/Runner.Worker/TrustedWorkflow.cs
COPY --chmod=0644 runner/TrustedTemplate.cs src/Runner.Worker/TrustedTemplate.cs
COPY --chmod=0644 runner/tests/Fixtures.cs src/Test/L0/Worker/CloudlabFixtures.cs
COPY --chmod=0644 runner/tests/TrustedWorkflowL0.cs src/Test/L0/Worker/CloudlabTrustedWorkflowL0.cs
COPY runner/nuget/ src/
# The upstream build records this deterministic derivative tree in BuildConstants.
RUN git init -q \
    && git config user.name 'Cloudlab build' \
    && git config user.email 'build@example.invalid' \
    && git add . \
    && git add -f src/Runner.Sdk/BuildConstants.cs \
    && GIT_AUTHOR_DATE='2000-01-01T00:00:00Z' GIT_COMMITTER_DATE='2000-01-01T00:00:00Z' git commit -qm 'Pinned runner source with reviewed local changes'
WORKDIR /source/runner/src
RUN dotnet msbuild dir.proj -t:GenerateConstant -p:RunnerVersion=2.338.0 -p:PackageRuntime=linux-x64
RUN dotnet restore Test/Test.csproj --runtime linux-x64 --locked-mode -p:RuntimeIdentifiers=linux-x64

FROM source AS test
RUN dotnet test Test/Test.csproj --configuration Release --runtime linux-x64 --no-restore \
    -p:Version=2.338.0 -p:RuntimeIdentifiers=linux-x64 \
    --filter 'FullyQualifiedName~TrustedWorkflow|FullyQualifiedName~JobRunnerL0' \
    --logger 'trx;LogFileName=cloudlab-gate.trx' --results-directory /test-results \
    && grep -Eq 'total="24".*passed="24"' /test-results/cloudlab-gate.trx

FROM source AS build
COPY --from=test /test-results/cloudlab-gate.trx /test-results/cloudlab-gate.trx
RUN dotnet msbuild dir.proj -t:Build -p:RunnerVersion=2.338.0 -p:BUILDCONFIG=Release \
    -p:PackageRuntime=linux-x64 -p:RuntimeIdentifiers=linux-x64 -p:RestoreLockedMode=true \
    && cp -a Misc/layoutbin/. ../_layout/bin/ \
    && cp -a Misc/layoutroot/. ../_layout/ \
    && test "$(../_layout/bin/Runner.Listener --version)" = '2.338.0' \
    && grep -q '"version": "8.0.32"' ../_layout/bin/Runner.Listener.runtimeconfig.json

FROM docker.io/aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222 AS trivy

FROM ghcr.io/actions/actions-runner:2.338.0@sha256:4ffadc0002b2581327e06101fc8c06cd189232baf79fe561fac9caeb76f5e807 AS runner
USER root
RUN rm -rf /home/runner/bin /home/runner/externals/node20 \
      /home/runner/externals/node24/lib/node_modules \
      /usr/local/lib/docker /usr/libexec/docker \
    && rm -f /home/runner/externals/node24/bin/npm /home/runner/externals/node24/bin/npx \
      /usr/bin/docker /usr/bin/dockerd /usr/bin/docker-proxy /usr/bin/containerd \
      /usr/bin/containerd-shim-runc-v2 /usr/bin/ctr /usr/bin/runc
COPY --from=build --chown=runner:runner /source/runner/_layout/ /home/runner/
COPY --from=build /source/runner/LICENSE /usr/share/doc/cloudlab-runner/LICENSE
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=tools /usr/local/bin/cosign /usr/local/bin/cosign
COPY --from=tools /usr/local/bin/buildctl /usr/local/bin/buildctl
COPY --from=tools /usr/local/bin/crane /usr/local/bin/crane
COPY --chmod=0444 runner/health.py /usr/local/libexec/cloudlab-ci-health.py
ENV FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true
USER runner
WORKDIR /home/runner
ENTRYPOINT ["/home/runner/run.sh"]
