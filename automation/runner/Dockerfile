FROM docker.io/grafana/k6:2.3.0@sha256:9c2dee7f8ed74d317e4027c06a10f169b625638189de8d4555d0b3486a5aeb34 AS k6

FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed AS provider-build
COPY debian.sources /etc/apt/sources.list.d/debian.sources
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
COPY cloudflare-provider.lock.json cloudflare-legacy.patch build_cloudflare.py /opt/provider-build/
RUN --mount=type=cache,target=/root/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build python /opt/provider-build/build_cloudflare.py

FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed

COPY --from=k6 /usr/bin/k6 /usr/local/bin/k6
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
COPY providers.tfrc /opt/runner/providers.tfrc
COPY run.py /opt/runner/run.py
ENV ANSIBLE_CONFIG=/workspace/ansible/ansible.cfg \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /workspace/ansible
ENTRYPOINT ["python", "/opt/runner/run.py"]
