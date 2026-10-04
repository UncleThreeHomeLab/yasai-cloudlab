FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed

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
COPY run.py /opt/runner/run.py
ENV ANSIBLE_CONFIG=/workspace/ansible/ansible.cfg \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /workspace/ansible
ENTRYPOINT ["python", "/opt/runner/run.py"]
