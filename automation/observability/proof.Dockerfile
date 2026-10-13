FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed
COPY telemetry-requirements.txt /requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: -r /requirements.txt
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /workspace
