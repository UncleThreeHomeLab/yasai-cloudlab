FROM --platform=linux/amd64 python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed AS dependencies
COPY apps/oidc-proof/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --index-url https://pypi.org/simple --require-hashes --only-binary=:all: --target /dependencies -r /tmp/requirements.txt

FROM --platform=linux/amd64 python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed AS runtime
COPY --from=dependencies /dependencies /dependencies
COPY apps/oidc-proof/server.py /app/server.py
COPY apps/oidc-proof/worker.py /app/worker.py
ENV PYTHONPATH=/dependencies PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080 8081
CMD ["python", "/app/server.py"]
