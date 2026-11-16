FROM --platform=linux/amd64 python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e AS dependencies
COPY apps/oidc-proof/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --index-url https://pypi.org/simple --require-hashes --only-binary=:all: --target /dependencies -r /tmp/requirements.txt

FROM --platform=linux/amd64 python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e AS runtime
RUN rm -rf /usr/local/lib/python3.13/site-packages/pip /usr/local/lib/python3.13/site-packages/pip-*.dist-info /usr/local/lib/python3.13/ensurepip \
    && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.13 \
    && test ! -e /usr/local/lib/python3.13/site-packages/pip \
    && test ! -e /usr/local/lib/python3.13/site-packages/pip-*.dist-info \
    && test ! -e /usr/local/lib/python3.13/ensurepip \
    && test ! -e /usr/local/bin/pip \
    && test ! -e /usr/local/bin/pip3 \
    && test ! -e /usr/local/bin/pip3.13 \
    && ! python -m pip --version
COPY --from=dependencies /dependencies /dependencies
COPY apps/oidc-proof/server.py /app/server.py
COPY apps/oidc-proof/worker.py /app/worker.py
ENV PYTHONPATH=/dependencies PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080 8081
CMD ["python", "/app/server.py"]
