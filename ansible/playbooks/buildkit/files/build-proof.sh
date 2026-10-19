#!/bin/sh
set -eu
test "$(id -u)" = 1000
awk '$1 == 0 && $2 != 0 && $3 == 65536 { ok=1 } END { exit !ok }' /proc/self/uid_map
grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status
grep -Eq '^CapBnd:[[:space:]]+0*c0$' /proc/self/status
grep -qx 'cloudlab-buildkit (enforce)' /proc/self/attr/current
test ! -S /var/run/docker.sock
test ! -S /run/containerd/containerd.sock
test ! -e /var/lib/rancher/k3s

"$@" &
daemon=$!
trap 'kill "$daemon" 2>/dev/null || true; wait "$daemon" 2>/dev/null || true' EXIT
trap 'exit 143' TERM INT
attempt=0
until buildctl --addr unix:///run/user/1000/buildkit/buildkitd.sock debug workers -v > /tmp/workers; do
  kill -0 "$daemon"
  attempt=$((attempt + 1))
  test "$attempt" -lt 60
  sleep 1
done
grep -Eq 'org.mobyproject.buildkit.worker.oci.process-mode:[[:space:]]+sandbox$' /tmp/workers
buildctl --addr tcp://127.0.0.1:1234 debug workers -v > /tmp/tcp-workers
grep -Eq 'org.mobyproject.buildkit.worker.oci.process-mode:[[:space:]]+sandbox$' /tmp/tcp-workers
mkdir -p /workspace/context
cat > /workspace/context/Dockerfile <<'DOCKERFILE'
FROM docker.io/library/python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed
RUN python - <<'PY'
import ctypes
import errno
import os
assert os.getuid() == 0
assert os.path.basename(os.readlink('/proc/1/exe')) in ('dash', 'python3.13')
libc = ctypes.CDLL(None, use_errno=True)
assert libc.syscall(250, 1, ctypes.c_char_p(b'cloudlab-proof-denied')) == -1
assert ctypes.get_errno() in (errno.EPERM, errno.ENOSYS)
open('/proof.bin', 'wb').write(os.urandom(8 * 1024 * 1024))
os.chown('/proof.bin', 65534, 65534)
PY
DOCKERFILE
buildctl --addr unix:///run/user/1000/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 --local context=/workspace/context --local dockerfile=/workspace/context \
  --output type=oci,dest=/workspace/proof.tar,compression=uncompressed
test "$(wc -c < /workspace/proof.tar)" -gt 8388608
echo CLOUDLAB_ROOTLESS_BUILD_OK
