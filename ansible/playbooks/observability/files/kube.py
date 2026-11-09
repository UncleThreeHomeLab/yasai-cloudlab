"""Private Kubernetes I/O for observability verify; never expose diagnostics."""
import json
import subprocess
import time
from pathlib import Path

BASE = Path('/var/lib/cloudlab/observability')


def kube(*a, timeout=180):
    r = subprocess.run(
        ['/usr/local/bin/k3s', 'kubectl', '--request-timeout=30s', *a],
        capture_output=True, text=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError('Observability Kubernetes operation failed; diagnostics withheld')
    return r.stdout


def get(kind, name, ns=None):
    raw = kube('get', kind, name, *(['-n', ns] if ns else []),
               '--ignore-not-found', '-o', 'json')
    return json.loads(raw) if raw.strip() else None


def wait(p, label, timeout=600):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if p():
            return True
        time.sleep(5)
    raise RuntimeError('Observability check timed out: ' + label)


def contains(a, d):
    if isinstance(d, dict):
        return isinstance(a, dict) and all(k in a and contains(a[k], v) for k, v in d.items())
    return a == d
