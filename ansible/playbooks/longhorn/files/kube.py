"""Small kubectl interface shared by storage verification modules."""

import json
import subprocess
import time

KUBECTL = ['/usr/local/bin/k3s', 'kubectl', '--request-timeout=30s']
LH = 'longhorn-system'


def kubectl(*args, body=None):
    result = subprocess.run(KUBECTL + list(args), input=json.dumps(body) if body is not None else None,
                            text=True, capture_output=True, timeout=360)
    if result.returncode:
        # kubectl errors can contain endpoints and deployment identifiers.
        raise RuntimeError('Kubernetes operation failed: ' + args[0] + ' (details withheld)')
    return result.stdout


def get(kind, name=None, namespace=LH):
    args = ['get', kind] + ([name] if name else [])
    if namespace:
        args += ['-n', namespace]
    return json.loads(kubectl(*args, '-o', 'json'))


def wait(description, predicate, timeout=600):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            print(description + ': passed', flush=True)
            return value
        time.sleep(3)
    raise RuntimeError(description + ': timed out')


def create(kind, name, spec=None, namespace=LH, api='v1', **extra):
    metadata = {'name': name, 'labels': {'app.kubernetes.io/managed-by': 'cloudlab-verify'}}
    if namespace:
        metadata['namespace'] = namespace
    resource = dict(apiVersion=api, kind=kind, metadata=metadata, **extra)
    if spec is not None:
        resource['spec'] = spec
    kubectl('create', '-f', '-', body=resource)


def delete(kind, name, namespace=LH):
    args = ['delete', kind, name, '--ignore-not-found=true', '--wait=true', '--timeout=180s']
    if namespace:
        args += ['-n', namespace]
    kubectl(*args)
