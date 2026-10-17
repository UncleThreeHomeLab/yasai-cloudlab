"""Private Kubernetes I/O for the certificate owner; never return raw errors."""
import json
import subprocess
import time


def kube(*args, document=None, timeout=180):
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--request-timeout=30s', *args],
                            input=json.dumps(document) if document is not None else None,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Certificate Kubernetes operation failed; diagnostics withheld')
    return result.stdout


def get(kind, name, namespace=None):
    raw = kube('get', kind, name, *(['-n', namespace] if namespace else []), '--ignore-not-found', '-o', 'json')
    return json.loads(raw) if raw.strip() else None


def wait(predicate, label, timeout=900):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(5)
    raise RuntimeError('Certificate check timed out: ' + label)


def contains(actual, desired):
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(key in actual and contains(actual[key], value)
                                               for key, value in desired.items())
    return actual == desired


def ready(obj):
    return bool(obj) and any(condition.get('type') == 'Ready' and condition.get('status') == 'True'
                             and condition.get('observedGeneration', obj['metadata'].get('generation'))
                             == obj['metadata'].get('generation')
                             for condition in obj.get('status', {}).get('conditions', []))


def application_ready(name, revision):
    obj = get('application.argoproj.io', name, 'argocd') or {}
    status = obj.get('status', {})
    return (status.get('sync', {}).get('status') == 'Synced'
            and status.get('sync', {}).get('revision') == revision
            and status.get('health', {}).get('status') == 'Healthy'
            and not obj.get('operation')
            and status.get('operationState', {}).get('phase') in (None, 'Succeeded')
            and not any(c['type'].endswith('Error') for c in status.get('conditions', [])))
