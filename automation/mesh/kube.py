"""Captured Kubernetes I/O for mesh checks; never expose private diagnostics."""
import json
import subprocess
import time
try:
    from automation.gitops.source_revision import matches_revision
except ModuleNotFoundError:
    from source_revision import matches_revision  # Installed beside the standalone VM modules.


def kube(*args, document=None, timeout=180, allow_failure=False):
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--request-timeout=30s', *args],
                            input=json.dumps(document) if document is not None else None,
                            capture_output=True, text=True, timeout=timeout)
    if allow_failure:
        return result
    if result.returncode:
        raise RuntimeError('Mesh Kubernetes operation failed; diagnostics withheld')
    return result.stdout


def get(kind, name=None, namespace=None):
    raw = kube('get', kind, *([name] if name else []), *(['-n', namespace] if namespace else []),
               '--ignore-not-found', '--show-managed-fields=true', '-o', 'json')
    return json.loads(raw) if raw.strip() else None


def wait(predicate, label, timeout=600):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(5)
    raise RuntimeError('Mesh check timed out: ' + label)


def contains(actual, desired):
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(key in actual and contains(actual[key], value)
                                               for key, value in desired.items())
    if isinstance(desired, list):
        return isinstance(actual, list) and len(actual) == len(desired) and all(
            contains(a, d) for a, d in zip(actual, desired))
    return actual == desired


def condition(obj, name):
    return bool(obj) and any(c.get('type') == name and c.get('status') == 'True'
                             and c.get('observedGeneration', obj['metadata'].get('generation'))
                             == obj['metadata'].get('generation')
                             for c in obj.get('status', {}).get('conditions', []))


def application_ready(name, revision):
    obj = get('application.argoproj.io', name, 'argocd') or {}
    status = obj.get('status', {})
    return (status.get('sync', {}).get('status') == 'Synced'
            and matches_revision(obj, revision)
            and status.get('health', {}).get('status') == 'Healthy'
            and not obj.get('operation')
            and status.get('operationState', {}).get('phase') in (None, 'Succeeded')
            and not any(c['type'].endswith('Error') for c in status.get('conditions', [])))
