"""Private Kubernetes I/O for the certificate owner; never return raw errors."""
import json
import re
from pathlib import Path
import subprocess
import time

BASE = Path('/var/lib/cloudlab/certificates')


def kube(*args, document=None, timeout=180):
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--request-timeout=30s', *args],
                            input=json.dumps(document) if document is not None else None,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Certificate Kubernetes operation failed; diagnostics withheld')
    return result.stdout


def get(kind, name, namespace=None):
    raw = kube('get', kind, name, *(['-n', namespace] if namespace else []), '--ignore-not-found', '--show-managed-fields=true', '-o', 'json')
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
    if not obj or obj.get('metadata', {}).get('deletionTimestamp'):
        return False
    generation = obj.get('metadata', {}).get('generation')
    strict = obj.get('kind') in ('Certificate', 'Issuer', 'ClusterIssuer')
    conditions = obj.get('status', {}).get('conditions', [])
    if strict and (generation is None or any(condition.get('type') == 'Issuing'
            and condition.get('status') == 'True' and condition.get('observedGeneration') == generation
            for condition in conditions)):
        return False
    return any(condition.get('type') == 'Ready' and condition.get('status') == 'True'
        and condition.get('observedGeneration', None if strict else generation) == generation for condition in conditions)



def application_ready(name, revision, private_revision=None):
    obj = get('application.argoproj.io', name, 'argocd') or {}
    status = obj.get('status', {})
    sources = obj.get('spec', {}).get('sources')
    revisions_match = (status.get('sync', {}).get('revisions') == [revision, private_revision]
        and len(sources) == 2 and sources[0].get('targetRevision') == revision
        and sources[1].get('targetRevision') == 'main'
        and isinstance(revision, str) and re.fullmatch('[a-f0-9]{40}', revision)
        and isinstance(private_revision, str) and re.fullmatch('[a-f0-9]{40}', private_revision)
        and not obj.get('spec', {}).get('source')) if sources else status.get('sync', {}).get('revision') == revision
    return (status.get('sync', {}).get('status') == 'Synced'
            and revisions_match
            and str(obj.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/skip-reconcile', '')).lower() != 'true'
            and status.get('health', {}).get('status') == 'Healthy'
            and not obj.get('operation')
            and status.get('operationState', {}).get('phase') in (None, 'Succeeded')
            and not any(c['type'].endswith('Error') for c in status.get('conditions', [])))

def certificate(name, namespace):
    obj = wait(lambda: (current if ready(current := get('certificate.cert-manager.io', name, namespace)) else None),
               'certificate issuance')
    secret = get('secret', obj['spec']['secretName'], namespace)
    if not secret or secret.get('type') != 'kubernetes.io/tls' or not {'tls.crt', 'tls.key'} <= secret.get('data', {}).keys():
        raise RuntimeError('Issued certificate Secret is incomplete')
    if secret['metadata'].get('annotations', {}).get('cert-manager.io/certificate-name') != name:
        raise RuntimeError('Certificate Secret lacks its controller association')
    return {'certificate_uid': obj['metadata']['uid'], 'secret_uid': secret['metadata']['uid']}
