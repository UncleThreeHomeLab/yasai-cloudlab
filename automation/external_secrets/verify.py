"""Check fresh vault authentication and disposable ESO reconciliation without logging secrets."""

import base64
import json
import subprocess
import sys
import time
import uuid

NAMESPACE = 'external-secrets'
API = 'external-secrets.io/v1'


def kubectl(*args, body=None):
    result = subprocess.run(
        ['/usr/local/bin/k3s', 'kubectl', '--request-timeout=30s', '-n', NAMESPACE, *args],
        input=json.dumps(body) if body is not None else None, text=True,
        capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError('Kubernetes operation failed (details withheld)')
    return json.loads(result.stdout) if result.stdout.strip().startswith('{') else None


def resource(kind, name, spec):
    return dict(apiVersion=API, kind=kind,
                metadata=dict(name=name, namespace=NAMESPACE), spec=spec)


def wait(predicate):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(3)
    raise RuntimeError('External Secrets verification timed out')


def ready(kind, name):
    value = kubectl('get', kind, name, '-o', 'json')
    return any(c['type'] == 'Ready' and c['status'] == 'True'
               for c in value.get('status', {}).get('conditions', []))


def main(store_name):
    name = 'cloudlab-verify-' + uuid.uuid4().hex[:12]
    vault_name = name + '-vault'
    try:
        store = kubectl('get', 'clustersecretstore', store_name, '-o', 'json')
        wait(lambda: ready('clustersecretstore', store_name))
        # A new store forces a new SDK client and real vault lookup, bypassing cached readiness.
        provider = store['spec']['provider']
        provider['onepasswordSDK']['auth']['serviceAccountSecretRef'].pop('namespace', None)
        kubectl('create', '-f', '-', body=resource('SecretStore', vault_name, dict(provider=provider)))
        wait(lambda: ready('secretstore', vault_name))

        # No write permission or manually created 1Password test item is required.
        fake = resource('SecretStore', name, dict(provider=dict(fake=dict(data=[
            dict(key='probe', value='first')]))))
        kubectl('create', '-f', '-', body=fake)
        secret = resource('ExternalSecret', name, dict(
            refreshInterval='5s', secretStoreRef=dict(name=name, kind='SecretStore'),
            target=dict(name=name, creationPolicy='Owner'),
            data=[dict(secretKey='probe', remoteRef=dict(key='probe'))]))
        kubectl('create', '-f', '-', body=secret)

        def has_value(expected):
            value = kubectl('get', 'secret', name, '--ignore-not-found', '-o', 'json')
            return value is not None and value.get('data', {}).get('probe') == base64.b64encode(expected.encode()).decode()

        wait(lambda: has_value('first'))
        kubectl('patch', 'secretstore', name, '--type=merge', '-p', json.dumps(dict(
            spec=dict(provider=dict(fake=dict(data=[dict(key='probe', value='second')]))))))
        wait(lambda: has_value('second'))
        kubectl('patch', 'secret', name, '--type=merge', '-p', json.dumps(dict(
            data=dict(probe=base64.b64encode(b'drift').decode()))))
        wait(lambda: has_value('second'))
        print('Fresh CloudLab authentication, Secret creation, refresh, and drift repair passed.')
    finally:
        # Explicitly remove both owned and source resources even after partial failure.
        for kind, target in [('externalsecret', name), ('secret', name),
                             ('secretstore', name), ('secretstore', vault_name)]:
            kubectl('delete', kind, target, '--ignore-not-found', '--wait=true', '--timeout=60s')


if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except Exception:
        print('External Secrets proof failed; details withheld to protect credentials.', file=sys.stderr)
        sys.exit(1)
