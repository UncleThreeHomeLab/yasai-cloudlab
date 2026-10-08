"""Validate stored Helm retention before authorizing the server-side handoff."""
from contextlib import redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import sys
import yaml

sys.path[:0] = [str(Path(__file__).resolve().parents[2]), str(Path(__file__).resolve().parents[1] / 'tailscale')]
from verify_access import ssh
from automation.connectivity.checkpoint import transaction
from automation.connectivity.preflight import audit


def definitions():
    root = Path(__file__).resolve().parents[2] / 'platform/connectivity/gateway-api'
    artifact = (root / 'upstream.yaml').read_bytes()
    if hashlib.sha256(artifact).hexdigest() != json.loads((root / 'artifact.lock.json').read_text())['sha256']:
        raise RuntimeError('Gateway API artifact checksum mismatch')
    return [x for x in yaml.safe_load_all(artifact) if x and x.get('kind') == 'CustomResourceDefinition']


def retention(manifest, expected):
    objects = [x for x in yaml.safe_load_all(manifest) if x]
    found = {x['metadata']['name']: x for x in objects
             if x.get('kind') == 'CustomResourceDefinition' and x['spec'].get('group') == 'gateway.networking.k8s.io'}
    if set(found) != {x['metadata']['name'] for x in expected}:
        raise RuntimeError('Stored Helm release has an unexpected Gateway API inventory')
    if any(x['metadata'].get('annotations', {}).get('helm.sh/resource-policy') != 'keep' for x in found.values()):
        raise RuntimeError('Stored Helm release would delete a required Gateway API CRD')


def remote(action, payload=None):
    return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 /var/lib/cloudlab/connectivity/legacy.py',
        input=json.dumps(dict(payload or {}, action=action)), timeout=1500 if action in ('finish', 'accept') else 180))


def prepare(payload):
    if not remote('status')['state']:
        from automation.connectivity.verify import run as verify_access
        # Keep the CLI's stdout a single JSON result for Ansible changed_when.
        with redirect_stdout(sys.stderr):
            verify_access(failures=False)
    with transaction():
        # Serialize acceptance/provider changes with the destructive cutover gate.
        state = remote('status')['state']
        if not state:
            if not audit()['ready']:
                raise RuntimeError('Legacy removal prerequisites are not healthy')
            release = remote('release')
            retention(release['manifest'], payload['gateway_api'])
            payload = dict(payload, release_uid=release['uid'],
                           release_hash=hashlib.sha256(release['manifest'].encode()).hexdigest())
        return remote('prepare', payload)


if __name__ == '__main__':
    try:
        payload = json.load(sys.stdin)
        payload['gateway_api'] = definitions()
        action = payload.pop('action', 'prepare')
        if action in ('finish', 'accept'):
            with transaction():
                result = remote(action, payload)
        elif action == 'prepare':
            result = prepare(payload)
        else:
            raise ValueError('Invalid cutover stage')
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Legacy removal gate failed; no removal authorized.') from None
