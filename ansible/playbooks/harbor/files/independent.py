"""Monthly Compose retrieval with only public source, B2 and the vault reader."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time

from dotenv import dotenv_values

from playbooks.secrets.files.vault import fields
from playbooks.data.files.remote import require_window
from playbooks.harbor.files import recovery
from playbooks.harbor.files.remote import Repository

MATERIAL = {
    'harbor-emergency': {'username': 'username', 'password': 'password'},
    'harbor-database': {'password': 'password', 'POSTGRES_PASSWORD': 'password'},
    'harbor-runtime': {name: name for name in ('secretKey', 'secret', 'CSRF_KEY', 'JOBSERVICE_SECRET',
                                              'REGISTRY_HTTP_SECRET', 'REGISTRY_PASSWD', 'REGISTRY_HTPASSWD')},
    'harbor-token-signing': {'tls.key': 'tls_key', 'tls.crt': 'tls_crt'},
    'harbor-browser-key': {'cookie_secret': 'cookie_secret'},
    'harbor-recovery-verifier': {'public_key': 'public_key'},
}


def verify_material(manifest):
    for item, mapping in MATERIAL.items():
        values = fields(item, tuple(set(mapping.values())))
        delivered = {key: base64.b64encode(values[field].encode()).decode() for key, field in mapping.items()}
        digest = hashlib.sha256(json.dumps(delivered, sort_keys=True).encode()).hexdigest()
        if digest != manifest['secrets'][item]:
            raise RuntimeError('Vault recovery material changed; map the recorded generation before recovery')
    if manifest.get('signatures'):
        from playbooks.harbor.files.signatures import public_key, SIGNER, VERIFIER
        private = fields(SIGNER, ('private_key',))['private_key']
        public = fields(VERIFIER, ('public_key',))['public_key']
        if (public_key(private) != public or
                hashlib.sha256(public.encode()).hexdigest() != manifest['signatures']['verifier_sha256']):
            raise RuntimeError('Independent signing recovery material differs from the recorded verifier')
    return len(MATERIAL)


def retrieve():
    require_window(reserve=3600)
    os.umask(0o077)
    values = dotenv_values('/workspace/.env', interpolate=False)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    with Path('/state/harbor-retrieve.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        policy = json.loads((recovery.ARTIFACTS.parent / 'storage/longhorn-backup/policy.json').read_text())
        target = fields(policy['item'], ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_ENDPOINTS', 'BUCKET', 'REGION'))
        target['AWS_ENDPOINT'] = target.pop('AWS_ENDPOINTS')
        repository = Repository(target)
        manifest = repository.latest()
        material = verify_material(manifest)
        result = {'independent_retrieval': True, 'cluster_used': False, 'harbor_used': False, 'arc_used': False,
                  'vault_inputs_verified': material, 'captured_at': manifest['captured_at'],
                  'retrieved_at': time.time(), 'source_revision': manifest['installation']['revision'],
                  **repository.read_blocks(manifest), 'network': repository.client.counters()}
        recovery.atomic(Path('/state/harbor-retrieval.json'), result)
        return result


if __name__ == '__main__':
    try:
        print(json.dumps(retrieve(), sort_keys=True))
    except Exception:
        raise SystemExit('Independent Harbor retrieval incomplete; private details withheld') from None
