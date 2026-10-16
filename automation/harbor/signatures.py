"""Local recovery signer; only its separate public verifier is delivered to the lab."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from automation.credentials.provision import command, ensure_items

SIGNER = 'harbor-recovery-signer'
VERIFIER = 'harbor-recovery-verifier'


def private_key():
    return ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def public_key(value):
    key = serialization.load_pem_private_key(value.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError('Recovery signing requires the retained P-256 private key')
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def durable(token, title, field, kind):
    rows = [item for item in command(['item', 'list', '--vault', 'CloudLab'], token) if item.get('title') == title]
    if len(rows) != 1:
        raise ValueError('Recovery signing input missing or ambiguous')
    document = command(['item', 'get', rows[0]['id'], '--vault', 'CloudLab'], token)
    fields = [row for row in document.get('fields', []) if row.get('label') == field]
    if len(fields) != 1 or fields[0].get('type') != kind or not fields[0].get('value'):
        raise ValueError('Recovery signing field incompatible; existing values preserved')
    return fields[0]['value']


def provision(token):
    # Two items prevent an extract-only ESO provider from delivering the private key.
    result = ensure_items(token, {SIGNER: {'private_key': ('CONCEALED', private_key)}})
    private = durable(token, SIGNER, 'private_key', 'CONCEALED')
    public = public_key(private)
    verifier = ensure_items(token, {VERIFIER: {'public_key': ('STRING', lambda: public)}})
    if durable(token, VERIFIER, 'public_key', 'STRING') != public:
        raise ValueError('Recovery verifier differs from the original signer; replacement refused')
    return {'created': result['created'] + verifier['created'],
            'preserved': result['preserved'] + verifier['preserved'], 'private_key_delivered': False}


class Cosign:
    def __init__(self, registry):
        self.registry = registry

    def command(self, *arguments, password=None, required=True):
        environment = {key: value for key, value in self.registry.environment.items()
                       if key in ('PATH', 'HOME', 'HTTPS_PROXY', 'NO_PROXY', 'DOCKER_CONFIG')}
        if password is not None:
            environment['COSIGN_PASSWORD'] = password
        result = subprocess.run(['cosign', *arguments], env=environment, input=b'',
                                capture_output=True, timeout=180)
        if required and result.returncode:
            raise RuntimeError('Native recovery signature operation failed; private output withheld')
        return result.returncode == 0

    @contextmanager
    def key(self, private, public):
        if public_key(private) != public:
            raise ValueError('Recovery signer and verifier do not match')
        with tempfile.TemporaryDirectory(prefix='harbor-recovery-signing-', dir='/dev/shm') as temporary:
            directory = Path(temporary)
            pem, verifier, prefix = directory / 'private.pem', directory / 'public.pem', directory / 'imported'
            for path, value in ((pem, private), (verifier, public)):
                path.write_text(value)
                path.chmod(0o600)
            password = secrets.token_urlsafe(48)
            self.command('import-key-pair', '--key', str(pem), '--output-key-prefix', str(prefix), password=password)
            pem.unlink()
            yield prefix.with_suffix('.key'), verifier, password

    def verify(self, reference, verifier, *, required=True):
        if not re.fullmatch(re.escape(self.registry.host) +
                            r'/(cloudlab-public|cloudlab-private)/bootstrap@sha256:[a-f0-9]{64}', reference):
            raise ValueError('Recovery signatures require an exact designated image digest')
        return self.command('verify', '--insecure-ignore-tlog=true', '--max-workers=2',
                            '--check-claims=true', '--key', str(verifier), reference,
                            required=required)

    def sign(self, reference, key, verifier, password):
        if not self.verify(reference, verifier, required=False):
            self.command('sign', '--yes', '--use-signing-config=false', '--tlog-upload=false',
                         '--key', str(key), reference, password=password)
        self.verify(reference, verifier)


def prove(client):
    from automation.credentials.vault import fields
    from automation.harbor import api, artifacts, api_policy
    from automation.harbor.recovery import atomic
    from automation.harbor.registry import Registry
    from automation.connectivity.preflight import ssh
    if client.plan(verify=True)['changes'] != 0:
        raise ValueError('Accept the unchanged native Harbor root before signing recovery artifacts')
    images = artifacts.receipt(client.path / 'artifacts/receipt.json')
    if not images.get('verified_at') or set(images['projects']) != set(api_policy.POLICY['projects']) or any(
            set(row.get('rollback', {})) != set(artifacts.ROLLBACK_TAGS) for row in images['projects'].values()):
        raise ValueError('Complete independent deployment and rollback artifacts before signing')
    private = fields(SIGNER, ('private_key',))['private_key']
    public = fields(VERIFIER, ('public_key',))['public_key']
    if public_key(private) != public:
        raise ValueError('Recovery signer and delivered verifier differ; replacement refused')
    proof = {'format': 1, 'verifier_sha256': hashlib.sha256(public.encode()).hexdigest(),
             'image': json.loads((api.ROOT / 'platform/harbor/cosign.lock.json').read_text())['image'],
             'projects': {project: sorted([row['digest'], *[entry['digest'] for entry in row['rollback'].values()]])
                          for project, row in images['projects'].items()}}
    directory = client.path / 'signatures'
    directory.mkdir(mode=0o700, exist_ok=True)
    journal = directory / 'receipt.json'
    if journal.exists() and json.loads(journal.read_text()) != proof:
        raise ValueError('Original signature inputs changed; preserve the recorded signer and artifact set')
    atomic(journal, proof)
    registry = Registry(client.private['host'], client.env, directory / 'diagnostics.txt')
    signer = Cosign(registry)
    with signer.key(private, public) as (key, verifier, password), \
            tempfile.TemporaryDirectory(prefix='harbor-wrong-verifier-', dir='/dev/shm') as temporary:
        wrong = Path(temporary) / 'public.pem'
        wrong.write_text(public_key(private_key()))
        for project, digests in proof['projects'].items():
            with registry.identity(client.private['robots'][project + '-push']):
                for digest in digests:
                    reference = registry.reference(project, digest)
                    if registry.digest(reference) != digest:
                        raise RuntimeError('Original image differs from its protected digest receipt')
                    signer.sign(reference, key, verifier, password)
                reference = registry.reference(project, digests[0])
                if signer.verify(reference, wrong, required=False):
                    raise RuntimeError('Registry signature accepted another recovery signer')
                signer.verify(reference, verifier)
    delivered = json.loads(ssh('VM', client.values['VM_HOST'],
        'python3 /opt/cloudlab/automation/harbor/recovery.py record-signatures', input=json.dumps(proof), timeout=120))
    if delivered != {'signature_digests_recorded': sum(map(len, proof['projects'].values())), 'private_key_received': False}:
        raise RuntimeError('Remote signature evidence differs; original local journal retained')
    return {**delivered, 'native_signatures_verified': 12, 'wrong_recovery_key_rejected': True,
            'project_scoped_push_robots': True, 'public_transparency_upload': False}


def main():
    import argparse
    import fcntl
    from dotenv import dotenv_values
    from automation.harbor import api
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('provision', 'prove'))
    action = parser.parse_args().action
    os.umask(0o077)
    api.binding()
    api.WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (api.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if action == 'provision':
            values = dotenv_values(api.ROOT / '.env', interpolate=False)
            result = provision(values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'))
        else:
            client = api.Client()
            with client.connected():
                result = prove(client)
        print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Recovery signature operation incomplete; original keys, journals and artifacts retained') from None
