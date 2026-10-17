"""Restore missing native-root inputs only when every original checksum matches."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from playbooks.infrastructure.files.backend import environment
from playbooks.infrastructure.files.command import shared_identities

FILES = {'desired.tfvars.json', 'backend.json', 'encryption.json', 'credentials.env',
         'inventory.json', 'acceptance.json'}


def documents(binding, desired, plan, bundle):
    root = binding.get('root')
    if root not in ('cloudflare', 'github') or set(binding.get('inputs', {})) != FILES:
        raise ValueError('Complete protected native-root input hashes required')
    if root == 'github' and not bundle.get('token'):
        raise ValueError('Original scoped GitHub credential required')
    values = {'desired.tfvars.json': desired}
    for name, document in {
        'backend.json': {'project_id': bundle['backend']['PROJECT_ID']},
        'encryption.json': {'passphrase': bundle['encryption']['PASSPHRASE']},
        'inventory.json': shared_identities(plan),
        'acceptance.json': {'root': root, 'status': 'accepted'},
    }.items():
        values[name] = json.dumps(document, sort_keys=True).encode()
    if root == 'cloudflare':
        credentials = {'TF_HTTP_USERNAME': bundle['backend']['USERNAME'], 'TF_HTTP_PASSWORD': bundle['backend']['TOKEN'],
                       'CLOUDFLARE_API_TOKEN': bundle['management']['API_TOKEN'], 'TF_VAR_dns_api_token': bundle['dns']['API_TOKEN']}
    else:
        credentials = {'GITHUB_TOKEN': bundle['token'], 'TF_HTTP_USERNAME': bundle['backend']['USERNAME'],
                       'TF_HTTP_PASSWORD': bundle['backend']['TOKEN']}
    if any(not value or '\n' in value or '\r' in value for value in credentials.values()):
        raise ValueError('Recovery credentials contain unsupported values')
    values['credentials.env'] = ''.join(key + '=' + value + '\n' for key, value in credentials.items()).encode()
    if any(hashlib.sha256(raw).hexdigest() != binding['inputs'][name] for name, raw in values.items()):
        raise ValueError('Recovery inputs differ from protected original hashes; nothing restored')
    return values


def restore(destination, values):
    if set(values) != FILES or destination.is_symlink() or destination.resolve() != destination.absolute():
        raise ValueError('Recovery requires the exact private directory and complete inputs')
    if not destination.is_dir():
        raise ValueError('Mount the existing private Cloudflare input directory writable')
    for name, raw in values.items():
        path = destination / name
        if path.is_symlink() or (path.exists() and (not path.is_file() or path.read_bytes() != raw)):
            raise ValueError('Existing private input conflicts; no files overwritten')
    created = 0
    for name, raw in values.items():
        path = destination / name
        if path.exists():
            continue
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        created += 1
    return {'restored_files': created, 'original_hashes_verified': True, 'production_mutations': 0}


def main():
    os.umask(0o077)
    from playbooks.access.files.checkpoint import transaction
    from playbooks.access.files.external import accepted
    from playbooks.infrastructure.files.snapshot import credentials
    root = sys.argv[1] if len(sys.argv) == 2 else 'cloudflare'
    if root not in ('cloudflare', 'github') or len(sys.argv) > 2:
        raise ValueError('Select cloudflare or github input recovery')
    base = Path('/infra-work') / root
    with (base.parent / (root + '.lock')).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        binding = json.loads((base / 'plan-binding.json').read_text())
        plan = base / 'reviewed.tfplan'
        if hashlib.sha256(plan.read_bytes()).hexdigest() != binding.get('plan_hash'):
            raise ValueError('Protected recovery plan checksum mismatch')
        if root == 'cloudflare':
            bundle = credentials()
            with transaction() as receipts:
                accepted(receipts.load('external') or {})
        else:
            from dotenv import dotenv_values
            from playbooks.secrets.files.vault import fields
            values = dotenv_values('/workspace/.env', interpolate=False)
            os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
            bundle = {'token': sys.stdin.readline().strip(),
                      'backend': fields('gitlab-state-github', ('PROJECT_ID', 'USERNAME', 'TOKEN')),
                      'encryption': fields('opentofu-state-github', ('PASSPHRASE',))}
        # Local decoding needs no provider/backend credentials or network access.
        env = environment({'USERNAME': 'local-recovery', 'TOKEN': 'unused'},
                          'https://example.invalid', bundle['encryption']['PASSPHRASE'])
        result = subprocess.run(['tofu', 'show', '-json', str(plan)], cwd=base,
                                env=env, capture_output=True, timeout=90)
        if result.returncode:
            raise RuntimeError('Protected plan decoding failed; private diagnostics withheld')
        values = documents(binding, (base / 'desired.tfvars.json').read_bytes(), json.loads(result.stdout), bundle)
        print(json.dumps(restore(Path('/inputs') / root, values), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Private input recovery incomplete; originals and protected evidence retained') from None
