"""Portable local preview review, publication and scoped setup commands."""
import argparse
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import sys
import time

from dotenv import dotenv_values
from playbooks.previews.files.contract import (SOURCE_PATH, MAX_LIFETIME, PRIVATE_MAX_LIFETIME, approval,
    catalog, repository, source, digest)

ROOT = Path(__file__).resolve().parents[4]


def read(filename):
    relative = Path(filename)
    target = (ROOT / relative).resolve()
    if relative.is_absolute() or ROOT / 'docs/local' not in target.parents or not target.is_file() or target.stat().st_size > 262144:
        raise ValueError('Private preview review inputs must remain under ignored docs/local')
    return json.loads(target.read_text())


def prepare(request):
    if set(request) != {'repository', 'pullRequest', 'image', 'platformRevision', 'lifetimeSeconds', 'private'}:
        raise ValueError('Preview preparation requires its exact repository, PR, image, platform and lifetime')
    if type(request['private']) is not bool or type(request['lifetimeSeconds']) is not int or not 60 <= request['lifetimeSeconds'] <= MAX_LIFETIME:
        raise ValueError('Preview review lifetime or source visibility is invalid')
    repository(request['repository'])
    if type(request['pullRequest']) is not int or request['pullRequest'] < 1 or not isinstance(request['platformRevision'], str) or not re.fullmatch('[a-f0-9]{40}', request['platformRevision']):
        raise ValueError('Preview review requires an exact PR number and platform revision')
    values = dotenv_values(ROOT / '.env', interpolate=False)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    from playbooks.previews.files.github import GitHub
    if request['private']:
        from playbooks.argocd.files.github_setup import repository as designated_repository
        from playbooks.argocd.files.repository_tokens import issue, revoke
        if (request['repository'] != designated_repository(values.get('PRIVATE_CONFIG_REPOSITORY')) or
                request['lifetimeSeconds'] > PRIVATE_MAX_LIFETIME):
            raise ValueError('Private preview review requires its designated repository and bounded lifetime')
        lease = issue(values, 'private-config', {'contents': 'read', 'pull_requests': 'read'})
        try:
            return prepare_source(request, GitHub(lease['token'], private=True,
                lease={key: item for key, item in lease.items() if key != 'token'}))
        finally:
            revoke(lease)
    return prepare_source(request, GitHub())


def prepare_source(request, api):
    pull = api.request('repos/' + request['repository'] + '/pulls/' + str(request['pullRequest']))
    now = int(time.time())
    row = {'instance': secrets.token_hex(16), 'repository': request['repository'],
        'repositoryId': pull['base']['repo']['id'], 'pullRequest': request['pullRequest'],
        'sourceSha': pull['head']['sha'], 'sourcePath': SOURCE_PATH,
        'image': request['image'], 'platformRevision': request['platformRevision'],
        'createdAt': now, 'expiresAt': now + request['lifetimeSeconds']}
    from playbooks.previews.files.contract import validate_pull
    validate_pull(row, pull)
    raw = api.blob(row)
    row.update(sourceDigest=digest(raw), definition=source(raw))
    approval(row)
    if not api.allows(row, now):
        raise ValueError('Private approval lifetime exceeds its discovery lease')
    api.verified(row)
    target = Path('/recovery/preview-approval-' + row['instance'] + '.json')
    with target.open('x') as stream:
        target.chmod(0o600)
        json.dump(row, stream, sort_keys=True, indent=2)
    return {'prepared': True, 'private_output': str(target), 'publication_required': True}


def playbook(name):
    result = subprocess.run(['ansible-playbook', '-i', 'inventory.yml', 'playbooks/previews/' + name], cwd=ROOT / 'ansible')
    if result.returncode:
        raise RuntimeError('Scoped preview operation failed')


def main(arguments=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'prepare', 'catalog-propose', 'bootstrap', 'verify', 'prove', 'credentials-retire'))
    parser.add_argument('input', nargs='?')
    args = parser.parse_args(arguments)
    if args.action == 'check':
        from playbooks.previews.files.check import run
        print(json.dumps(run(), sort_keys=True))
        return
    if args.action in ('prepare', 'catalog-propose'):
        if not args.input:
            raise ValueError('Preview review requires an ignored private input file')
        value = read(args.input)
        if args.action == 'prepare':
            result = prepare(value)
        else:
            if not isinstance(value, dict) or set(value) != {'catalog'}:
                raise ValueError('Preview publication requires one complete catalog')
            catalog(value['catalog'])
            from playbooks.argocd.files.github_setup import GitHub
            from playbooks.argocd.files.repository_tokens import issue, revoke
            from playbooks.argocd.files.private_publish import publish
            values = dotenv_values(ROOT / '.env', interpolate=False)
            os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
            lease = issue(values, 'private-config', {'contents': 'write', 'pull_requests': 'write'})
            try:
                result = publish(GitHub(lease['token']), values, {'previews/catalog.json': json.dumps(value, sort_keys=True, indent=2) + '\n'}, scope='previews')
            finally:
                revoke(lease)
        print(json.dumps(result, sort_keys=True))
        return
    if args.input:
        raise ValueError('Scoped preview setup does not accept ad-hoc input overrides')
    if args.action == 'credentials-retire':
        from playbooks.previews.files.credentials import main as retire_credentials
        retire_credentials('retire')
        return
    import yaml
    if not yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['previews']['enabled']:
        raise ValueError('Enable previews in the reviewed public root before scoped setup or proof')
    values = dotenv_values(ROOT / '.env', interpolate=False)
    for prefix in ('VM', 'VM2'):
        for suffix in ('_HOST', '_USER', '_PASSWORD'):
            if not values.get(prefix + suffix):
                raise ValueError('Scoped preview operation requires both VM credential sets')
        for suffix in ('_HOST', '_USER', '_PASSWORD', '_PORT', '_BECOME_PASSWORD'):
            os.environ[prefix + suffix] = values.get(prefix + suffix) or ('22' if suffix == '_PORT' else values[prefix + '_PASSWORD'] if suffix == '_BECOME_PASSWORD' else '')
    sequence = ('bootstrap',) if args.action == 'bootstrap' else ('verify',) if args.action == 'verify' else ('bootstrap', 'bootstrap', 'verify')
    for index, name in enumerate(sequence):
        playbook('010-bootstrap.yml' if name == 'bootstrap' else 'verify.yml')
        if args.action == 'prove' and index == 1:
            stats = json.loads(Path('/tmp/lab-stats.json').read_text())
            if set(stats) != {'cloudlab', 'cloudlab-worker'} or any(host['changed'] or host['failures'] or host['unreachable'] for host in stats.values()):
                raise RuntimeError('Scoped preview second apply was not unchanged on both nodes')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (ValueError, RuntimeError)) else
                         'Preview operation failed; private inputs and diagnostics withheld') from None
