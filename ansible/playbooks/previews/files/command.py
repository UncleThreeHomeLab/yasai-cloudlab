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


def verified_row(request, api, *, instance, created_at, verification_time):
    """Build an immutable approval without artifact, clock or randomness side effects."""
    if (not isinstance(instance, str) or not re.fullmatch('[a-f0-9]{32}', instance) or
            type(created_at) is not int or type(verification_time) is not int or
            not 0 < created_at <= verification_time or
            not created_at <= verification_time < created_at + request['lifetimeSeconds']):
        raise ValueError('Preview preparation requires its original identity and current verification time')
    pull = api.request('repos/' + request['repository'] + '/pulls/' + str(request['pullRequest']))
    row = {'instance': instance, 'repository': request['repository'],
        'repositoryId': pull['base']['repo']['id'], 'pullRequest': request['pullRequest'],
        'sourceSha': pull['head']['sha'], 'sourcePath': SOURCE_PATH,
        'image': request['image'], 'platformRevision': request['platformRevision'],
        'createdAt': created_at, 'expiresAt': created_at + request['lifetimeSeconds']}
    from playbooks.previews.files.contract import validate_pull
    validate_pull(row, pull)
    raw = api.blob(row)
    row.update(sourceDigest=digest(raw), definition=source(raw))
    approval(row)
    if not api.allows(row, verification_time):
        raise ValueError('Private approval lifetime exceeds its discovery lease')
    return row


def prepare_source(request, api):
    now = int(time.time())
    row = verified_row(request, api, instance=secrets.token_hex(16), created_at=now, verification_time=now)
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


def published():
    from playbooks.argocd.files.render import committed_payload
    committed_payload()


def vm_environment(values):
    for prefix in ('VM', 'VM2'):
        for suffix in ('_HOST', '_USER', '_PASSWORD'):
            if not values.get(prefix + suffix):
                raise ValueError('Scoped preview operation requires both VM credential sets')
        for suffix in ('_HOST', '_USER', '_PASSWORD', '_PORT', '_BECOME_PASSWORD'):
            os.environ[prefix + suffix] = values.get(prefix + suffix) or ('22' if suffix == '_PORT' else values[prefix + '_PASSWORD'] if suffix == '_BECOME_PASSWORD' else '')


def main(arguments=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'prepare', 'catalog-propose', 'dns', 'withdraw', 'bootstrap', 'verify', 'prove', 'credentials-retire'))
    parser.add_argument('input', nargs='?')
    args = parser.parse_args(arguments)
    if args.action == 'check':
        from playbooks.previews.files.check import run
        print(json.dumps(run(), sort_keys=True))
        return
    if args.action in ('prepare', 'catalog-propose'):
        if not args.input:
            raise ValueError('Preview review requires an ignored private input file')
        published()
        value = read(args.input)
        if args.action == 'prepare':
            result = prepare(value)
        else:
            if (not isinstance(value, dict) or set(value) != {'catalog', 'expectedBase'} or
                    not isinstance(value['expectedBase'], str) or not re.fullmatch('[a-f0-9]{40}', value['expectedBase'])):
                raise ValueError('Preview publication requires a complete catalog and inspected expectedBase')
            catalog(value['catalog'])
            from playbooks.argocd.files.github_setup import GitHub
            from playbooks.argocd.files.repository_tokens import issue, revoke
            from playbooks.argocd.files.private_publish import publish
            values = dotenv_values(ROOT / '.env', interpolate=False)
            os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
            lease = issue(values, 'private-config', {'contents': 'write', 'pull_requests': 'write'})
            try:
                result = publish(GitHub(lease['token']), values, {'previews/catalog.json': json.dumps(
                    {'catalog': value['catalog']}, sort_keys=True, indent=2) + '\n'}, scope='previews', expected_base=value['expectedBase'])
            finally:
                revoke(lease)
        print(json.dumps(result, sort_keys=True))
        return
    if args.action == 'withdraw':
        if not args.input:
            raise ValueError('Withdrawal requires its ignored journaled request')
        request = read(args.input)
        vm_environment(dotenv_values(ROOT / '.env', interpolate=False))
        os.environ['CLOUDLAB_PREVIEW_WITHDRAW_REQUEST'] = json.dumps(request)
        playbook('withdraw.yml')
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
    if args.action == 'dns':
        published()
        for key, value in values.items():
            if value is not None:
                os.environ[key] = value
        from playbooks.services.files.inputs import private_dns_names
        private_names = json.loads(values.get('PRIVATE_ACCESS_HOSTS') or '[]')
        os.environ['PRIVATE_ACCESS_HOSTS'] = json.dumps(sorted(set(private_names + private_dns_names())))
        from playbooks.keycloak.files.access_inputs import runtime
        runtime(os.environ, yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text()))
    vm_environment(values)
    if args.action == 'dns':
        playbook('../access/preview-dns.yml')
        return
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
