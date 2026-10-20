"""Local native ownership of read-only workflow defaults on the two GitOps repositories."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from types import SimpleNamespace

from playbooks.argocd.files.github_setup import configuration, inputs
from playbooks.ci.files.chart import ROOT
from playbooks.harbor.files.recovery import atomic
from playbooks.infrastructure.files import harbor as source
from playbooks.infrastructure.files.backend import environment
from playbooks.infrastructure.files.native import document_plan, native, require
from playbooks.infrastructure.files.retention import ciphertext, maintain, request
from playbooks.secrets.files.vault import fields

BASE = ROOT / 'infra/github-workflows'
ROLES = {'public_platform': 'public-platform', 'private_config': 'private-config'}


def copy_source(directory):
    files = {name: BASE / name for name in ('main.tf', 'variables.tf', 'policy.json')}
    files.update({name: ROOT / 'infra/github' / name for name in ('versions.tf', '.terraform.lock.hcl')})
    allowed = set(files) | {'imports.tf.json', 'desired.tfvars.json'}
    for pattern in ('*.tf', '*.tf.json', '*.tfvars*'):
        if any(path.name not in allowed or path.is_symlink() for path in directory.glob(pattern)):
            raise ValueError('Unexpected workflow declarations; existing inputs retained')
    for name, path in files.items():
        if (directory / name).is_symlink():
            raise ValueError('Workflow work files cannot redirect outside their protected directory')
        shutil.copy2(path, directory / name)


def repositories(api, values):
    targets = {role: (name, private) for role, name, private in configuration(values)}
    result, observed = {}, {}
    for key, role in ROLES.items():
        name, private = targets[role]
        current = api.request('GET', 'repos/' + name)
        if (current.get('full_name') != name or current.get('private') is not private or
                current.get('fork') or current.get('archived') or type(current.get('id')) is not int or
                current['id'] <= 0 or not current.get('node_id')):
            raise ValueError('GitOps repository identity differs; no workflow permission changed')
        policy = api.request('GET', 'repos/' + name + '/actions/permissions/workflow')
        if (set(policy) != {'default_workflow_permissions', 'can_approve_pull_request_reviews'} or
                policy['default_workflow_permissions'] not in ('read', 'write') or
                type(policy['can_approve_pull_request_reviews']) is not bool):
            raise ValueError('Unsupported workflow policy fields; ownership refused')
        result[key] = {'name': current['name'], 'id': current['id'], 'node_id': current['node_id']}
        observed[key] = policy
    owner, = {name.split('/')[0] for name, _ in targets.values()}
    return {'owner': owner, 'repositories': result}, observed


def identities(desired):
    return {key: {field: repository[field] for field in ('id', 'node_id')}
            for key, repository in desired['repositories'].items()}


def expected_resources(desired):
    return {'github_workflow_repository_permissions.release[' + json.dumps(key) + ']': (key, repository)
            for key, repository in desired['repositories'].items()}


def occupied(document, desired):
    values = document.get('values', {})
    root = values.get('root_module', {})
    rows = root.get('resources', [])
    if root.get('child_modules') or not rows and values.get('outputs'):
        raise ValueError('Workflow state contains unexpected or missing managed resources')
    if not rows:
        return False
    expected = expected_resources(desired)
    if (len(rows) != 2 or {row['address'] for row in rows} != set(expected) or
            values.get('outputs', {}).get('repository_identities', {}).get('value') != identities(desired)):
        raise ValueError('Workflow state differs from its original immutable repository identities')
    for row in rows:
        _, repository = expected[row['address']]
        if (row.get('type') != 'github_workflow_repository_permissions' or
                row.get('values', {}).get('id') != repository['name'] or
                row['values'].get('repository') != repository['name']):
            raise ValueError('Workflow state contains a foreign resource; no live refresh permitted')
    return True


def guard(document, desired, permissions, *, importing=False):
    expected = expected_resources(desired)
    rows = document.get('resource_changes', [])
    if len(rows) != len(expected) or {row['address'] for row in rows} != set(expected):
        raise ValueError('Workflow plan exceeds the two approved repository resources')
    for row in rows:
        key, repository = expected[row['address']]
        change = row['change']
        after = change.get('after') or {}
        if (row.get('type') != 'github_workflow_repository_permissions' or
                after.get('id') != repository['name'] or after.get('repository') != repository['name'] or
                any(after.get(field) != value for field, value in permissions[key].items())):
            raise ValueError('Workflow plan changed an unapproved identity or permission')
        if importing:
            if change['actions'] != ['no-op'] or change.get('importing', {}).get('id') != repository['name']:
                raise ValueError('Workflow import must preserve every current remote field')
        else:
            before = change.get('before') or {}
            if change['actions'] not in (['no-op'], ['update']) or before.get('id') != repository['name']:
                raise ValueError('Workflow convergence cannot create, delete or replace a repository resource')
            for field, value in before.items():
                if (field not in permissions[key] and not change.get('after_unknown', {}).get(field) and
                        after.get(field) != value):
                    raise ValueError('Workflow convergence changed an unowned field')


def run(action):
    revision = source.binding()
    values, api = inputs()
    desired, observed = repositories(api, values)
    os.environ.pop('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', None)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    if not os.environ['OP_SERVICE_ACCOUNT_TOKEN']:
        raise ValueError('Local read-only vault credential required for independent encrypted state')
    backend = fields('gitlab-state-github', ('PROJECT_ID', 'USERNAME', 'TOKEN'))
    key = fields('opentofu-state-github', ('PASSPHRASE',))['PASSPHRASE']
    if not re.fullmatch('[1-9][0-9]*', backend['PROJECT_ID']) or len(key) < 32:
        raise ValueError('Existing GitHub state backend and encryption key required')
    url = 'https://gitlab.com/api/v4/projects/' + backend['PROJECT_ID'] + '/terraform/state/ci-workflow-permissions'
    env = environment(backend, url, key)
    env['GITHUB_TOKEN'] = api.token
    path = source.WORK / 'ci/workflow-permissions'
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (path.resolve() != path.absolute() or any(file.is_symlink() for file in path.iterdir()) or
            (path / 'errored.tfstate').exists()):
        raise ValueError('Workflow state recovery required; preserved files cannot be replaced')
    client = SimpleNamespace(path=path, env=env, native=lambda *args: native(path, env, *args))
    with (source.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        copy_source(path)
        accepted = path / 'accepted.json'
        binding = {'backend': hashlib.sha256(url.encode()).hexdigest(), 'repositories': identities(desired)}
        if accepted.exists() and any(json.loads(accepted.read_text()).get(k) != v for k, v in binding.items()):
            raise ValueError('Workflow state or repository identity changed; restore original inputs')
        status, _ = request(env)
        if status not in (200, 404) or status == 404 and accepted.exists():
            raise ValueError('Workflow backend unavailable; existing acceptance and state retained')
        if status == 200:
            ciphertext(env)
        atomic(path / 'desired.tfvars.json', desired)
        require(client.native('init', '-reconfigure', '-lockfile=readonly', '-input=false'))
        state = json.loads(require(client.native('show', '-json')).stdout)
        if not occupied(state, desired):
            if action != 'apply' or accepted.exists():
                raise ValueError('Creation-free native import required before workflow checks')
            atomic(path / 'desired.tfvars.json', dict(desired, import_permissions=observed))
            atomic(path / 'imports.tf.json', {'import': [
                {'to': 'github_workflow_repository_permissions.release[' + json.dumps(role) + ']',
                 'id': repository['name']} for role, repository in desired['repositories'].items()]})
            _, plan = document_plan(path, env, 'import.tfplan')
            guard(plan, desired, observed, importing=True)
            if source.binding() != revision or repositories(api, values)[0] != desired:
                raise ValueError('Source changed before import; no state or policy changed')
            require(client.native('apply', '-input=false', '-lock-timeout=0s', 'import.tfplan'))
            maintain(client)
            atomic(path / 'desired.tfvars.json', desired)
        policy = json.loads((BASE / 'policy.json').read_text())
        code, plan = document_plan(path, env, 'desired.tfplan')
        guard(plan, desired, policy)
        if code == 2 and action == 'check':
            raise ValueError('Workflow permissions differ; review the protected plan and apply the declared policy')
        if action == 'apply':
            if source.binding() != revision or repositories(api, values)[0] != desired:
                raise ValueError('Source changed before apply; existing policy retained')
            if code == 2:
                require(client.native('apply', '-input=false', '-lock-timeout=0s', 'desired.tfplan'))
            maintain(client)
            repeated, plan = document_plan(path, env, 'repeat.tfplan')
            guard(plan, desired, policy)
            if repeated != 0:
                raise ValueError('Workflow permissions did not converge; no unrelated resource changed')
            atomic(accepted, dict(binding, revision=revision, independent_encrypted_state=True))
        return {'repository_receivers': 2, 'default_workflow_permissions': 'read',
                'creation_free_import': True, 'organization_policy_changed': False,
                'job_credentials_created': 0, 'repeat_plan_empty': code == 0 or action == 'apply'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('check', 'apply'), default='check', nargs='?')
    os.umask(0o077)
    print(json.dumps(run(parser.parse_args().action)))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Workflow permissions incomplete; protected state retained and organization policy unchanged') from None
