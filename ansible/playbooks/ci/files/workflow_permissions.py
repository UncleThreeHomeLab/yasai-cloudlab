"""Local native ownership of GitOps workflow defaults and the public merge boundary."""
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
MERGE_GUARD = 'github_repository_ruleset.merge_guard[0]'
MERGE_NAME = 'cloudlab-human-release-merge'
TAG_GUARD = 'github_repository_ruleset.tag_guard[0]'
TAG_NAME = 'cloudlab-human-gitops-tags'
REFERENCE_GUARDS = {MERGE_GUARD: MERGE_NAME, TAG_GUARD: TAG_NAME}


def copy_source(directory):
    files = {name: BASE / name for name in ('main.tf', 'variables.tf', 'policy.json', 'merge-guard.tf')}
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


def merge_policy(value, desired):
    """Only a separate admin-through-PR update gate is an accepted merge boundary."""
    if (value.get('repository') != desired['repositories']['public_platform']['name'] or
            value.get('name') != MERGE_NAME or value.get('target') != 'branch' or
            value.get('enforcement') != 'active' or
            value.get('conditions') != [{'ref_name': [{'include': ['~DEFAULT_BRANCH'], 'exclude': []}]}] or
            value.get('bypass_actors') != [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'pull_request'}]):
        raise ValueError('Release merge guard identity, scope or human-only boundary differs')
    rules, = value.get('rules', [])
    if rules.get('update') is not True or any(v for k, v in rules.items() if k != 'update'):
        raise ValueError('Release merge guard must preserve independent PR and status rules')


def require_release_guard(api, repository):
    """Reject publishing before loading App credentials if GitHub cannot enforce the boundary."""
    prefix = 'repos/' + repository
    rules = api.request('GET', prefix + '/rulesets?includes_parents=true&per_page=100')
    selected = [row for row in rules if row.get('name') == MERGE_NAME and row.get('enforcement') == 'active']
    if len(selected) != 1:
        raise ValueError('Publishing requires an enforceable human-only GitOps merge guard')
    rule = api.request('GET', prefix + '/rulesets/' + str(selected[0]['id']))
    if (rule.get('target') != 'branch' or rule.get('enforcement') != 'active' or
            rule.get('conditions') != {'ref_name': {'include': ['~DEFAULT_BRANCH'], 'exclude': []}} or
            rule.get('bypass_actors') != [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'pull_request'}] or
            rule.get('rules') not in ([{'type': 'update'}], [{'type': 'update',
                'parameters': {'update_allows_fetch_and_merge': False}}])):
        raise ValueError('GitOps merge guard differs from its reviewed human-only rule')
    tags = [row for row in rules if row.get('name') == TAG_NAME and row.get('enforcement') == 'active']
    if len(tags) != 1:
        raise ValueError('GitOps publishing requires tag protection against branch-name shadowing')
    tag = api.request('GET', prefix + '/rulesets/' + str(tags[0]['id']))
    if (tag.get('target') != 'tag' or tag.get('enforcement') != 'active' or
            tag.get('conditions') != {'ref_name': {'include': ['~ALL'], 'exclude': []}} or
            tag.get('bypass_actors') != [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always'}] or
            {row.get('type') for row in tag.get('rules', [])} != {'creation', 'update', 'deletion'} or
            len(tag['rules']) != 3 or any(set(row) - {'type', 'parameters'} or row.get('parameters') not in (
                None, {}, {'update_allows_fetch_and_merge': False}) for row in tag['rules'])):
        raise ValueError('GitOps tag protection differs from its reviewed admin-only rule')
    for candidate in rules:
        if candidate.get('id') == rule.get('id') or candidate.get('enforcement') != 'active':
            continue
        other = api.request('GET', prefix + '/rulesets/' + str(candidate['id']))
        refs = other.get('conditions', {}).get('ref_name', {})
        if (other.get('target') == 'branch' and not other.get('bypass_actors') and not refs.get('exclude') and
                any(ref in ('~DEFAULT_BRANCH', 'refs/heads/main', '~ALL') for ref in refs.get('include', [])) and
                any(r.get('type') == 'pull_request' for r in other.get('rules', []))):
            return {'merge': rule['id'], 'tag': tag['id']}
    raise ValueError('GitOps requires a separate non-bypassable pull request rule')


def guard_existing_merge_rule(api, desired, state):
    repository = desired['repositories']['public_platform']['name']
    rows = api.request('GET', 'repos/' + desired['owner'] + '/' + repository +
                       '/rulesets?includes_parents=true&per_page=100')
    for address, name in REFERENCE_GUARDS.items():
        matches = [row for row in rows if row.get('name') == name]
        owned = [row for row in state.get('values', {}).get('root_module', {}).get('resources', [])
                 if row.get('address') == address]
        if len(matches) > 1 or matches and (not owned or str(matches[0]['id']) !=
                str(owned[0]['values'].get('ruleset_id') or owned[0]['values']['id']).rsplit(':', 1)[-1]):
            raise ValueError('Existing reference guard has another owner; adoption or duplicate creation refused')


def reference_policy(address, value, desired):
    if address == MERGE_GUARD:
        return merge_policy(value, desired)
    if (value.get('repository') != desired['repositories']['public_platform']['name'] or
            value.get('name') != TAG_NAME or value.get('target') != 'tag' or value.get('enforcement') != 'active' or
            value.get('conditions') != [{'ref_name': [{'include': ['~ALL'], 'exclude': []}]}] or
            value.get('bypass_actors') != [{'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always'}]):
        raise ValueError('GitOps tag identity or admin-only boundary differs')
    rules, = value.get('rules', [])
    if (any(rules.get(key) is not True for key in ('creation', 'update', 'deletion')) or
            any(value for key, value in rules.items() if key not in ('creation', 'update', 'deletion'))):
        raise ValueError('GitOps tags require creation, update and deletion protection')


def occupied(document, desired):
    values = document.get('values', {})
    root = values.get('root_module', {})
    rows = root.get('resources', [])
    if root.get('child_modules') or not rows and values.get('outputs'):
        raise ValueError('Workflow state contains unexpected or missing managed resources')
    if not rows:
        return False
    expected = expected_resources(desired)
    addresses = {row['address'] for row in rows}
    if (len(rows) != len(addresses) or addresses not in (set(expected), set(expected) | {MERGE_GUARD}, set(expected) | set(REFERENCE_GUARDS)) or
            values.get('outputs', {}).get('repository_identities', {}).get('value') != identities(desired)):
        raise ValueError('Workflow state differs from its original immutable repository identities')
    for row in rows:
        if row['address'] in REFERENCE_GUARDS:
            if row.get('type') != 'github_repository_ruleset' or not row.get('values', {}).get('id'):
                raise ValueError('Release merge state contains a foreign resource')
            reference_policy(row['address'], row['values'], desired)
            continue
        _, repository = expected[row['address']]
        if (row.get('type') != 'github_workflow_repository_permissions' or
                row.get('values', {}).get('id') != repository['name'] or
                row['values'].get('repository') != repository['name']):
            raise ValueError('Workflow state contains a foreign resource; no live refresh permitted')
    return True


def guard(document, desired, permissions, *, importing=False):
    expected = expected_resources(desired)
    rows = document.get('resource_changes', [])
    addresses = set(expected) | (set() if importing else set(REFERENCE_GUARDS))
    if len(rows) != len(addresses) or {row['address'] for row in rows} != addresses:
        raise ValueError('Workflow plan exceeds approved repository security resources')
    for row in rows:
        if row['address'] in REFERENCE_GUARDS:
            change = row['change']
            if (row.get('type') != 'github_repository_ruleset' or
                    change['actions'] not in (['create'], ['update'], ['no-op'])):
                raise ValueError('Release merge guard cannot be removed or replaced')
            reference_policy(row['address'], change.get('after') or {}, desired)
            if change.get('before'):
                before, after = change['before'], change['after']
                if (before.get('repository') != after['repository'] or before.get('name') != REFERENCE_GUARDS[row['address']] or
                        before.get('id') != after.get('id')):
                    raise ValueError('Release merge guard identity cannot change')
            continue
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
            atomic(path / 'desired.tfvars.json', dict(desired, import_permissions=observed, enable_merge_guard=False))
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
        guard_existing_merge_rule(api, desired, json.loads(require(client.native('show', '-json')).stdout))
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
        require_release_guard(api, desired['owner'] + '/' + desired['repositories']['public_platform']['name'])
        return {'repository_receivers': 2, 'default_workflow_permissions': 'read',
                'public_merge_requires_repository_admin': True, 'private_merge_guard_managed': False,
                'public_tags_require_repository_admin': True,
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
