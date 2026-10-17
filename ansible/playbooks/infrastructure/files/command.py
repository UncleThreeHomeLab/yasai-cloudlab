"""Pinned native OpenTofu operations; private plans require explicit review."""
import argparse
import fcntl
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from dotenv import dotenv_values
from playbooks.infrastructure.files.backend import environment
from playbooks.infrastructure.files.retention import ciphertext, maintain, MAX_BYTES

WORKSPACE = Path('/workspace')
PRIVATE = Path('/inputs')
WORK = Path('/infra-work')
ROOTS = ('cloudflare', 'github')
SCHEMAS = {
    'cloudflare': {
        'account_id': None, 'zone_id': None, 'tunnel_id': None, 'team_name': None,
        'applications': {'*': {
            'name': None, 'domain': None, 'session_duration': None, 'allowed_idps': [None],
            'app_launcher_visible': None, 'auto_redirect_to_identity': None,
            'enable_binding_cookie': None, 'options_preflight_bypass': None,
            'policies': {'*': {'id': None, 'name': None, 'decision': None, 'precedence': None,
                          'include': [{'email': {'email': None}, 'service_token': {'token_id': None}}],
                          'exclude': [{'email': {'email': None}}],
                          'require': [{'login_method': {'id': None}, 'oidc': {
                              'claim_name': None, 'claim_value': None, 'identity_provider_id': None}}]}}}},
        'routes': {'*': {'hostname': None, 'service': None, 'application': None, 'dns_comment': None}}},
    'github': {
        'owner': None,
        'repositories': {'*': {key: None for key in (
            'name', 'description', 'visibility', 'default_branch', 'has_issues', 'has_projects',
            'has_wiki', 'has_discussions', 'allow_merge_commit', 'allow_squash_merge',
            'allow_rebase_merge', 'allow_auto_merge', 'delete_branch_on_merge', 'web_commit_signoff_required')}},
        'rulesets': {'*': {
            'repository': None, 'name': None, 'include': [None], 'exclude': [None],
            'bypass_actors': [{'actor_id': None, 'actor_type': None, 'bypass_mode': None}],
            'deletion': None, 'non_fast_forward': None, 'required_linear_history': None,
            'pull_request': {key: None for key in (
                'allowed_merge_methods', 'dismiss_stale_reviews_on_push', 'require_code_owner_review',
                'require_last_push_approval', 'required_approving_review_count', 'required_review_thread_resolution')},
            'strict_status_checks': None, 'status_checks': [{'context': None, 'integration_id': None}]}}}}


SCHEMAS['cloudflare']['service_exposures'] = {'*': {
    'exposure': {'class': None, 'hostname': None, 'access': None, 'path': None, 'port': None},
    'origin': None, 'application': None, 'routed': None, 'published': None}}


def reject_unknown(value, schema):
    """OpenTofu object conversion drops unknown keys; reject them before conversion."""
    if value is None or schema is None:
        return
    if isinstance(schema, list):
        if not isinstance(value, list):
            raise ValueError('Expected an input list')
        for item in value:
            reject_unknown(item, schema[0])
    else:
        if not isinstance(value, dict):
            raise ValueError('Expected an input object')
        if '*' in schema:
            for key, item in value.items():
                if not re.fullmatch(r'[a-z][a-z0-9_-]*', key):
                    raise ValueError('Input map needs stable logical keys')
                reject_unknown(item, schema['*'])
        else:
            if set(value) - set(schema):
                raise ValueError('Unsupported input field; adoption cannot discard unknown policy')
            for key, item in value.items():
                reject_unknown(item, schema[key])


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(resource, attributes):
    keys = ['id']
    if resource['type'] == 'github_repository':
        keys += ['repo_id', 'node_id']
    if resource['type'] == 'cloudflare_zero_trust_access_application':
        keys += ['aud']
    result = {key: attributes.get(key) for key in keys}
    if resource['type'] == 'cloudflare_zero_trust_access_application':
        result['policies'] = {policy['id']: policy.get('reusable') for policy in attributes.get('policies') or []}
    return result


def shared_identities(document):
    # Service DNS has native state identity and an explicit lifecycle; imported
    # shared infrastructure retains its independent, immutable adoption inventory.
    return {resource['address']: identity(resource, resource['change'].get('before') or {})
            for resource in document.get('resource_changes', []) if resource.get('mode') == 'managed'
            and not resource['address'].startswith('cloudflare_dns_record.service_publication[')}


def validate_inventory(root, desired, inventory):
    if root == 'cloudflare':
        expected = {'cloudflare_zero_trust_tunnel_cloudflared_config.routing'}
        for kind, values in (('cloudflare_dns_record.publication', desired['routes']),
                             ('cloudflare_zero_trust_access_application.application', desired['applications'])):
            expected.update(kind + '[' + json.dumps(key) + ']' for key in values)
        for key, app in desired['applications'].items():
            saved = inventory.get('cloudflare_zero_trust_access_application.application[' + json.dumps(key) + ']', {})
            policies = {policy['id']: False for policy in app['policies'].values()}
            if not saved.get('aud') or not policies or saved.get('policies') != policies:
                raise ValueError('Private policy identities or audience differ from accepted inventory')
    else:
        expected = {'github_repository.repository[' + json.dumps(key) + ']' for key in desired['repositories']}
        expected.update('github_branch_default.default[' + json.dumps(key) + ']'
                        for key, repository in desired['repositories'].items() if repository['default_branch'] is not None)
        expected.update('github_repository_ruleset.ruleset[' + json.dumps(key) + ']' for key in desired['rulesets'])
    if not expected or set(inventory) != expected:
        raise ValueError('Private declarations differ from accepted resource scope; refused before live plan')


def source_binding(root):
    files = list((WORKSPACE / 'ansible/playbooks/infrastructure').rglob('*'))
    files += list((WORKSPACE / 'infra' / root).rglob('*'))
    files += list((WORKSPACE / 'ansible/runner').glob('*')) + [WORKSPACE / name for name in (
        'compose.yaml', '.gitignore', '.gitattributes')]
    if root == 'cloudflare':
        files += list((WORKSPACE / 'ansible/playbooks/access/files').glob('*.py'))
        files += list((WORKSPACE / 'ansible/playbooks/services/files').glob('*.py'))
        files += list((WORKSPACE / 'charts/service').rglob('*'))
        files += list((WORKSPACE / 'ansible/playbooks/keycloak/files').glob('access_*.py'))
    else:
        files += list((WORKSPACE / 'ansible/playbooks/argocd/files').glob('*.py'))
    content = hashlib.sha256()
    for path in sorted(files):
        if path.is_file() and '.terraform' not in path.parts and '__pycache__' not in path.parts:
            content.update(str(path.relative_to(WORKSPACE)).encode() + b'\0' + path.read_bytes())
    revision = subprocess.run(['git', '-c', 'safe.directory=/workspace', 'rev-parse', 'HEAD'],
                              cwd=WORKSPACE, capture_output=True, check=True, text=True).stdout.strip()
    paths = ['ansible/playbooks/infrastructure', 'ansible/runner', 'infra/' + root, 'compose.yaml', '.gitignore', '.gitattributes']
    if root == 'cloudflare':
        paths += ['ansible/playbooks/access/files', 'ansible/playbooks/keycloak/files', 'ansible/playbooks/services/files', 'charts/service']
    else:
        paths += ['ansible/playbooks/argocd/files']
    dirty = subprocess.run(['git', '-c', 'safe.directory=/workspace', 'status', '--porcelain', '--', *paths],
                           cwd=WORKSPACE, capture_output=True, check=True).stdout
    if dirty:
        raise ValueError('Live commands require committed infrastructure sources')
    return {'revision': revision, 'source_hash': content.hexdigest()}


def guarded_changes(plan):
    """Ordinary apply repairs existing fields; adoption and lifecycle remain maintenance."""
    changes = plan.get('resource_changes', [])
    for resource in changes:
        if resource.get('mode') != 'managed':
            continue
        change = resource['change']
        if change.get('importing') or resource.get('previous_address'):
            raise ValueError('Import and address migration require explicit maintenance')
        if any(action in ('delete', 'create') for action in change['actions']):
            raise ValueError('Ordinary apply refuses creation, deletion, and replacement')
        before, after = change.get('before') or {}, change.get('after') or {}
        if identity(resource, before) != identity(resource, after):
            raise ValueError('Ordinary apply must preserve resource identities')
        if resource['type'] == 'github_repository':
            if any(before.get(key) != after.get(key) for key in ('name', 'visibility', 'archived')):
                raise ValueError('Ordinary apply refuses repository rename, visibility, or archival changes')
        if resource['type'] == 'cloudflare_zero_trust_access_application':
            if before.get('id') != after.get('id') or before.get('aud') != after.get('aud'):
                raise ValueError('Access identity and JWT audience must remain unchanged')
        if resource['type'] == 'github_repository_ruleset':
            if before.get('bypass_actors') != after.get('bypass_actors'):
                raise ValueError('Ordinary apply must preserve ruleset bypass scope')
            if any(before.get(key) != after.get(key) for key in ('conditions', 'enforcement', 'target', 'repository')):
                raise ValueError('Ordinary apply must preserve ruleset enforcement and branch scope')
            old_rules, new_rules = before.get('rules') or [], after.get('rules') or []
            if old_rules != new_rules:
                # Governance changes need separate maintenance review, not drift repair approval.
                raise ValueError('Ordinary apply must preserve current review and status requirements')
    return sum(resource['change']['actions'] != ['no-op'] for resource in changes)


class Client:
    def __init__(self, root, *, maintenance=False):
        self.root = root
        self.path = WORK / root
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if any(self.path.glob('*.auto.tfvars')) or any(self.path.glob('*.auto.tfvars.json')):
            raise ValueError('Implicit private inputs forbidden; inspect protected work files before initialization')
        inputs = PRIVATE / root
        required = ('desired.tfvars.json', 'backend.json', 'credentials.env', 'encryption.json', 'acceptance.json', 'inventory.json')
        if any(not (inputs / name).is_file() for name in required):
            raise ValueError('Private inputs unavailable; refused before live init or plan')
        snapshot = {name: (inputs / name).read_bytes() for name in required}
        source_start = source_binding(root)
        # Remove only copied declarations, never state, backend cache, or recovery material.
        for path in self.path.glob('*.tf'):
            path.unlink()
        source = WORKSPACE / 'infra' / root
        for path in source.glob('*'):
            if path.is_file() and (path.suffix == '.tf' or path.name in ('.terraform.lock.hcl', 'fixtures.json')):
                shutil.copy2(path, self.path / path.name)
        shutil.copytree(source / 'tests', self.path / 'tests', dirs_exist_ok=True)
        if source_binding(root) != source_start:
            raise ValueError('Source changed while preparing the private run')
        self.desired = json.loads(snapshot[required[0]])
        allowed = set(SCHEMAS[root])
        required_keys = allowed - ({'service_exposures'} if root == 'cloudflare' else set())
        if not required_keys <= set(self.desired) <= allowed:
            raise ValueError('Private desired inputs incomplete')
        reject_unknown(self.desired, SCHEMAS[root])
        backend = json.loads(snapshot['backend.json'])
        if set(backend) != {'project_id'} or not re.fullmatch(r'[1-9][0-9]*', str(backend['project_id'])):
            raise ValueError('Backend requires the designated private GitLab project ID')
        credentials = dotenv_values(stream=StringIO(snapshot['credentials.env'].decode()), interpolate=False)
        provider_key = 'CLOUDFLARE_API_TOKEN' if root == 'cloudflare' else 'GITHUB_TOKEN'
        credential_keys = {'TF_HTTP_USERNAME', 'TF_HTTP_PASSWORD', provider_key}
        if root == 'cloudflare':
            credential_keys.add('TF_VAR_dns_api_token')
        if set(credentials) != credential_keys or not all(credentials.values()):
            raise ValueError('Use separate scoped backend and governance credentials')
        if root == 'cloudflare' and credentials['CLOUDFLARE_API_TOKEN'] == credentials['TF_VAR_dns_api_token']:
            raise ValueError('Cloudflare management and DNS credentials must remain separate')
        encryption = json.loads(snapshot['encryption.json'])
        if set(encryption) != {'passphrase'} or not isinstance(encryption['passphrase'], str) or len(encryption['passphrase']) < 32:
            raise ValueError('Independent encryption recovery passphrase required')
        acceptance = json.loads(snapshot['acceptance.json'])
        statuses = ('accepted', 'prepared', 'importing', 'imported', 'reversing') if maintenance else ('accepted',)
        if set(acceptance) != {'root', 'status'} or acceptance['root'] != root or acceptance['status'] not in statuses:
            raise ValueError('Ordinary commands require accepted ownership; use reviewed maintenance for adoption')
        self.inventory = json.loads(snapshot['inventory.json'])
        if not isinstance(self.inventory, dict) or not self.inventory or not all(
                isinstance(key, str) and isinstance(value, dict) and
                isinstance(value.get('id'), str) and value['id'] and
                not set(value) - {'id', 'aud', 'repo_id', 'node_id', 'policies'}
                for key, value in self.inventory.items()):
            raise ValueError('Accepted private resource identity inventory required')
        validate_inventory(root, self.desired, self.inventory)
        url = 'https://gitlab.com/api/v4/projects/' + str(backend['project_id']) + '/terraform/state/managed'
        self.env = environment({'USERNAME': credentials['TF_HTTP_USERNAME'], 'TOKEN': credentials['TF_HTTP_PASSWORD']},
                               url, encryption['passphrase'])
        self.env[provider_key] = credentials[provider_key]
        if root == 'cloudflare':
            self.env['TF_VAR_dns_api_token'] = credentials['TF_VAR_dns_api_token']
        self.binding = dict(source_start, root=root, backend_hash=digest(url.encode()),
                            inputs={name: digest(data) for name, data in snapshot.items()})
        (self.path / 'desired.tfvars.json').write_bytes(snapshot['desired.tfvars.json'])

    def unchanged_inputs(self):
        if source_binding(self.root) != {key: self.binding[key] for key in ('revision', 'source_hash')} or any(
                digest((PRIVATE / self.root / name).read_bytes()) != checksum
                for name, checksum in self.binding['inputs'].items()):
            raise ValueError('Source or private inputs changed during the run; review a fresh plan')

    def native(self, *arguments):
        prefix = 2 if arguments[0] == 'state' else 1
        result = subprocess.run(['tofu', *arguments[:prefix], '-no-color', *arguments[prefix:]], cwd=self.path,
                                env=self.env, capture_output=True)
        # Plan/show stdout may contain secrets and never enters CI/chat output.
        with (self.path / 'diagnostics.txt').open('ab') as output:
            output.write(result.stderr if arguments[0] == 'show' or arguments[:2] == ('state', 'pull')
                         else result.stdout + result.stderr)
        if result.returncode not in (0, 2):
            print(json.dumps({'root': self.root, 'native_exit': result.returncode,
                              'private_diagnostics': str(self.path / 'diagnostics.txt')}))
        return result

    def initialize(self):
        result = self.native('init', '-input=false', '-lockfile=readonly', '-reconfigure')
        if result.returncode:
            raise RuntimeError('Native init failed; private diagnostics retained')

    def plan(self, action):
        if self.root == 'github':
            from playbooks.infrastructure.files.github_adoption import observe
            observe(self.desired, self.inventory, self.env['GITHUB_TOKEN'])
        self.initialize()
        ciphertext(self.env)
        filename = 'reviewed.tfplan'
        result = self.native('plan', '-input=false', '-detailed-exitcode', '-lock-timeout=0s',
                             '-var-file=desired.tfvars.json', '-out=' + filename)
        if result.returncode not in (0, 2):
            return result.returncode
        shown = self.native('show', '-json', filename)
        if shown.returncode:
            return shown.returncode
        document = json.loads(shown.stdout)
        if len(shown.stdout) > MAX_BYTES // 2:
            raise ValueError('Private plan exceeds the bounded state review size; maintenance required')
        count = sum(resource['change']['actions'] != ['no-op'] for resource in document.get('resource_changes', []))
        blocked = None
        try:
            guarded_changes(document)
        except ValueError as error:
            blocked = str(error)
        identities = shared_identities(document)
        if identities != self.inventory:
            blocked = 'Resource inventory changed; maintenance review required'
        review = self.native('show', filename)
        if review.returncode:
            return review.returncode
        (self.path / 'review.txt').write_bytes(review.stdout)
        self.unchanged_inputs()
        manifest = dict(self.binding, plan_hash=digest((self.path / filename).read_bytes()), planned_at=int(time.time()))
        (self.path / 'plan-binding.json').write_text(json.dumps(manifest, sort_keys=True))
        print(json.dumps({'root': self.root, 'changes': count, 'review': manifest['plan_hash'],
                          'private_review': str(self.path / 'review.txt'), 'apply_blocked': blocked}))
        if action == 'verify' and blocked:
            return 1
        return result.returncode

    def apply(self, reviewed_hash):
        manifest = json.loads((self.path / 'plan-binding.json').read_text())
        planned_at = manifest.pop('planned_at', None)
        current = dict(self.binding, plan_hash=digest((self.path / 'reviewed.tfplan').read_bytes()))
        if manifest != current or reviewed_hash != manifest['plan_hash']:
            raise ValueError('Apply requires exact reviewed plan, revision, inputs, lock and backend')
        if type(planned_at) is not int or not 0 <= time.time() - planned_at <= 3600:
            raise ValueError('Reviewed plan expired; generate and review a fresh plan')
        shown = self.native('show', '-json', 'reviewed.tfplan')
        if shown.returncode:
            return shown.returncode
        document = json.loads(shown.stdout)
        count = guarded_changes(document)
        identities = shared_identities(document)
        if identities != self.inventory:
            raise ValueError('Resource inventory changed; maintenance review required')
        # Native backend serial/lineage checks reject stale plans after initialization.
        if self.root == 'github':
            from playbooks.infrastructure.files.github_adoption import observe
            observe(self.desired, self.inventory, self.env['GITHUB_TOKEN'])
        self.initialize()
        self.unchanged_inputs()
        ciphertext(self.env)
        result = self.native('apply', '-input=false', '-lock-timeout=0s', 'reviewed.tfplan')
        print(json.dumps({'root': self.root, 'native_apply_exit': result.returncode, 'changed': count > 0 and result.returncode == 0,
                          'recovery_directory': str(self.path)}))
        if result.returncode == 0:
            maintain(self)
        return result.returncode


def main(arguments=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'verify', 'drift'))
    parser.add_argument('root', choices=ROOTS)
    parser.add_argument('--review', help='Exact private plan SHA-256 after reviewing review.txt')
    args = parser.parse_args(arguments)
    WORK.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (WORK / (args.root + '.lock')).open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Concurrent local operation rejected; never force unlock') from None
        client = Client(args.root)
        return client.apply(args.review) if args.action == 'apply' else client.plan(args.action)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, TypeError, KeyError, AttributeError, OSError, subprocess.SubprocessError) as error:
        # Do not interpolate native exceptions: they may include credentials or state.
        print(str(error) if isinstance(error, (ValueError, RuntimeError)) else
              'Infrastructure operation failed; private recovery material retained', file=sys.stderr)
        raise SystemExit(1) from None
