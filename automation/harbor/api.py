"""Independent local OpenTofu client for the designated Harbor API resources."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import secrets
import shutil
import subprocess
import tempfile
import time

from dotenv import dotenv_values
import yaml

from automation.credentials.provision import ensure_items
from automation.credentials.vault import fields
from automation.connectivity.preflight import ssh
from automation.harbor import api_policy, credentials, transport
from automation.harbor.configuration import client as identity_client
from automation.harbor.recovery import atomic
from automation.infra.backend import environment
from automation.infra.native import native, require
from automation.infra.retention import ciphertext, maintain, request

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'infra/harbor'
WORK = Path('/infra-work/harbor')


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def binding():
    source = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    if (not re.fullmatch(r'https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[.]git', source['repository']) or
            not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9/_-]*', source['revision'])):
        raise ValueError('Harbor API source must use the retained public GitOps repository')
    dirty = subprocess.run(['git', '-c', 'safe.directory=/workspace', 'status', '--porcelain'],
                           cwd=ROOT, capture_output=True, check=True).stdout
    if dirty:
        raise ValueError('Harbor API operations require a clean published checkout')
    env = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    env['GIT_TERMINAL_PROMPT'] = '0'
    revision = subprocess.check_output(['git', '-c', 'safe.directory=/workspace', 'rev-parse', 'HEAD'],
                                       cwd=ROOT, env=env, text=True).strip()
    remote = subprocess.run(['git', '-c', 'credential.helper=', 'ls-remote', '--exit-code', source['repository'],
                             'refs/heads/' + source['revision']], capture_output=True, text=True, env=env, timeout=60)
    published = remote.stdout.split()[0] if remote.returncode == 0 and remote.stdout.split() else ''
    if (not re.fullmatch('[a-f0-9]{40}', published) or subprocess.run(
            ['git', '-c', 'safe.directory=/workspace', 'merge-base', '--is-ancestor', revision, published], cwd=ROOT, env=env,
            capture_output=True).returncode):
        raise ValueError('Harbor requires a reviewed public-main ancestor; fetch the public source before retrying')
    return revision


def metadata(values):
    script = '''import sys,json
sys.path.insert(0,'/opt/cloudlab')
from automation.harbor.recovery import application,APPS,NAMESPACE
from automation.mesh.kube import application_ready,get
apps=[application(name) for name in APPS]
revisions={app['spec']['source']['targetRevision'] for app in apps}
if len(revisions)!=1 or not all(application_ready(app['metadata']['name'],app['spec']['source']['targetRevision']) for app in apps):raise RuntimeError('Harbor installation must converge')
configuration=next(app for app in apps if app['metadata']['name']=='cloudlab-harbor-configuration')['spec']['source']['helm']['valuesObject']
images=sorted(container['image'] for kind in ('deployment','statefulset') for obj in (get(kind,namespace=NAMESPACE) or {}).get('items',[]) for container in obj['spec']['template']['spec']['containers'])
print(json.dumps({'harborHost':configuration['harborHost'],'loginHost':configuration['loginHost'],'images':images,'repositories':sorted({app['spec']['source']['repoURL'] for app in apps})}))
'''
    value = json.loads(ssh('VM', values['VM_HOST'], 'python3 -c ' + shlex.quote(script), timeout=60))
    repository = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
    if (value['repositories'] != [repository] or
            value['images'] != sorted(json.loads((ROOT / 'platform/harbor/images.lock.json').read_text()).values())):
        raise ValueError('Harbor installation differs from the recorded independent artifacts')
    identity_client('https://' + value['loginHost'] + '/realms/platform', 'https://' + value['harborHost'])
    return value


def inputs():
    binding()
    values = dotenv_values(ROOT / '.env', interpolate=False)
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    robots = credentials.provision(WORK / 'provision.lock')
    state = ensure_items(values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), {
        'opentofu-state-harbor': {'PASSPHRASE': ('CONCEALED', lambda: secrets.token_urlsafe(64))}})
    return {'robots': robots, 'state_key': state, 'registry_mutations': 0}


def copy_source(directory, check=False):
    allowed = {'versions.tf', 'variables.tf', 'main.tf'}
    if (any(path.name not in allowed or path.is_symlink() for path in directory.glob('*.tf')) or
            list(directory.glob('*.tf.json')) or list(directory.glob('*.tfvars*'))):
        raise ValueError('Unexpected Harbor declarations or implicit inputs; preserve and review them')
    for name in (*sorted(allowed), '.terraform.lock.hcl', 'contract.json'):
        destination = directory / name
        if destination.is_symlink():
            raise ValueError('Harbor work files must not redirect outside their protected directory')
        shutil.copy2(SOURCE / name, destination)
    if check:
        shutil.copytree(SOURCE / 'tests', directory / 'tests')


def check():
    with tempfile.TemporaryDirectory(prefix='harbor-check-') as temporary:
        directory = Path(temporary)
        copy_source(directory, check=True)
        env = environment({'USERNAME': 'synthetic', 'TOKEN': 'synthetic'}, 'https://example.invalid',
                          'synthetic-only-passphrase-never-used-for-live-state')
        for arguments in (('fmt', '-check', '-recursive'), ('init', '-backend=false', '-lockfile=readonly', '-input=false'),
                          ('validate',), ('test',)):
            require(native(directory, env, *arguments))
    return {'native_configuration': True, 'mock_contract': True, 'live_resources_verified': False}


class Client:
    def __init__(self):
        os.environ.pop('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', None)
        self.revision = binding()
        self.values = dotenv_values(ROOT / '.env', interpolate=False)
        os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = self.values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
        if not os.environ['OP_SERVICE_ACCOUNT_TOKEN']:
            raise ValueError('Read-only vault token required for Harbor API operations')
        backend = fields('gitlab-state-harbor', ('PROJECT_ID', 'USERNAME', 'TOKEN'))
        key = fields('opentofu-state-harbor', ('PASSPHRASE',))['PASSPHRASE']
        if not re.fullmatch('[1-9][0-9]*', backend['PROJECT_ID']) or len(key) < 32:
            raise ValueError('Independent scoped backend and encryption recovery key required')
        url = 'https://gitlab.com/api/v4/projects/' + backend['PROJECT_ID'] + '/terraform/state/managed'
        self.env = environment(backend, url, key)
        self.private = {'backend': backend, 'state_key': key}
        self.backend = checksum(json.dumps(self.private, sort_keys=True).encode())
        self.path = WORK
        self.path.mkdir(mode=0o700, parents=True, exist_ok=True)
        copy_source(self.path)
        self.provider = json.loads((ROOT / 'automation/runner/harbor-provider.lock.json').read_text())['package_sha256']

    def native(self, *arguments):
        return require(native(self.path, self.env, *arguments), allowed=(0, 2))

    def initialize(self):
        require(self.native('init', '-reconfigure', '-lockfile=readonly', '-input=false'))

    def unchanged(self, recorded):
        current = {'revision': binding(), 'inputs': checksum(json.dumps(self.private, sort_keys=True).encode()),
                   'provider': self.provider, 'backend': self.backend}
        if current != recorded:
            raise ValueError('Harbor source, provider or vault inputs changed; review a fresh plan')

    def snapshot(self):
        return {'revision': self.revision, 'inputs': checksum(json.dumps(self.private, sort_keys=True).encode()),
                'provider': self.provider, 'backend': self.backend}

    @contextmanager
    def local_import(self):
        with tempfile.TemporaryDirectory(prefix='harbor-native-import-') as temporary:
            directory = Path(temporary)
            copy_source(directory)
            versions = directory / 'versions.tf'
            text = versions.read_text()
            if text.count('  backend "http" {}') != 1:
                raise ValueError('Import fixture must remove exactly its production backend declaration')
            versions.write_text(text.replace('  backend "http" {}', ''))
            env = {key: value for key, value in self.env.items() if not key.startswith('TF_HTTP_')}
            try:
                require(native(directory, env, 'init', '-backend=false', '-lockfile=readonly', '-input=false'))
                yield directory, env
            except Exception:
                for name in ('diagnostics.txt', 'import.tfplan'):
                    if (directory / name).is_file():
                        shutil.copy2(directory / name, self.path / ('import-failure-' + name))
                raise

    @contextmanager
    def connected(self):
        for name in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
            if not self.values.get(name):
                raise ValueError('Existing bootstrap SSH inputs required for private Harbor')
            os.environ[name] = self.values[name]
        os.environ['VM_PORT'] = self.values.get('VM_PORT') or '22'
        discovered = metadata(self.values)
        admin = fields('harbor-emergency', ('username', 'password'))
        if admin['username'] != 'admin':
            raise ValueError('Harbor requires its retained noninteractive emergency identity')
        robots = {project + '-' + role: credentials.read_robot(os.environ['OP_SERVICE_ACCOUNT_TOKEN'],
                    f'harbor-{project}-{role}', f'robot${project}+{role}')
                  for project in api_policy.POLICY['projects'] for role in ('push', 'pull')}
        self.private.update(host=discovered['harborHost'], installation_images=discovered['images'], admin=admin, robots=robots)
        self.env.update(HARBOR_URL='https://' + discovered['harborHost'], HARBOR_USERNAME=admin['username'],
                        HARBOR_PASSWORD=admin['password'], TF_VAR_robot_secrets=json.dumps({
                            name: robot['password'] for name, robot in robots.items()}))
        with transport.forward(self.values, discovered['harborHost']) as (port, proxy):
            self.env.update(proxy)
            self.reader = transport.Reader(discovered['harborHost'], port, admin['username'], admin['password'])
            settings = self.reader.get('/api/v2.0/configurations')
            required = {'auth_mode': 'oidc_auth', 'oidc_endpoint': 'https://' + discovered['loginHost'] + '/realms/platform',
                'oidc_client_id': 'harbor', 'oidc_admin_group': '/platform-admin', 'oidc_verify_cert': True,
                'self_registration': False, 'project_creation_restriction': 'adminonly',
                'oidc_user_claim': 'sub', 'oidc_groups_claim': 'groups'}
            if any(settings.get(name, {}).get('value') != value for name, value in required.items()):
                raise ValueError('Harbor OIDC prerequisites differ; no API ownership or human onboarding')
            gc = self.reader.get('/api/v2.0/system/gc/schedule') or {}
            schedule = gc.get('schedule') or {}
            if schedule.get('cron') or schedule.get('type') not in (None, '', 'None', 'Manual'):
                raise ValueError('Automatic GC is outside the accepted artifact-preservation policy')
            yield

    def state(self):
        self.initialize()
        ciphertext(self.env)
        shown = json.loads(require(self.native('show', '-json')).stdout)
        return {'independent_encrypted_state': True,
                'managed_resources': len(shown.get('values', {}).get('root_module', {}).get('resources', [])),
                'harbor_connection_used': False}

    def empty_state(self):
        status, raw = request(self.env)
        if status == 404 or (status == 204 and not raw):
            return
        ciphertext(self.env)
        shown = json.loads(require(self.native('show', '-json')).stdout)
        if shown.get('values', {}).get('root_module', {}).get('resources'):
            raise ValueError('Harbor bootstrap cannot adopt or replace existing state resources')

    def accepted(self):
        record = json.loads((self.path / 'accepted.json').read_text())
        inventory = json.loads((self.path / 'inventory.json').read_text())
        if (record.get('provider') != self.provider or record.get('imports_verified') is not True or
                record.get('backend') != self.backend or
                record.get('inventory') != inventory or set(inventory) != set(api_policy.resources())):
            raise ValueError('Harbor native field/import acceptance differs from its provider or resource inventory')
        return inventory

    def live_ids(self):
        def rows(path):
            value = self.reader.get('/api/v2.0/' + path + '?page=1&page_size=100')
            if not isinstance(value, list) or len(value) >= 100:
                raise ValueError('Harbor adoption inventory exceeds its bounded scope')
            return value
        def one(values):
            if len(values) > 1:
                raise ValueError('Duplicate Harbor identity; no creation or adoption')
            return values[0] if values else None
        def identifier(row):
            if type(row.get('id')) is not int or row['id'] <= 0:
                raise ValueError('Invalid Harbor resource identity')
            return str(row['id'])
        projects = {name: self.reader.get('/api/v2.0/projects/' + name, missing=True) for name in api_policy.POLICY['projects']}
        groups, robots = rows('usergroups'), rows('robots')
        members, immutable = {}, {}
        for name, project in projects.items():
            if project:
                project_id = project['project_id']
                if type(project_id) is not int or project_id <= 0:
                    raise ValueError('Invalid Harbor project identity')
                members[name] = rows('projects/' + str(project_id) + '/members')
                immutable[name] = rows('projects/' + str(project_id) + '/immutabletagrules')
        result = {}
        for address, (kind, key) in api_policy.resources().items():
            identity = None
            if kind == 'project':
                identity = '/projects/' + str(projects[key]['project_id']) if projects[key] else None
            elif kind == 'group':
                row = one([row for row in groups if row.get('group_name') == key])
                if row and row.get('group_type') != 3:
                    raise ValueError('Selected group has another identity type; preserve it for review')
                identity = '/usergroups/' + identifier(row) if row else None
            elif kind == 'robot_account':
                project, role = key.rsplit('-', 1)
                row = one([row for row in robots if row.get('name') == f'robot${project}+{role}'])
                identity = '/robots/' + identifier(row) if row else None
            else:
                project = api_policy.POLICY['memberships'][key]['project'] if kind == 'project_member_group' else key
                if projects[project]:
                    prefix = '/projects/' + str(projects[project]['project_id'])
                    if kind == 'project_member_group':
                        group = api_policy.POLICY['memberships'][key]['group']
                        row = one([row for row in members[project] if row.get('entity_type') == 'g' and row.get('entity_name') == group])
                        identity = prefix + '/members/' + identifier(row) if row else None
                    elif kind == 'retention_policy':
                        retained = int(projects[project].get('metadata', {}).get('retention_id') or 0)
                        identity = '/retentions/' + str(retained) if retained > 0 else None
                    elif kind == 'immutable_tag_rule':
                        row = one([row for row in immutable[project] if any(selector.get('pattern') == api_policy.POLICY['protected_tags']
                            for selector in row.get('tag_selectors', [])) and any(selector.get('pattern') == '**'
                            for selector in row.get('scope_selectors', {}).get('repository', []))])
                        identity = prefix + '/immutabletagrules/' + identifier(row) if row else None
            result[address] = identity
        return result

    def plan(self, bootstrap=False, verify=False):
        self.initialize()
        if bootstrap:
            self.empty_state()
            if (self.path / 'operation-pending.json').exists() or (self.path / 'accepted.json').exists():
                raise ValueError('Harbor bootstrap requires fresh ownership and no interrupted operation')
            if any(self.live_ids().values()):
                raise ValueError('Existing scoped resources require exact native adoption; never retry creation blindly')
        else:
            ciphertext(self.env)
            if (self.path / 'operation-pending.json').exists():
                raise ValueError('Resolve pending recovery before ordinary Harbor apply')
            if not (self.path / 'accepted.json').exists():
                self.qualify_imports()
            self.accepted()
        result = self.native('plan', '-input=false', '-detailed-exitcode', '-lock-timeout=0s',
                             '-parallelism=2', '-out=reviewed.tfplan')
        shown = json.loads(require(self.native('show', '-json', 'reviewed.tfplan')).stdout)
        changes = api_policy.plan(shown, bootstrap=bootstrap)
        if not bootstrap and self.accepted() != {row['address']: row['change']['after']['id']
                for row in shown['resource_changes'] if row.get('mode') == 'managed'}:
            raise ValueError('Harbor native plan changed accepted resource identities')
        if verify and changes:
            raise ValueError('Harbor API drift detected; review the independent native plan')
        self.unchanged(self.snapshot())
        plan_hash = checksum((self.path / 'reviewed.tfplan').read_bytes())
        (self.path / 'review.txt').write_bytes(require(self.native('show', 'reviewed.tfplan')).stdout)
        atomic(self.path / 'plan-binding.json', dict(self.snapshot(), plan_hash=plan_hash,
                                                    planned_at=time.time(), bootstrap=bootstrap))
        return {'changes': changes, 'review': plan_hash, 'bootstrap': bootstrap, 'native_exit': result.returncode}

    def apply(self, review, recovery=False):
        pending = self.path / 'operation-pending.json'
        if pending.exists() and not recovery:
            raise ValueError('Interrupted native operation retained; inspect recovery before another apply')
        saved = json.loads((self.path / 'plan-binding.json').read_text())
        if recovery != bool(saved.get('recovery')):
            raise ValueError('Harbor apply mode differs from its reviewed plan')
        if recovery:
            self.pending()
            if checksum(pending.read_bytes()) != saved.get('pending_hash'):
                raise ValueError('Harbor interruption record changed; recovery plan refused')
        self.unchanged({key: saved[key] for key in ('revision', 'inputs', 'provider', 'backend')})
        if (review != saved['plan_hash'] or checksum((self.path / 'reviewed.tfplan').read_bytes()) != review or
                not 0 <= time.time() - saved['planned_at'] <= 3600):
            raise ValueError('Harbor apply requires the exact unexpired reviewed encrypted plan')
        shown = json.loads(require(self.native('show', '-json', 'reviewed.tfplan')).stdout)
        api_policy.plan(shown, bootstrap=saved['bootstrap'], imported=recovery and saved['bootstrap'], recovery=recovery)
        self.initialize()
        if saved['bootstrap'] and not recovery:
            self.empty_state()
            if any(self.live_ids().values()):
                raise ValueError('Scoped resources appeared after bootstrap review; creation refused')
        elif not recovery:
            ciphertext(self.env)
            self.accepted()
        if recovery:
            self.check_live_plan(shown)
        if not recovery:
            atomic(pending, saved)
        require(self.native('apply', '-input=false', '-lock-timeout=0s', '-parallelism=2', 'reviewed.tfplan'))
        identities = api_policy.inventory(json.loads(require(self.native('show', '-json')).stdout))
        atomic(self.path / 'inventory.json', identities)
        maintain(self)
        pending.unlink()
        return {'native_apply': True, 'managed_resources': len(identities), 'robots_rotated': False,
                'native_import_acceptance_required': not (self.path / 'accepted.json').exists()}

    def qualify_imports(self):
        if (self.path / 'operation-pending.json').exists():
            raise ValueError('Resolve interrupted ownership before qualifying imports')
        self.initialize()
        ciphertext(self.env)
        identities = api_policy.inventory(json.loads(require(self.native('show', '-json')).stdout))
        inventory_path = self.path / 'inventory.json'
        if inventory_path.exists() and identities != json.loads(inventory_path.read_text()):
            raise ValueError('Harbor identity inventory changed before native import qualification')
        imported_robot_versions = 0
        with self.local_import() as (directory, env):
            for address in api_policy.resources():
                identity = identities[address]
                require(native(directory, env, 'import', '-input=false', '-lock-timeout=0s', address, identity))
            require(native(directory, env, 'plan', '-input=false', '-detailed-exitcode', '-lock-timeout=0s',
                           '-out=import.tfplan'), allowed=(0, 2))
            shown = json.loads(require(native(directory, env, 'show', '-json', 'import.tfplan')).stdout)
            api_policy.plan(shown, imported=True)
            for row in shown['resource_changes']:
                if row.get('mode') != 'managed' or row['change']['actions'] == ['no-op']:
                    continue
                if row['type'] != 'harbor_robot_account':
                    raise ValueError('Native import gap requires explicit disposition by field before acceptance')
                imported_robot_versions += 1
        self.unchanged(self.snapshot())
        if api_policy.inventory(json.loads(require(self.native('show', '-json')).stdout)) != identities:
            raise ValueError('Production Harbor identities changed during read-only import qualification')
        atomic(inventory_path, identities)
        atomic(self.path / 'accepted.json', {'provider': self.provider, 'inventory': identities,
            'backend': self.backend, 'imports_verified': True, 'qualified_at': time.time(),
            'robot_import_version_fields': imported_robot_versions})
        return {'native_imported_resources': len(identities), 'robot_import_version_fields': imported_robot_versions,
                'production_api_writes': 0, 'fixture_state_encrypted': True}

    def pending(self):
        record = json.loads((self.path / 'operation-pending.json').read_text())
        self.unchanged({key: record[key] for key in ('revision', 'inputs', 'provider', 'backend')})
        return record

    def recover_state(self):
        record = json.loads((self.path / 'operation-pending.json').read_text())
        if (record['revision'] != binding() or record['provider'] != self.provider or record['backend'] != self.backend):
            raise ValueError('Use the recorded source, backend and independent encryption key for state recovery')
        checkpoint = self.path / 'errored.tfstate'
        raw = checkpoint.read_bytes()
        if len(raw) > 8 * 1024**2 or 'encrypted_data' not in json.loads(raw):
            raise ValueError('Native recovery requires the preserved encrypted failure checkpoint')
        self.initialize()
        require(self.native('state', 'push', '-lock-timeout=0s', str(checkpoint)))
        return {'native_state_checkpoint_restored': True, 'force_used': False, 'harbor_connection_used': False}

    def recover_import(self, address, identity):
        record = self.pending()
        if address not in api_policy.resources():
            raise ValueError('Native recovery import escaped its designated resource scope')
        kind, key = api_policy.resources()[address]
        if not re.fullmatch(api_policy.IDENTITIES[kind], identity or '') or self.live_ids()[address] != identity:
            raise ValueError('Inspect exact live identity before native import; no title-only adoption')
        if kind == 'robot_account' and not record['bootstrap']:
            raise ValueError('Restore original encrypted robot state; normal project recovery cannot reset robot secrets')
        with self.local_import() as (directory, env):
            require(native(directory, env, 'import', '-input=false', address, identity))
            shown = json.loads(require(native(directory, env, 'show', '-json')).stdout)
            rows = shown.get('values', {}).get('root_module', {}).get('resources', [])
            if len(rows) != 1 or rows[0]['address'] != address or rows[0]['values']['id'] != identity:
                raise ValueError('Quarantined native import returned another identity')
            attributes = dict(rows[0]['values'])
            if kind == 'robot_account':
                project, role = key.rsplit('-', 1)
                if attributes.get('full_name') != self.private['robots'][key]['username']:
                    raise ValueError('Interrupted robot name differs from its original durable vault identity')
                attributes['secret_wo_version'] = 1
            if kind != 'retention_policy' or not record['bootstrap']:
                api_policy.fields(kind, key, attributes)
            if kind in ('project_member_group', 'retention_policy', 'immutable_tag_rule'):
                project = api_policy.POLICY['memberships'][key]['project'] if kind == 'project_member_group' else key
                expected = self.live_ids()['harbor_project.project[' + json.dumps(project) + ']']
                if attributes['scope' if kind == 'retention_policy' else 'project_id'] != expected:
                    raise ValueError('Recovery import refers to another project')
        self.initialize()
        self.pending()
        require(self.native('import', '-input=false', '-lock-timeout=0s', address, identity))
        return {'native_identity_imported': True, 'api_mutations': 0, 'original_vault_input_preserved': True}

    def recover_plan(self):
        record = self.pending()
        archive = self.path / ('interrupted-' + record['plan_hash'] + '.tfplan')
        original = self.path / 'reviewed.tfplan'
        if not archive.exists():
            if checksum(original.read_bytes()) != record['plan_hash']:
                raise ValueError('Preserve the original encrypted plan before preparing recovery')
            shutil.copy2(original, archive)
        elif checksum(archive.read_bytes()) != record['plan_hash']:
            raise ValueError('Original interrupted plan changed; recovery refused')
        self.initialize()
        self.native('plan', '-input=false', '-detailed-exitcode', '-lock-timeout=0s', '-parallelism=2', '-out=reviewed.tfplan')
        shown = json.loads(require(self.native('show', '-json', 'reviewed.tfplan')).stdout)
        changes = api_policy.plan(shown, bootstrap=record['bootstrap'], imported=record['bootstrap'], recovery=True)
        self.check_live_plan(shown)
        self.pending()
        plan_hash = checksum((self.path / 'reviewed.tfplan').read_bytes())
        (self.path / 'review.txt').write_bytes(require(self.native('show', 'reviewed.tfplan')).stdout)
        atomic(self.path / 'plan-binding.json', dict(self.snapshot(), plan_hash=plan_hash, planned_at=time.time(),
            bootstrap=record['bootstrap'], recovery=True,
            pending_hash=checksum((self.path / 'operation-pending.json').read_bytes())))
        return {'changes': changes, 'review': plan_hash, 'recovery': True, 'original_vault_input_preserved': True}

    def check_live_plan(self, shown):
        live = self.live_ids()
        for row in shown['resource_changes']:
            if row.get('mode') != 'managed':
                continue
            existing = live[row['address']]
            if row['change']['actions'] == ['create']:
                if existing:
                    raise ValueError('Live resource is missing from state; inspect and import it before recovery')
            elif existing != row['change']['after']['id']:
                raise ValueError('Recovery identity differs from the inspected live resource')


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'inputs', 'state-check', 'plan', 'apply', 'verify', 'qualify-imports',
                                         'recover-state', 'recover-import', 'recover-plan', 'recover-apply'))
    parser.add_argument('--bootstrap', action='store_true')
    parser.add_argument('--review')
    parser.add_argument('--address')
    parser.add_argument('--id')
    args = parser.parse_args()
    if ((args.bootstrap and args.action != 'plan') or
            (args.review is not None) != (args.action in ('apply', 'recover-apply')) or
            (args.address is not None) != (args.action == 'recover-import') or
            (args.id is not None) != (args.action == 'recover-import')):
        parser.error('Supply only the required options for the selected Harbor operation')
    if args.action in ('check', 'inputs'):
        result = {'check': check, 'inputs': inputs}[args.action]()
    else:
        WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (WORK / 'client.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            client = Client()
            if args.action in ('state-check', 'recover-state'):
                result = {'state-check': client.state, 'recover-state': client.recover_state}[args.action]()
            else:
                with client.connected():
                    operations = {'plan': lambda: client.plan(bootstrap=args.bootstrap),
                                  'verify': lambda: client.plan(verify=True), 'apply': lambda: client.apply(args.review),
                                  'qualify-imports': client.qualify_imports,
                                  'recover-import': lambda: client.recover_import(args.address, args.id),
                                  'recover-plan': client.recover_plan,
                                  'recover-apply': lambda: client.apply(args.review, recovery=True)}
                    result = operations[args.action]()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Harbor API operation incomplete; private diagnostics and durable inputs retained') from None
