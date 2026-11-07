"""Control-machine Harbor settings reconciler.

Reads the reviewed private registry binding at protected main, compiles it
with registry.py, and plans the native module every cycle. Plans apply only
with an explicit merged approval binding {binding, plan}; standing
reconciliation never carries one. Invalid or unreachable sources retain
last-valid state and report blocked; they never delete, rotate, or publish.

Approval ceremony: merge the binding change; read the pending digest from
this reconciler's status; merge a second PR binding {binding, plan} for the
current binding content hash; the standing loop applies it and reports
convergence. Merging the approval PR keeps the binding bytes identical, so
the approval stays satisfiable; any binding or plan change voids it until
rebound.

Removal lifecycle: an undeclared project or membership is retained and
reported, never deleted. Any plan containing a delete or replace action is
refused. Scoped revocation needs a separately reviewed scope.

Robot passwords come from the local vault reader; the provisioning identity
never enters provider subprocesses. Harbor stays private: provider traffic
runs through an ephemeral SSH SOCKS tunnel, never with TLS verification off.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, '/workspace/ansible')

from dotenv import dotenv_values

import registry
from playbooks.secrets.files.vault import fields

ROOT = Path('/workspace')
WORK = Path('/infra-work/harbor')
INPUTS = Path('/inputs/harbor')
BINDING_PATH = 'platform/registry/projects/private.yaml'
APPROVAL_PATH = 'platform/registry/approval.yaml'
MAX_FILE_BYTES = 65536


def configuration():
    values = dotenv_values(str(ROOT / '.env'), interpolate=False)
    config = {'private_repository': values.get('PRIVATE_CONFIG_REPOSITORY') or '',
              'github_token': values.get('GITHUB_PROVISION_TOKEN') or '',
              'interval': values.get('HARBOR_INTERVAL') or '300'}
    try:
        config['interval'] = int(config['interval'])
    except ValueError:
        raise RuntimeError('HARBOR_INTERVAL must be seconds') from None
    if not 60 <= config['interval'] <= 86400:
        raise RuntimeError('HARBOR_INTERVAL must be between 60 and 86400 seconds')
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD', 'VM_PORT',
                'OP_SERVICE_ACCOUNT_TOKEN', 'PRIVATE_CONFIG_REPOSITORY',
                'GITHUB_PROVISION_TOKEN'):
        if values.get(key):
            os.environ.setdefault(key, values[key])
    os.environ.setdefault('VM_PORT', '22')
    return config


def repository_slug(url):
    match = re.fullmatch(r'https://github[.]com/([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)[.]git',
                         url or '')
    if not match:
        raise RuntimeError('Repository binding is not a designated HTTPS repository')
    return match[1] + '/' + match[2]


class GitHub:
    """Bounded read-only GitHub client; writes are refused."""

    def __init__(self, token=''):
        self.token = token

    def request(self, path, limit=MAX_FILE_BYTES):
        if not re.fullmatch(r'[A-Za-z0-9_./?=&-]+', path) or '..' in path:
            raise ValueError('Invalid GitHub read path')
        headers = {'Accept': 'application/vnd.github+json'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        request = urllib.request.Request('https://api.github.com/' + path, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read(limit + 1)
                if len(raw) > limit:
                    raise RuntimeError('GitHub response exceeds its bound')
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise RuntimeError('GitHub read failed: HTTP ' + str(error.code)) from None
        except (urllib.error.URLError, ValueError):
            raise RuntimeError('GitHub read unavailable or invalid') from None

    def ref(self, repo, branch='main'):
        document = self.request('repos/' + repo + '/git/ref/heads/' + branch)
        if not document or not re.fullmatch('[a-f0-9]{40}', document['object']['sha']):
            raise RuntimeError('Git revision is unavailable')
        return document['object']['sha']

    def contents(self, repo, path, ref, limit=MAX_FILE_BYTES):
        document = self.request('repos/' + repo + '/contents/' + path + '?ref=' + ref)
        if document is None:
            return None
        if (not isinstance(document, dict) or document.get('type') != 'file'
                or document.get('encoding') != 'base64'
                or type(document.get('size')) is not int
                or not 0 < document['size'] <= limit
                or not isinstance(document.get('content'), str)):
            raise RuntimeError('Git declaration requires a bounded regular file')
        raw = base64.b64decode(document['content'].replace('\r', '').replace('\n', ''),
                              validate=True)
        if len(raw) != document['size']:
            raise RuntimeError('Git declaration size changed during transfer')
        return raw


def harbor_inputs():
    """Static backend plus credentials and encryption from ignored inputs."""
    for name in ('backend.json', 'credentials.env', 'encryption.json'):
        if not (INPUTS / name).exists():
            raise RuntimeError('Harbor private inputs unavailable; refused before live plan')
    backend = json.loads((INPUTS / 'backend.json').read_text())
    if (set(backend) != {'project_id', 'harbor_host'}
            or not re.fullmatch(r'[1-9][0-9]*', str(backend['project_id']))
            or not isinstance(backend['harbor_host'], str)
            or len(backend['harbor_host']) > 253
            or re.fullmatch(r'[a-z0-9]([a-z0-9.-]*[a-z0-9])?',
                            backend['harbor_host']) is None):
        raise RuntimeError('Harbor backend requires the designated state project and host')
    credentials = dotenv_values(str(INPUTS / 'credentials.env'), interpolate=False)
    if not {'TF_HTTP_USERNAME', 'TF_HTTP_PASSWORD'} <= set(credentials) or not all(
            credentials[key] for key in ('TF_HTTP_USERNAME', 'TF_HTTP_PASSWORD')):
        raise RuntimeError('Harbor keeps backend credentials separate')
    encryption = json.loads((INPUTS / 'encryption.json').read_text())
    if (set(encryption) != {'passphrase'} or not isinstance(encryption['passphrase'], str)
            or len(encryption['passphrase']) < 32):
        raise RuntimeError('Harbor requires its independent encryption passphrase')
    return backend, credentials, encryption


def robot_secrets():
    """Durable vault robot passwords with retained identity and version."""
    secrets = {}
    for project in ('cloudlab-public', 'cloudlab-private'):
        for role in ('push', 'pull'):
            item = 'harbor-%s-%s' % (project, role)
            values = fields(item, ('username', 'password', 'secret_version'))
            if (values['username'] != 'robot$%s+%s' % (project, role)
                    or values['secret_version'] != '1'
                    or len(values['password']) < 32):
                raise RuntimeError('Robot custody differs from its retained identity: ' + item)
            secrets['%s-%s' % (project, role)] = values['password']
    return secrets


def administrator():
    admin = fields('harbor-emergency', ('username', 'password'))
    if admin['username'] != 'admin' or not admin['password']:
        raise RuntimeError('Harbor requires its retained noninteractive emergency identity')
    return admin


class Tunnel:
    """Ephemeral SSH SOCKS tunnel to private Harbor; TLS stays verifying."""

    def __init__(self):
        self.process = None

    def __enter__(self):
        env = dict(os.environ, SSHPASS=os.environ['VM_PASSWORD'])
        argv = ['sshpass', '-e', 'ssh', '-N', '-D', '127.0.0.1:1080',
               '-p', os.environ.get('VM_PORT') or '22',
               '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
               '-o', 'PreferredAuthentications=password',
               '-o', 'PubkeyAuthentication=no',
               '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UserKnownHostsFile=/state/known_hosts',
               os.environ['VM_USER'] + '@' + os.environ['VM_HOST']]
        self.process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        start_new_session=True)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('Harbor tunnel failed; shared state retained')
            try:
                socket.create_connection(('127.0.0.1', 1080), timeout=2).close()
                return {'HTTPS_PROXY': 'socks5h://127.0.0.1:1080',
                        'https_proxy': 'socks5h://127.0.0.1:1080',
                        'NO_PROXY': 'gitlab.com', 'no_proxy': 'gitlab.com'}
            except OSError:
                time.sleep(0.5)
        raise RuntimeError('Harbor tunnel failed; shared state retained')

    def __exit__(self, *exc):
        if self.process is not None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            self.process.wait(timeout=10)
        return False


def tofu_environment(backend, credentials, passphrase, admin, host, robots, proxy):
    """Minimal native HTTP-backend environment with enforced state encryption."""
    result = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    url = ('https://gitlab.com/api/v4/projects/' + str(backend['project_id'])
           + '/terraform/state/harbor')
    result['TF_CLI_CONFIG_FILE'] = '/opt/runner/providers.tfrc'
    result.update(TF_HTTP_ADDRESS=url, TF_HTTP_LOCK_ADDRESS=url + '/lock',
                  TF_HTTP_UNLOCK_ADDRESS=url + '/lock', TF_HTTP_LOCK_METHOD='POST',
                  TF_HTTP_UNLOCK_METHOD='DELETE', TF_HTTP_USERNAME=credentials['TF_HTTP_USERNAME'],
                  TF_HTTP_PASSWORD=credentials['TF_HTTP_PASSWORD'], TF_HTTP_RETRY_MAX='0',
                  TF_IN_AUTOMATION='true', TF_INPUT='false',
                  HARBOR_URL='https://' + host, HARBOR_USERNAME=admin['username'],
                  HARBOR_PASSWORD=admin['password'],
                  TF_VAR_robot_secrets=json.dumps(robots, sort_keys=True))
    result.update(proxy)
    result['TF_ENCRYPTION'] = '''key_provider "pbkdf2" "recovery" {
  passphrase = %s
}
method "aes_gcm" "protected" {
  keys = key_provider.pbkdf2.recovery
}
state {
  method = method.aes_gcm.protected
  enforced = true
}
plan {
  method = method.aes_gcm.protected
  enforced = true
}
''' % json.dumps(passphrase)
    return result


def tofu(directory, environment, *args, timeout=600):
    result = subprocess.run(['tofu', *args], cwd=directory, env=environment,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Native Harbor operation failed; shared state retained')
    return result.stdout


def plan_owned_scope(document):
    """Only quota and membership updates may change; every delete is refused."""
    for resource in document.get('resource_changes', []):
        address, actions = resource['address'], resource['change']['actions']
        if actions == ['no-op']:
            continue
        if address.startswith('harbor_project.project['):
            if actions != ['update']:
                raise RuntimeError('Harbor project replacement refused: ' + address)
            before, after = resource['change'].get('before'), resource['change'].get('after')
            if not isinstance(before, dict) or not isinstance(after, dict):
                raise RuntimeError('Harbor project change is unreadable: ' + address)
            changed = sorted(key for key in after if before.get(key) != after.get(key))
            # Imported projects represent the local force_destroy guard as
            # null; its normalization to explicit false rides along with
            # quota updates and is never an API write.
            if changed not in (['storage_quota'],
                               ['force_destroy', 'storage_quota']):
                raise RuntimeError('Only project quota may change: ' + address)
            continue
        if address.startswith('harbor_project_member_group.member['):
            if actions not in (['create'], ['update']):
                raise RuntimeError('Harbor membership removal needs a separate scope: '
                                   + address)
            continue
        raise RuntimeError('Unowned Harbor change refused: ' + address)
    return True


def plan_digest(document):
    """Stable digest over the canonical planned change set.

    Only resource-change addresses, actions, and after-values feed the
    digest, so serialization noise in `tofu show -json` output can never
    void an approval across consecutive cycles.
    """
    changes = sorted(
        ({'address': resource['address'], 'actions': resource['change']['actions'],
          'after': resource['change'].get('after')}
         for resource in document.get('resource_changes', [])
         if resource['change']['actions'] != ['no-op']),
        key=lambda change: change['address'])
    return hashlib.sha256(json.dumps(changes, sort_keys=True).encode()).hexdigest()


def validate_approval(text, binding):
    """Merged {binding, plan} approves exactly one binding hash and plan digest."""
    import yaml
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise RuntimeError('Harbor approval binding invalid; settings retained') from error
    if (not isinstance(document, dict) or set(document) != {'binding', 'plan'}
            or not re.fullmatch(r'[a-f0-9]{64}', document['binding'] or '')
            or not re.fullmatch(r'[a-f0-9]{64}', document['plan'] or '')):
        raise RuntimeError('Harbor approval binding invalid; settings retained')
    return hashlib.sha256(binding).hexdigest() == document['binding'], document['plan']


def reconcile_harbor(config, github, *, apply_allowed=True):
    """Compile the reviewed binding; plan always, apply only the merged binding."""
    backend, credentials, encryption = harbor_inputs()
    robots = robot_secrets()
    admin = administrator()
    repo = repository_slug(config['private_repository'])
    revision = github.ref(repo)
    raw = github.contents(repo, BINDING_PATH, revision)
    if raw is None:
        raise RuntimeError('Registry binding unavailable; last-valid state retained')
    WORK.mkdir(parents=True, exist_ok=True)
    binding_path = WORK / 'binding.yaml'
    binding_path.write_bytes(raw)
    os.chmod(binding_path, 0o600)
    try:
        value = registry.binding(str(binding_path))
        compiled = registry.compile_binding(value)
    except SystemExit as error:
        raise RuntimeError('Registry binding invalid; last-valid state retained: '
                           + str(error)) from None
    retained = sorted(set(registry.CONTRACT['projects']) - set(compiled['projects']))
    directory = WORK / 'harbor'
    if directory.exists():
        shutil.rmtree(directory)
    shutil.copytree(ROOT / 'infra/harbor', directory,
                    ignore=shutil.ignore_patterns('tests', '.terraform*', 'reconcile.py'))
    (directory / 'desired.tfvars.json').write_text(
        json.dumps({'registry': compiled}, sort_keys=True))
    os.chmod(directory / 'desired.tfvars.json', 0o600)
    with Tunnel() as proxy:
        environment = tofu_environment(backend, credentials, encryption['passphrase'],
                                       admin, backend['harbor_host'], robots, proxy)
        tofu(directory, environment, 'init', '-input=false', '-reconfigure')
        planned = subprocess.run(['tofu', 'plan', '-input=false', '-detailed-exitcode',
                                  '-out=plan', '-var-file=desired.tfvars.json'],
                                 cwd=directory, env=environment, capture_output=True,
                                 text=True, timeout=600)
        if planned.returncode not in (0, 2):
            raise RuntimeError('Native Harbor plan failed; shared state retained')
        document = json.loads(tofu(directory, environment, 'show', '-json', 'plan'))
        digest = plan_digest(document)
        plan_owned_scope(document)
        drifted = planned.returncode == 2
        if not drifted:
            return {'ready': True, 'changed': False, 'revision': revision,
                    'plan': digest, 'retained': retained}
        approval_raw = github.contents(repo, APPROVAL_PATH, revision)
        approved = False
        if approval_raw is not None:
            current_binding, approved_plan = validate_approval(approval_raw.decode(), raw)
            approved = current_binding and approved_plan == digest
        if not approved or not apply_allowed:
            return {'ready': True, 'changed': False, 'revision': revision,
                    'plan': digest, 'retained': retained, 'drifted': True,
                    'approved': approved, 'pending_review': True}
        tofu(directory, environment, 'init', '-input=false', '-reconfigure')
        applied = subprocess.run(['tofu', 'apply', '-input=false', '-auto-approve', 'plan'],
                                 cwd=directory, env=environment, capture_output=True,
                                 text=True, timeout=600)
        if applied.returncode:
            raise RuntimeError('Native Harbor apply failed; inspect shared state before retrying')
    return {'ready': True, 'changed': True, 'revision': revision, 'plan': digest,
            'retained': retained, 'approved': True}


def report(status):
    WORK.mkdir(parents=True, exist_ok=True)
    path = WORK / 'status.json'
    path.write_text(json.dumps(status, sort_keys=True))
    os.chmod(path, 0o600)
    print(json.dumps(status, sort_keys=True), flush=True)


def once(config, github):
    try:
        status = {'harbor': reconcile_harbor(config, github)}
        status['ok'] = True
    except RuntimeError as error:
        status = {'ok': False, 'harbor': {'ready': False, 'error': str(error)}}
    report(status)
    return status


def verify(config, github):
    """Read-only proof that live state matches accepted Git intent; never mutates."""
    try:
        planned = reconcile_harbor(config, github, apply_allowed=False)
        proof = {'verified': True, 'revision': planned['revision'], 'plan': planned['plan'],
                 'drifted': bool(planned.get('drifted')),
                 'approved': bool(planned.get('approved', False)),
                 'retained': planned['retained']}
    except RuntimeError as error:
        proof = {'verified': False, 'error': str(error)}
    report(proof)
    return proof


def main(argv):
    if argv[:1] not in (['once'], ['loop'], ['verify']):
        raise SystemExit('Harbor reconciler requires once, loop, or verify')
    os.umask(0o077)
    WORK.mkdir(parents=True, exist_ok=True)
    import fcntl
    with (WORK / 'lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit('Another Harbor reconciliation holds the lock')
        config = configuration()
        for name in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
            if not os.environ.get(name):
                raise SystemExit('Missing lab connection input: ' + name)
        github = GitHub(config['github_token'])
        if argv[0] == 'once':
            status = once(config, github)
            raise SystemExit(0 if status['ok'] else 1)
        if argv[0] == 'verify':
            proof = verify(config, github)
            raise SystemExit(0 if proof['verified'] else 1)
        while True:
            try:
                once(config, github)
            except RuntimeError as error:
                report({'ok': False, 'error': str(error)})
            except Exception:
                report({'ok': False, 'error': 'Harbor reconciliation failed; state retained'})
            time.sleep(config['interval'])


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
