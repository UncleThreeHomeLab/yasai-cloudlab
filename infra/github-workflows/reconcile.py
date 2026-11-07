"""Reconcile GitHub repository governance from reviewed public Git.

Trusted executor for repository governance. Control machine only: reads the
reviewed public declaration (platform/governance/repositories/platform.yaml)
from a clean checkout at protected main, verifies both repository identities
against the GitHub API, and plans the native module every cycle. Plans apply
only with an explicit merged approval binding {binding, plan} from the private
repository; the standing loop applies that binding with no second operator
command. Tokens and private repository identity stay in ignored local inputs;
only revisions, digests and change counts are reported.

Approval ceremony: merge the declaration change; read the pending digest from
this reconciler's status; merge a second private PR binding {binding, plan}
for the current declaration content hash; the standing loop applies it and
reports convergence. Merging the approval PR keeps the declaration bytes
identical, so the approval stays satisfiable; any declaration or plan change
voids it until rebound.
"""

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

import yaml
from dotenv import dotenv_values

ROOT = Path('/workspace')
WORK = Path('/infra-work/github')
INPUTS = Path('/inputs/github')
MODULE = 'infra/github-workflows'
DECLARATION = 'platform/governance/repositories/platform.yaml'
APPROVAL_PATH = 'platform/governance/approval.yaml'
MAX_FILE_BYTES = 65536
PROFILE_FIELDS = ('profile', 'workflowTokenPermissions', 'workflowsMayApprovePullRequests',
                  'releaseAppsMayMerge', 'forcePushes', 'branchDeletion', 'reviewBoundary')
OWNED = re.compile(r'terraform_data[.]governance'
                   r'|github_workflow_repository_permissions[.]release\["(?:public_platform|private_config)"\]'
                   r'|github_repository_ruleset[.](?:merge_guard|tag_guard)\[0\]')


def fail(message):
    raise RuntimeError(message)


def configuration():
    interval = os.environ.get('GOVERNANCE_INTERVAL', '300')
    try:
        interval = int(interval)
    except ValueError:
        fail('GOVERNANCE_INTERVAL must be seconds')
    if not 60 <= interval <= 86400:
        fail('GOVERNANCE_INTERVAL must be between 60 and 86400 seconds')
    return {'interval': interval}


def reviewed_revision():
    """Accept only a clean checkout at protected main; merges declare intent."""
    git = ['git', '--no-optional-locks', '-c', 'safe.directory=/workspace', '-C', str(ROOT)]
    head = subprocess.run(git + ['rev-parse', 'HEAD'], capture_output=True, text=True,
                          timeout=30, check=True).stdout.strip()
    dirty = subprocess.run(git + ['status', '--porcelain'], capture_output=True, text=True,
                           timeout=60, check=True).stdout.strip()
    main = remote_main()
    if dirty or not re.fullmatch(r'[a-f0-9]{40}', head) or head != main:
        fail('Governance checkout must be clean at reviewed origin/main')
    return head


def remote_main():
    """Fetch protected main from true upstream; never mutate mounts."""
    try:
        git = ['git', '--no-optional-locks', '-c', 'safe.directory=/workspace', '-C', str(ROOT)]
        upstream = subprocess.run(git + ['remote', 'get-url', 'origin'],
                                  capture_output=True, text=True, timeout=30, check=True).stdout.strip()
        if not upstream:
            fail('Governance freshness check failed; refused')
        WORK.mkdir(parents=True, exist_ok=True)
        copy = WORK / 'freshness'
        if copy.exists():
            shutil.rmtree(copy)
        subprocess.run(['git', 'clone', '--quiet', '--no-checkout', str(ROOT), str(copy)],
                       capture_output=True, text=True, timeout=120, check=True)
        subprocess.run(['git', '-C', str(copy), 'remote', 'set-url', 'origin', upstream],
                       capture_output=True, text=True, timeout=30, check=True)
        subprocess.run(['git', '-C', str(copy), 'fetch', '--quiet', 'origin', 'main'],
                       capture_output=True, text=True, timeout=120, check=True)
        return subprocess.run(['git', '-C', str(copy), 'rev-parse', 'origin/main'],
                              capture_output=True, text=True, timeout=30, check=True).stdout.strip()
    except RuntimeError:
        raise
    except (subprocess.SubprocessError, OSError):
        fail('Governance freshness check failed; refused')


def declaration(raw):
    """Reviewed public declaration; mirrors the native module preconditions."""
    document = yaml.safe_load(raw)
    if not isinstance(document, dict) or set(document) != {'repository', 'repositoryId', 'governance'}:
        fail('Governance declaration is not the reviewed platform document')
    profile = document['governance']
    if (not isinstance(document['repository'], str) or not re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+', document['repository'])
            or type(document['repositoryId']) is not int or document['repositoryId'] <= 0
            or not isinstance(profile, dict) or set(profile) != set(PROFILE_FIELDS)
            or profile['profile'] != 'public-gitops'
            or profile['workflowTokenPermissions'] != 'read-only'
            or profile['workflowsMayApprovePullRequests'] is not False
            or profile['releaseAppsMayMerge'] is not False
            or profile['forcePushes'] is not False
            or profile['branchDeletion'] is not False
            or profile['reviewBoundary'] != 'public-pr-merge-guard'):
        fail('Governance declaration differs from the reviewed read-only profile')
    owner, _, name = document['repository'].partition('/')
    return {'owner': owner, 'name': name, 'id': document['repositoryId']}


def github_inputs():
    """Backend, credentials, encryption and private identity from ignored inputs."""
    for name in ('backend.json', 'credentials.env', 'encryption.json', 'private.json'):
        if not (INPUTS / name).is_file():
            fail('Governance private inputs unavailable; refused before live plan')
    backend = json.loads((INPUTS / 'backend.json').read_text())
    if set(backend) != {'project_id'} or not re.fullmatch(r'[1-9][0-9]*', str(backend['project_id'])):
        fail('Governance backend requires the designated state project')
    credentials = dotenv_values(str(INPUTS / 'credentials.env'), interpolate=False)
    if not {'TF_HTTP_USERNAME', 'TF_HTTP_PASSWORD', 'GITHUB_TOKEN'} <= set(credentials) or not all(
            credentials[key] for key in ('TF_HTTP_USERNAME', 'TF_HTTP_PASSWORD', 'GITHUB_TOKEN')):
        fail('Governance keeps backend and provider credentials separate')
    encryption = json.loads((INPUTS / 'encryption.json').read_text())
    if (set(encryption) != {'passphrase'} or not isinstance(encryption['passphrase'], str)
            or len(encryption['passphrase']) < 32):
        fail('Governance requires its independent encryption passphrase')
    private = json.loads((INPUTS / 'private.json').read_text())
    identity = private.get('private_repository', {})
    permissions = private.get('private_permissions', {})
    if (set(private) != {'private_repository', 'private_permissions'}
            or set(identity) != {'name', 'id', 'node_id'}
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', identity.get('name', ''))
            or type(identity.get('id')) is not int or identity['id'] <= 0
            or not isinstance(identity.get('node_id'), str) or not identity['node_id']
            or set(permissions) != {'default_workflow_permissions', 'can_approve_pull_request_reviews'}
            or permissions['default_workflow_permissions'] not in ('read', 'write')
            or type(permissions['can_approve_pull_request_reviews']) is not bool):
        fail('Governance private inputs violate their contract')
    return backend, credentials, encryption['passphrase'], private


def repository_identity(token, owner, name):
    request = urllib.request.Request('https://api.github.com/repos/' + owner + '/' + name,
                                     headers={'Authorization': 'Bearer ' + token,
                                              'Accept': 'application/vnd.github+json',
                                              'User-Agent': 'cloudlab-governance-reconciler'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            document = json.load(response)
    except (urllib.error.URLError, ValueError):
        fail('GitHub repository lookup failed; governance retained')
    if (not isinstance(document, dict) or document.get('name') != name
            or type(document.get('id')) is not int
            or not isinstance(document.get('node_id'), str) or not document['node_id']):
        fail('GitHub repository identity is invalid; governance retained')
    return {'name': name, 'id': document['id'], 'node_id': document['node_id']}


def github_json(token, path, limit=MAX_FILE_BYTES):
    """Bounded read-only GitHub API read; 404 is absent, anything else fails closed."""
    if not re.fullmatch(r'[A-Za-z0-9_./?=&-]+', path) or '..' in path:
        fail('Invalid GitHub read path')
    request = urllib.request.Request('https://api.github.com/' + path,
                                     headers={'Authorization': 'Bearer ' + token,
                                              'Accept': 'application/vnd.github+json',
                                              'User-Agent': 'cloudlab-governance-reconciler'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(limit + 1)
            if len(raw) > limit:
                fail('GitHub response exceeds its bound')
            return json.loads(raw)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        fail('GitHub read failed: HTTP ' + str(error.code))
    except (urllib.error.URLError, ValueError):
        fail('GitHub read unavailable or invalid')


def private_approval(token, slug):
    """Merged private {binding, plan} bytes at private main, or None when absent."""
    document = github_json(token, 'repos/' + slug + '/git/ref/heads/main')
    reference = document.get('object') if isinstance(document, dict) else None
    revision = reference.get('sha') if isinstance(reference, dict) else None
    if not revision or not re.fullmatch('[a-f0-9]{40}', revision):
        fail('Private approval revision is unavailable')
    document = github_json(token, 'repos/' + slug + '/contents/' + APPROVAL_PATH + '?ref=' + revision)
    if document is None:
        return None
    if (not isinstance(document, dict) or document.get('type') != 'file'
            or document.get('encoding') != 'base64'
            or type(document.get('size')) is not int
            or not 0 < document['size'] <= MAX_FILE_BYTES
            or not isinstance(document.get('content'), str)):
        fail('Private approval requires a bounded regular file')
    try:
        raw = base64.b64decode(document['content'].replace('\r', '').replace('\n', ''),
                               validate=True)
    except ValueError:
        fail('Private approval transfer is invalid')
    if len(raw) != document['size']:
        fail('Private approval size changed during transfer')
    return raw


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
    """Merged {binding, plan} approves exactly one declaration hash and plan digest."""
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise RuntimeError('Governance approval binding invalid; settings retained') from error
    if (not isinstance(document, dict) or set(document) != {'binding', 'plan'}
            or not isinstance(document['binding'], str)
            or not re.fullmatch(r'[a-f0-9]{64}', document['binding'])
            or not isinstance(document['plan'], str)
            or not re.fullmatch(r'[a-f0-9]{64}', document['plan'])):
        fail('Governance approval binding invalid; settings retained')
    return hashlib.sha256(binding).hexdigest() == document['binding'], document['plan']


def approval_satisfied(approval, binding, digest):
    """True only when the merged approval binds the live declaration and plan."""
    if approval is None:
        return False
    try:
        text = approval.decode()
    except ValueError:
        fail('Governance approval binding invalid; settings retained')
    current_binding, approved_plan = validate_approval(text, binding)
    return current_binding and approved_plan == digest


def unsupported_prerequisites(document):
    """Module-reported unsupported prerequisites from the planned outputs."""
    outputs = (document.get('planned_values') or {}).get('outputs') or {}
    value = (outputs.get('unsupported_prerequisites') or {}).get('value')
    if (not isinstance(value, list) or not value
            or not all(isinstance(item, str) and item for item in value)):
        fail('Governance prerequisites report is unavailable; refused')
    return value


def tofu_environment(backend, credentials, passphrase):
    """Minimal native HTTP-backend environment with enforced state encryption."""
    result = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    url = ('https://gitlab.com/api/v4/projects/' + str(backend['project_id'])
           + '/terraform/state/github-workflows')
    result['TF_CLI_CONFIG_FILE'] = '/opt/runner/providers.tfrc'
    result.update(TF_HTTP_ADDRESS=url, TF_HTTP_LOCK_ADDRESS=url + '/lock',
                  TF_HTTP_UNLOCK_ADDRESS=url + '/lock', TF_HTTP_LOCK_METHOD='POST',
                  TF_HTTP_UNLOCK_METHOD='DELETE', TF_HTTP_USERNAME=credentials['TF_HTTP_USERNAME'],
                  TF_HTTP_PASSWORD=credentials['TF_HTTP_PASSWORD'], TF_HTTP_RETRY_MAX='0',
                  TF_IN_AUTOMATION='true', TF_INPUT='false',
                  GITHUB_TOKEN=credentials['GITHUB_TOKEN'])
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
        fail('Native governance operation failed; shared state retained')
    return result.stdout


def stage(revision):
    """Stage the reviewed module with its declaration layout; never mutate mounts."""
    root = WORK / 'stage' / revision
    if root.exists():
        shutil.rmtree(root)
    (root / MODULE).parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ROOT / MODULE, root / MODULE,
                    ignore=shutil.ignore_patterns('tests', '.terraform', 'reconcile.py'))
    shutil.copytree(ROOT / 'platform/governance', root / 'platform/governance')
    return root / MODULE


def plan_owned_scope(document):
    """Only the reviewed governance resources may change; shared state is untouchable."""
    for resource in document.get('resource_changes', []):
        if resource['change']['actions'] != ['no-op'] and not OWNED.fullmatch(resource['address']):
            fail('Governance plan touches unowned resources; refused')
    return {'changed': sum(resource['change']['actions'] != ['no-op'] for resource in document.get('resource_changes', [])),
            'total': len(document.get('resource_changes', []))}


def reconcile():
    """Plan governance always; apply only the merged approval binding."""
    revision = reviewed_revision()
    binding = (ROOT / DECLARATION).read_bytes()
    public = declaration(binding)
    backend, credentials, passphrase, private = github_inputs()
    token = credentials['GITHUB_TOKEN']
    live_public = repository_identity(token, public['owner'], public['name'])
    if live_public['id'] != public['id']:
        fail('Public repository identity differs from its reviewed declaration')
    live_private = repository_identity(token, public['owner'], private['private_repository']['name'])
    if live_private != private['private_repository']:
        fail('Private repository identity differs from its declared inputs')
    directory = stage(revision)
    desired = {'owner': public['owner'], 'enable_merge_guard': True,
               'repositories': {'public_platform': live_public, 'private_config': live_private},
               'private_permissions': private['private_permissions']}
    (directory / 'desired.tfvars.json').write_text(json.dumps(desired, sort_keys=True))
    os.chmod(directory / 'desired.tfvars.json', 0o600)
    environment = tofu_environment(backend, credentials, passphrase)
    tofu(directory, environment, 'init', '-input=false', '-reconfigure')
    planned = subprocess.run(['tofu', 'plan', '-input=false', '-detailed-exitcode',
                              '-out=plan', '-var-file=desired.tfvars.json'],
                             cwd=directory, env=environment, capture_output=True,
                             text=True, timeout=600)
    if planned.returncode not in (0, 2):
        fail('Native governance plan failed; shared state retained')
    document = json.loads(tofu(directory, environment, 'show', '-json', 'plan'))
    digest = plan_digest(document)
    changes = plan_owned_scope(document)
    unsupported = unsupported_prerequisites(document)
    drifted = planned.returncode == 2
    if not drifted:
        return {'ready': True, 'changed': False, 'revision': revision, 'plan': digest,
                'changes': changes, 'unsupported_prerequisites': unsupported}
    approval = private_approval(token, public['owner'] + '/' + private['private_repository']['name'])
    approved = approval_satisfied(approval, binding, digest)
    if not approved:
        return {'ready': True, 'changed': False, 'revision': revision, 'plan': digest,
                'changes': changes, 'unsupported_prerequisites': unsupported, 'drifted': True,
                'approved': approved, 'pending_review': True}
    state = tofu(directory, environment, 'state', 'list').split()
    expected = {'terraform_data.governance',
                'github_workflow_repository_permissions.release["public_platform"]',
                'github_workflow_repository_permissions.release["private_config"]',
                'github_repository_ruleset.merge_guard[0]',
                'github_repository_ruleset.tag_guard[0]'}
    if not expected <= set(state):
        fail('Governance apply requires its initial import first')
    applied = subprocess.run(['tofu', 'apply', '-input=false', '-auto-approve', 'plan'],
                             cwd=directory, env=environment, capture_output=True,
                             text=True, timeout=600)
    if applied.returncode:
        fail('Native governance apply failed; inspect shared state before retrying')
    return {'ready': True, 'changed': True, 'revision': revision, 'plan': digest,
            'changes': changes, 'unsupported_prerequisites': unsupported, 'approved': True}


def report(status):
    WORK.mkdir(parents=True, exist_ok=True)
    path = WORK / 'status.json'
    path.write_text(json.dumps(status, sort_keys=True))
    os.chmod(path, 0o600)
    print(json.dumps(status, sort_keys=True), flush=True)


def once():
    try:
        status = {'governance': reconcile()}
        status['ok'] = True
    except RuntimeError as error:
        status = {'governance': {'ready': False, 'error': str(error)}, 'ok': False}
    except Exception:
        status = {'governance': {'ready': False, 'error': 'Governance reconciliation failed; state retained'},
                  'ok': False}
    report(status)
    return status


def main(argv):
    if argv[:1] not in (['once'], ['loop']):
        raise SystemExit('Governance reconciler requires once or loop')
    if '--review' in argv:
        raise SystemExit('The review flag is retired; approval comes from the merged Git binding')
    os.umask(0o077)
    WORK.mkdir(parents=True, exist_ok=True)
    with (WORK / 'lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit('Another governance reconciliation holds the lock')
        config = configuration()
        if argv[0] == 'once':
            status = once()
            raise SystemExit(0 if status['ok'] else 1)
        while True:
            try:
                once()
            except RuntimeError as error:
                report({'ok': False, 'error': str(error)})
            except Exception:
                report({'ok': False, 'error': 'Governance reconciliation failed; state retained'})
            time.sleep(config['interval'])


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except RuntimeError as error:
        raise SystemExit('governance reconciler: ' + str(error)) from None
    except Exception:
        raise SystemExit('governance reconciler: Governance reconciliation failed; state retained') from None
