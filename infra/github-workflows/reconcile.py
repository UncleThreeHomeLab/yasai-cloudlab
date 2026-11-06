"""Reconcile GitHub repository governance from reviewed public Git.

Trusted executor for repository governance. Control machine only: reads the
reviewed public declaration (platform/governance/repositories/platform.yaml)
from a clean checkout at protected main, verifies both repository identities
against the GitHub API, and plans the native module every cycle. Plans apply
only with an explicit reviewed plan hash; standing reconciliation never
carries one. Tokens and private repository identity stay in ignored local
inputs; only revisions, digests and change counts are reported.
"""

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


def declaration():
    """Reviewed public declaration; mirrors the native module preconditions."""
    document = yaml.safe_load((ROOT / DECLARATION).read_text())
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


def reconcile(review=None):
    """Plan governance always; apply only the exact reviewed plan."""
    revision = reviewed_revision()
    public = declaration()
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
    digest = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
    changes = plan_owned_scope(document)
    drifted = planned.returncode == 2
    if not drifted:
        return {'ready': True, 'changed': False, 'revision': revision, 'plan': digest, 'changes': changes}
    if review is None:
        return {'ready': True, 'changed': False, 'revision': revision, 'plan': digest,
                'changes': changes, 'drifted': True, 'pending_review': True}
    if review != digest:
        fail('Apply requires the exact reviewed plan')
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
    return {'ready': True, 'changed': True, 'revision': revision, 'plan': digest, 'changes': changes}


def report(status):
    WORK.mkdir(parents=True, exist_ok=True)
    path = WORK / 'status.json'
    path.write_text(json.dumps(status, sort_keys=True))
    os.chmod(path, 0o600)
    print(json.dumps(status, sort_keys=True), flush=True)


def once(*, review=None):
    try:
        status = {'governance': reconcile(review=review)}
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
    review = None
    if '--review' in argv:
        try:
            review = argv[argv.index('--review') + 1]
        except IndexError:
            raise SystemExit('Apply requires the exact reviewed plan hash') from None
        if not re.fullmatch('[a-f0-9]{64}', review or ''):
            raise SystemExit('Apply requires the exact reviewed plan hash')
    if argv[0] == 'loop' and review is not None:
        raise SystemExit('Standing reconciliation never carries a standing apply review')
    os.umask(0o077)
    WORK.mkdir(parents=True, exist_ok=True)
    with (WORK / 'lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit('Another governance reconciliation holds the lock')
        config = configuration()
        if argv[0] == 'once':
            status = once(review=review)
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
