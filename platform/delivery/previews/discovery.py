"""Mint and deliver short-lived private preview discovery credentials.

Control-machine trusted delivery for the privateDiscovery path. Reads the
reviewed private catalog (clean checkout at a reviewed commit) or one explicit
catalog file, mints an exact-repository read token from the local release App
in 1Password, and delivers TOKEN plus lease.json into the owned
argocd/github-preview-discovery Secret over the recovery SSH path. App keys
never leave this machine; the in-cluster controller and ApplicationSet
generators consume only the short-lived token. Repeat runs preserve a valid
owned token; a superseded token expires within its issuer-enforced one hour.
"""
import argparse
import base64
from datetime import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve()
ROOT = next((parent for parent in HERE.parents
             if (parent / 'platform').is_dir() and (parent / 'ansible').is_dir()), None)
if ROOT is None:
    raise RuntimeError('Preview discovery requires the CloudLab checkout')
sys.path.insert(0, str(ROOT / 'platform/delivery/previews/runtime'))
sys.path.insert(0, str(ROOT / 'ansible'))

from contract import (  # noqa: E402
    APPROVALS, LEASE_MARGIN, OWNER, discovery_lease, obsolete, requested_catalog, runtime_catalog)
from playbooks.argocd.files.github_app import app_token  # noqa: E402
from playbooks.argocd.files.github_setup import GitHub, configuration  # noqa: E402
from playbooks.secrets.files.vault import fields  # noqa: E402

import yaml  # noqa: E402

APP_ITEM = 'github-release-private'
APP_FIELDS = ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY')
APP_PERMISSIONS = {'contents': 'write', 'pull_requests': 'write', 'metadata': 'read'}
TOKEN_PERMISSIONS = {'contents': 'read', 'pull_requests': 'read'}
LEASE_PERMISSIONS = {'contents': 'read', 'pull_requests': 'read', 'metadata': 'read'}
NAMESPACE = 'argocd'
NAME = 'github-preview-discovery'
LABELS = {'cloudlab.io/owner': 'cloudlab-preview-discovery',
          'argocd.argoproj.io/secret-type': 'scm-creds'}
CATALOG_PATH = 'previews/catalog.yaml'
MAX_CATALOG_BYTES = 262144
REVISION_PATTERN = re.compile(r'[a-f0-9]{40}')


def fail(message):
    raise ValueError(message)


def run_git(directory, *arguments, timeout=120):
    try:
        result = subprocess.run(['git', '-C', str(directory), *arguments],
                                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        fail('Private checkout git command did not complete')
    if result.returncode:
        fail('Private checkout is not a clean git repository at a reviewed commit')
    return result.stdout


def load_catalog(private_dir, catalog_file=None):
    """Read the reviewed private catalog document; explicit files skip git gates."""
    if catalog_file is not None:
        path = Path(catalog_file)
        source = {'selected': path.name}
    else:
        private = Path(private_dir)
        revision = run_git(private, 'rev-parse', 'HEAD').strip()
        if run_git(private, 'status', '--porcelain').strip() or not REVISION_PATTERN.fullmatch(revision):
            fail('Private checkout must be clean at a reviewed commit')
        path = private / CATALOG_PATH
        source = {'selected': CATALOG_PATH, 'revision': revision}
    try:
        raw = path.read_bytes()
    except OSError:
        fail('Cannot read ' + str(path))
    if len(raw) > MAX_CATALOG_BYTES:
        fail('Preview catalog exceeds its bound')
    try:
        document = json.loads(raw) if path.suffix == '.json' else yaml.safe_load(raw)
    except (ValueError, yaml.YAMLError):
        fail('Invalid YAML or JSON in ' + str(path))
    if not isinstance(document, dict) or not isinstance(document.get('catalog'), dict):
        fail('Preview catalog requires its catalog document in ' + str(path))
    return document['catalog'], source


def merged_settings(raw):
    try:
        return runtime_catalog(requested_catalog(raw))
    except (TypeError, KeyError, AttributeError):
        raise ValueError('Preview catalog requires exact private access and approvals') from None


def designated(values):
    return {role: repo for role, repo, _ in configuration(values)}['private-config']


def revoke(lease):
    try:
        GitHub(lease['token']).request('DELETE', 'installation/token')
    except RuntimeError as error:
        # An expired or already revoked installation token has no remaining access.
        if 'HTTP 401' not in str(error):
            raise


def issue(values):
    """Mint one exact-repository read lease from the local release App."""
    repo = designated(values)
    credentials = fields(APP_ITEM, APP_FIELDS)
    api = GitHub(app_token(credentials))
    app = api.request('GET', 'app')
    installation = api.request('GET', 'app/installations/' + credentials['INSTALLATION_ID'])
    owner = repo.split('/')[0].lower()
    account = installation.get('account') or {} if isinstance(installation, dict) else {}
    if (not isinstance(app, dict) or not isinstance(installation, dict) or
            str(app.get('id')) != credentials['APP_ID'] or app.get('permissions') != APP_PERMISSIONS or
            str(installation.get('app_id')) != credentials['APP_ID'] or
            installation.get('permissions') != APP_PERMISSIONS or installation.get('suspended_at') or
            installation.get('repository_selection') != 'selected' or
            (account.get('login') or '').lower() != owner or
            installation.get('target_type') != 'Organization'):
        raise RuntimeError('Release App grants differ from the designated repository contract')
    issued = api.request('POST', 'app/installations/' + credentials['INSTALLATION_ID'] + '/access_tokens',
                         {'repositories': [repo.split('/')[1]], 'permissions': dict(TOKEN_PERMISSIONS)})
    lease = {'token': issued.get('token')}
    try:
        if not isinstance(lease['token'], str) or not lease['token'] or any(char in lease['token'] for char in '\n\r'):
            raise ValueError('Issued repository token is invalid')
        instant = datetime.fromisoformat(str(issued.get('expires_at', '')).replace('Z', '+00:00'))
        expires = int(instant.timestamp())
        if (instant.tzinfo is None or not 0 < expires - int(time.time()) <= 3660 or
                issued.get('permissions') != LEASE_PERMISSIONS):
            raise ValueError('Issued repository token lifetime or permissions differ')
        inventory = GitHub(lease['token']).request('GET', 'installation/repositories?per_page=100')
        rows = inventory.get('repositories', [])
        if (inventory.get('total_count') != 1 or len(rows) != 1 or rows[0].get('full_name') != repo or
                rows[0].get('private') is not True or type(rows[0].get('id')) is not int or rows[0]['id'] < 1 or
                any(rows[0].get(key) for key in ('fork', 'archived', 'disabled'))):
            raise ValueError('Issued repository token selection differs')
        lease.update(repository=repo, repositoryId=rows[0]['id'],
                     permissions=dict(LEASE_PERMISSIONS), expiresAt=expires)
        return discovery_lease(lease)
    except Exception:
        revoke(lease)
        raise RuntimeError('Repository token validation failed; private diagnostics withheld') from None


_BINARY = None


def cluster(*args, document=None, timeout=90):
    """Run one fixed kubectl verb on the K3s server over the recovery SSH path."""
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        if not os.environ.get(key):
            raise RuntimeError('Preview discovery requires ' + key + ' in .env')
    # Imported late: the SSH transport needs POSIX-only modules and runs only here.
    sys.path.insert(0, str(ROOT / 'ansible/playbooks/tailscale/files'))
    from verify_access import ssh
    global _BINARY
    if _BINARY is None:
        _BINARY = ('k3s kubectl' if ssh('VM', os.environ['VM_HOST'], 'id -u').strip() == '0'
                   else 'sudo -n k3s kubectl')
    raw = ssh('VM', os.environ['VM_HOST'], _BINARY + ' ' + ' '.join(args),
              input=json.dumps(document) if document is not None else None, timeout=timeout)
    return json.loads(raw) if raw.strip() else None


def owned(value):
    meta = value.get('metadata', {})
    if (meta.get('name') != NAME or meta.get('namespace') != NAMESPACE or
            meta.get('labels', {}).get('cloudlab.io/owner') != LABELS['cloudlab.io/owner'] or
            meta.get('labels', {}).get('argocd.argoproj.io/secret-type') != LABELS['argocd.argoproj.io/secret-type'] or
            not meta.get('uid') or not meta.get('resourceVersion') or
            meta.get('ownerReferences') or meta.get('finalizers') or meta.get('deletionTimestamp') or
            value.get('type') != 'Opaque' or set(value.get('data', {})) != {'TOKEN', 'lease.json'}):
        raise ValueError('Preview discovery Secret has conflicting ownership')
    return value


def identity(value):
    return {key: value['metadata'][key] for key in ('uid', 'resourceVersion')} if value else None


def inspect():
    value = cluster('get', 'secret', NAME, '-n', NAMESPACE, '--ignore-not-found', '-o', 'json')
    return owned(value) if value else None


def decode(value):
    owned(value)
    lease = json.loads(base64.b64decode(value['data']['lease.json'], validate=True))
    lease['token'] = base64.b64decode(value['data']['TOKEN'], validate=True).decode()
    return discovery_lease(lease)


def secret_document(lease, resource_version=None):
    metadata = {'name': NAME, 'namespace': NAMESPACE, 'labels': dict(LABELS)}
    if resource_version is not None:
        metadata['resourceVersion'] = resource_version
    return {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque', 'metadata': metadata,
            'data': {'TOKEN': base64.b64encode(lease['token'].encode()).decode(),
                     'lease.json': base64.b64encode(json.dumps(
                         {key: item for key, item in lease.items() if key != 'token'},
                         sort_keys=True).encode()).decode()}}


def deliver(current, lease):
    discovery_lease(lease)
    if current is None:
        cluster('create', '-f', '-', '-o', 'json', document=secret_document(lease))
        return
    # Single-operator use serializes writers; the resourceVersion replace still
    # refuses a lost update, and the fresh token is revoked on any failure.
    if identity(inspect()) != identity(current):
        raise ValueError('Preview discovery Secret changed during the operation')
    cluster('replace', '-f', '-', '-o', 'json',
            document=secret_document(lease, current['metadata']['resourceVersion']))


def ensure(settings, values, *, now=None):
    settings = merged_settings(settings)
    if not settings['privateDiscovery']:
        return {'changed': False, 'private_discovery': False}
    repo = designated(values)
    if any(row['repository'] != repo for row in settings['approvals']):
        raise ValueError('Private previews must use the designated configuration repository')
    now = int(time.time()) if now is None else now
    eligible = [row for row in settings['approvals'] if row['expiresAt'] > now and not obsolete(row)]
    required = max((row['expiresAt'] + LEASE_MARGIN for row in eligible), default=now)
    current = inspect()
    if current:
        lease = decode(current)
        if lease['repository'] != repo:
            raise ValueError('Existing discovery token belongs to another repository')
        if lease['expiresAt'] >= required and lease['expiresAt'] > now:
            return {'changed': False, 'private_discovery': True}
    if not eligible:
        return {'changed': False, 'private_discovery': True}
    lease = issue(values)
    try:
        if lease['expiresAt'] < required:
            raise ValueError('Private preview expiry exceeds the issued credential lease')
        deliver(current, lease)
    except Exception:
        revoke(lease)
        raise
    # Superseded read-only tokens retain only their issuer-enforced one-hour lease.
    return {'changed': True, 'private_discovery': True}


def live_settings():
    approvals = cluster('get', 'configmap', APPROVALS, '-n', NAMESPACE, '--ignore-not-found', '-o', 'json')
    if not approvals:
        return None
    if not isinstance(approvals, dict) or approvals.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER:
        raise ValueError('Preview approvals have conflicting ownership')
    try:
        raw = json.loads(approvals['data']['catalog.json'])
    except (TypeError, KeyError, ValueError):
        raise ValueError('Preview approvals catalog is invalid') from None
    return merged_settings(raw)


def consumers_remain():
    found = cluster('get', 'applicationsets.argoproj.io', '-n', NAMESPACE, '-o', 'json') or {}

    def references(obj):
        if isinstance(obj, dict):
            return (obj.get('secretName') == NAME or obj.get('appSecretName') == NAME or
                    any(references(item) for item in obj.values()))
        return isinstance(obj, list) and any(references(item) for item in obj)

    return any(references(row.get('spec', {})) for row in found.get('items', []))


def retire(values):
    settings = live_settings()
    if settings and settings['privateDiscovery'] and settings['approvals']:
        raise ValueError('Withdraw preview approvals before retiring discovery credentials')
    if consumers_remain():
        raise ValueError('Preview discovery consumers remain; cleanup credentials retained')
    current = inspect()
    if current:
        lease = decode(current)
        if lease['repository'] != designated(values):
            raise ValueError('Discovery retirement cannot target another repository')
        revoke(lease)
        if identity(inspect()) != identity(current):
            raise ValueError('Preview discovery Secret changed during the operation')
        cluster('delete', '--raw=/api/v1/namespaces/' + NAMESPACE + '/secrets/' + NAME, '-f', '-',
                document={'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': identity(current)})
    return {'changed': current is not None}


def cycle(arguments, values):
    catalog, source = load_catalog(arguments.private_dir, arguments.catalog_file)
    if arguments.action == 'retire':
        return dict(retire(values), source=source)
    return dict(ensure(catalog, values), source=source)


def parse_arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='ensure', choices=('ensure', 'retire'))
    parser.add_argument('--private-dir', default=os.environ.get('PRIVATE_CONFIG_DIR', '/private-config'))
    parser.add_argument('--catalog-file', default=None)
    parser.add_argument('--workspace', default='/workspace')
    parser.add_argument('--interval', type=int, default=None)
    arguments = parser.parse_args(argv)
    if arguments.interval is None:
        try:
            arguments.interval = int(os.environ.get('PREVIEW_DISCOVERY_INTERVAL') or 0)
        except ValueError:
            parser.error('PREVIEW_DISCOVERY_INTERVAL must be seconds')
    if arguments.interval and not 60 <= arguments.interval <= 86400:
        parser.error('interval must be zero or between 60 and 86400 seconds')
    if arguments.action == 'retire' and arguments.interval:
        parser.error('retire runs once; it never loops')
    return arguments


def main(argv=None):
    arguments = parse_arguments(argv if argv is not None else sys.argv[1:])
    from dotenv import dotenv_values
    values = dotenv_values(str(Path(arguments.workspace) / '.env'), interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD', 'VM_PORT', 'OP_SERVICE_ACCOUNT_TOKEN'):
        if values.get(key):
            os.environ.setdefault(key, values[key])
    os.environ.setdefault('VM_PORT', '22')
    while True:
        try:
            report = cycle(arguments, values)
            report['completedAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
            print(json.dumps(report, sort_keys=True), flush=True)
        except (RuntimeError, ValueError, OSError) as error:
            print('preview discovery: ' + str(error), file=sys.stderr, flush=True)
            if not arguments.interval:
                return 1
        except KeyboardInterrupt:
            return 0
        if not arguments.interval:
            return 0
        time.sleep(arguments.interval)


if __name__ == '__main__':
    raise SystemExit(main())
