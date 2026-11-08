"""Create missing approved credential placeholders from accepted private Git declarations.

Trusted executor for credential provisioning. Control machine only: reads the
administrator's private-config checkout (reviewed main, clean tree) or one
explicit catalog file, derives missing-item requests from approved catalog
bindings, and creates them with EMPTY required fields through the shared
provisioner. The user fills values in 1Password; ESO resumes delivery on its
refresh interval. Never fills, overwrites, rotates, or deletes values. ESO
remains the sole read-only synchronizer; this token never leaves the machine.

Sources of truth: the active private catalog (services/catalog.json by default,
or the reviewed services.catalogPath selection) carries secret, identity, and
data bindings; services/<name>/protection.yaml files carry backup protection
bindings. Shared platform credentials (OIDC shared item, protection
destinations) are reported for user/administrator completion, never created.
Per-service secrets.yaml files do not exist: catalog supersession stands and
every binding lives in the accepted catalog, never beside a workload.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

try:
    from playbooks.secrets.files import provision
except ImportError:  # Direct script invocation outside the runner package path.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent.parent))
    from playbooks.secrets.files import provision

try:
    from dotenv import dotenv_values
except ImportError:  # pragma: no cover - runner image always provides dotenv.
    dotenv_values = None

import yaml

PROFILES_PATH = Path(__file__).resolve().parent / 'profiles.json'
# Same bound as the services root catalog-path gate.
CATALOG_PATH_PATTERN = re.compile(r'^services/catalog(-[a-z0-9]+(-[a-z0-9]+)*)?[.](json|yaml)$')
TITLE_PATTERN = re.compile(r'[a-z][a-z0-9-]{0,99}')
NAME_PATTERN = re.compile(r'[a-z][a-z0-9-]{0,30}')
CLIENT_PATTERN = re.compile(r'[a-z][a-z0-9-]{0,40}')
LABEL_PATTERN = re.compile(r'[a-zA-Z0-9_-]{1,64}')
SQL_PATTERN = re.compile(r'[a-z][a-z0-9_]{0,62}')
BUCKET_PATTERN = re.compile(r'[a-z][a-z0-9-]{0,40}')
RESERVED_DATABASES = {'postgres', 'template0', 'template1'}
OIDC_ITEM = 'keycloak-client-secrets'
OIDC_FIELD = 'client_secrets'
PROTECTION_PROFILE = 'coordinated-monthly'


def fail(message):
    raise ValueError(message)


def load_profiles():
    try:
        profiles = json.loads(PROFILES_PATH.read_text())
    except (OSError, ValueError):
        raise RuntimeError('Credential profiles are unavailable') from None
    if (not isinstance(profiles, dict) or
            any(key.startswith('_') and key != '_note' or
                not isinstance(value, dict) or set(value) - {'source', 'fields'} or
                not isinstance(value.get('fields'), dict) or not value['fields'] or
                any(not isinstance(label, str) or not label or kind not in ('STRING', 'CONCEALED')
                    for label, kind in value['fields'].items())
                for key, value in profiles.items() if key != '_note') or
            not any(key != '_note' for key in profiles)):
        raise RuntimeError('Credential profiles are invalid')
    return {key: value['fields'] for key, value in profiles.items() if key != '_note'}


def load_document(path):
    try:
        text = Path(path).read_text()
    except OSError:
        fail('Cannot read ' + str(path))
    try:
        if str(path).endswith('.json'):
            return json.loads(text)
        return yaml.safe_load(text)
    except (ValueError, yaml.YAMLError):
        fail('Invalid YAML or JSON in ' + str(path))


def title(value, what):
    if not isinstance(value, str) or not TITLE_PATTERN.fullmatch(value):
        fail('Invalid vault item title for ' + what)
    return value


def run_git(directory, *arguments, timeout=120):
    try:
        result = subprocess.run(['git', '-C', str(directory), *arguments],
                                capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        fail('Private checkout git command did not complete')
    if result.returncode:
        fail('Private checkout is not a clean git repository at a reviewed commit')
    return result.stdout


def acquire_lock(state_directory):
    state = Path(state_directory)
    try:
        state.mkdir(parents=True, exist_ok=True)
        os.chmod(state, 0o700)
    except OSError:
        raise RuntimeError('Cannot prepare reconciler state directory') from None
    handle = open(state / 'credential-reconciler.lock', 'a+b')
    try:
        if os.name == 'nt':
            import msvcrt
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        raise RuntimeError('Another credential reconciler holds the lock') from None
    return handle


def token_from(workspace):
    token = os.environ.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    if token:
        return token
    if dotenv_values is None:
        raise RuntimeError('Missing .env input: OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    values = dotenv_values(str(Path(workspace) / '.env'), interpolate=False)
    if not values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'):
        raise RuntimeError('Missing .env input: OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    return values['OP_PROVISION_SERVICE_ACCOUNT_TOKEN']


class Collector:
    """Merges approved placeholder requests; conflicting titles fail the cycle."""

    def __init__(self):
        self.definitions = {}

    def add(self, item, fields, what):
        title(item, what)
        if (not isinstance(fields, dict) or not fields or
                any(not isinstance(label, str) or not label for label in fields)):
            fail('Invalid placeholder fields for ' + what)
        if item in self.definitions:
            if self.definitions[item] != fields:
                fail('Conflicting placeholder fields for vault item: ' + item)
            return
        self.definitions[item] = fields

    def result(self):
        return {item: {label: (kind, None) for label, kind in fields.items()}
                for item, fields in self.definitions.items()}


def entry_scope(entry, index):
    if not isinstance(entry, dict):
        fail('Catalog entry %d is invalid' % index)
    approval, definition = entry.get('approval'), entry.get('definition')
    if not isinstance(approval, dict) or not isinstance(definition, dict):
        fail('Catalog entry %d requires approval and definition' % index)
    name = approval.get('name')
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        fail('Catalog entry %d has an invalid service name' % index)
    if approval.get('namespace') != 'cloudlab-app-' + name:
        fail('Service destination must be the administrator-owned namespace: ' + name)
    references = approval.get('secretReferences', [])
    if not isinstance(references, list):
        fail('Invalid approved secret references: ' + name)
    return name, approval, definition, references


def collect_data(collector, profiles, name, definition, approvals):
    data = definition.get('data', {})
    if not isinstance(data, dict):
        fail('Invalid data requests: ' + name)
    for kind, request in data.items():
        what = '%s %s request' % (name, kind)
        if kind not in profiles:
            fail('Unsupported data kind for ' + what)
        if (not isinstance(request, dict) or request.get('retention') != 'retain' or
                not isinstance(request.get('credentialReference'), str)):
            fail('Data request requires its credential reference and retain policy: ' + name)
        scope = approvals.get(request['credentialReference'])
        if (not isinstance(scope, dict) or scope.get('service') != name or
                scope.get('kind') != kind or scope.get('name') != request.get('name')):
            fail('Data request requires its exact administrator approval: ' + name)
        if kind == 'database':
            if (not isinstance(request.get('name'), str) or
                    not SQL_PATTERN.fullmatch(request['name']) or
                    request['name'].startswith('pg_') or request['name'] in RESERVED_DATABASES):
                fail('Invalid or reserved database name: ' + name)
        elif (not isinstance(request.get('name'), str) or
                not BUCKET_PATTERN.fullmatch(request['name'])):
            fail('Invalid bucket name: ' + name)
        collector.add(title(scope.get('item'), what), profiles[kind], what)
        if scope.get('migrationItem') is not None:
            collector.add(title(scope['migrationItem'], what + ' migration'), profiles[kind],
                          what + ' migration')


def collect_bindings(collector, name, bindings, references, lane):
    if bindings is None:
        return
    if not isinstance(bindings, list) or len(bindings) > 8:
        fail('Invalid %s secret bindings: %s' % (lane, name))
    for binding in bindings:
        what = '%s %s secret binding' % (name, lane)
        if (not isinstance(binding, dict) or set(binding) - {'name', 'item', 'fields'} or
                not isinstance(binding.get('name'), str) or
                not NAME_PATTERN.fullmatch(binding['name']) or binding['name'] not in references):
            fail('Secret binding destination requires administrator approval: ' + name)
        fields = binding.get('fields')
        if (not isinstance(fields, dict) or not 1 <= len(fields) <= 32 or
                any(not isinstance(key, str) or not key for key in fields) or
                any(not isinstance(label, str) or not LABEL_PATTERN.fullmatch(label)
                    for label in fields.values())):
            fail('Invalid %s secret fields: %s' % (lane, name))
        item = binding.get('item')
        if not isinstance(item, str) or not NAME_PATTERN.fullmatch(item):
            fail('Invalid vault item title for ' + what)
        collector.add(item, {label: 'CONCEALED' for label in fields.values()}, what)


def collect_oidc(name, approval, definition, references):
    """Returns (realm, client) for confidential clients, else None. Never reads values."""
    oidc = definition.get('oidc', {})
    if not isinstance(oidc, dict) or oidc.get('enabled') is not True:
        return None
    mounts = [item.get('name') for item in definition.get('secrets', [])
              if isinstance(item, dict)]
    if 'clientReference' in oidc or 'identityClient' in approval:
        fail('Identity reference profile is retired; declare explicit client settings: ' + name)
    if (oidc.get('realm') != 'applications' or not isinstance(oidc.get('client'), str) or
            not CLIENT_PATTERN.fullmatch(oidc['client']) or
            not isinstance(oidc.get('public'), bool)):
        fail('Invalid identity client settings: ' + name)
    if oidc['public']:
        return None
    secret = oidc.get('secretReference')
    if (not isinstance(secret, str) or not CLIENT_PATTERN.fullmatch(secret) or
            secret not in mounts or secret not in references):
        fail('Identity credential requires its approved scoped secret mount: ' + name)
    return 'applications', oidc['client']


def collect_wiring(name, approval, definition, coordinates):
    """Requires unique delivery names and a delivery source per ordinary mount.

    Only the catalog owner renders ExternalSecrets into service namespaces, so
    an ordinary mount without a binding, data credential, or confidential OIDC
    secret delivery would block its workload with no pending signal. Duplicate
    delivery names would render competing ExternalSecrets for one Secret. Runs
    after the collectors above validated these same structures; fail the cycle
    with the exact service and name instead.
    """
    composition = approval.get('composition')
    if composition is None:
        bindings = approval.get('secretBindings') or []
    else:
        bindings = composition.get('secrets') or []
    delivered = [binding['name'] for binding in bindings]
    delivered.extend(request['credentialReference']
                     for request in definition.get('data', {}).values())
    if coordinates is not None:
        delivered.append(definition['oidc']['secretReference'])
    seen = set()
    for target in delivered:
        if target in seen:
            fail('Duplicate credential delivery name: ' + name + '/' + target)
        seen.add(target)
    if composition is not None:
        return
    if approval.get('chartPath', 'charts/service') != 'charts/service':
        custom = definition.get('secrets', [])
        if (not isinstance(custom, list) or any(not isinstance(item, dict) or
                                                not isinstance(item.get('name'), str) for item in custom)):
            fail('Invalid secret mounts: ' + name)
        for mount in [item['name'] for item in custom]:
            if mount not in (approval.get('secretReferences') or []):
                fail('Custom-chart secret mount requires its approved reference: ' + name + '/' + mount)
        return
    mounts = definition.get('secrets', [])
    if (not isinstance(mounts, list) or any(not isinstance(item, dict) or
                                            not isinstance(item.get('name'), str) for item in mounts)):
        fail('Invalid secret mounts: ' + name)
    for mount in [item['name'] for item in mounts]:
        if mount not in seen:
            fail('Secret mount requires its approved delivery binding: ' + name + '/' + mount)


def collect_catalog(profiles, document):
    if not isinstance(document, dict) or not isinstance(document.get('catalog'), list):
        fail('Service catalog requires its entry list')
    approvals = document.get('dataApprovals', {})
    if not isinstance(approvals, dict):
        fail('Service catalog data approvals are invalid')
    collector, oidc, seen = Collector(), [], set()
    for index, entry in enumerate(document['catalog']):
        name, approval, definition, references = entry_scope(entry, index)
        if name in seen:
            fail('Duplicate service in catalog: ' + name)
        seen.add(name)
        collect_data(collector, profiles, name, definition, approvals)
        composition = approval.get('composition')
        if composition is not None:
            if not isinstance(composition, dict):
                fail('Invalid composition approval: ' + name)
            collect_bindings(collector, name, composition.get('secrets'), references, 'composition')
        bindings = approval.get('secretBindings')
        if bindings is not None:
            if 'composition' in approval or \
                    approval.get('chartPath', 'charts/service') != 'charts/service':
                fail('Secret bindings require the ordinary service profile: ' + name)
            collect_bindings(collector, name, bindings, references, 'ordinary')
        coordinates = collect_oidc(name, approval, definition, references)
        collect_wiring(name, approval, definition, coordinates)
        if coordinates is not None:
            oidc.append({'service': name, 'realm': coordinates[0], 'client': coordinates[1]})
    return collector.result(), oidc


def check_oidc(token, checks, inventory):
    """Reports confidential client key status from the existing shared item only."""
    matches = [item for item in inventory if item.get('title') == OIDC_ITEM]
    if len(matches) > 1:
        raise RuntimeError('Duplicate CloudLab item title: ' + OIDC_ITEM)
    if not checks:
        return []
    if not matches:
        return [{**check, 'status': 'awaiting-administrator',
                 'detail': 'shared identity item is missing; administrator bootstrap required'}
                for check in checks]
    current = provision.command(['item', 'get', matches[0]['id'], '--vault', 'CloudLab'], token)
    fields = current.get('fields', []) if isinstance(current, dict) else []
    values = [field.get('value') for field in fields
              if isinstance(field, dict) and field.get('label') == OIDC_FIELD]
    if len(values) != 1 or not isinstance(values[0], str):
        raise RuntimeError('Incompatible shared identity item fields')
    try:
        secrets = json.loads(values[0] or '{}')
    except ValueError:
        raise RuntimeError('Incompatible shared identity item fields') from None
    if not isinstance(secrets, dict):
        raise RuntimeError('Incompatible shared identity item fields')
    report = []
    for check in checks:
        value = secrets.get(check['realm'], {}).get(check['client']) \
            if isinstance(secrets.get(check['realm']), dict) else None
        if isinstance(value, str) and value:
            report.append({**check, 'status': 'ready'})
        else:
            report.append({**check, 'status': 'pending',
                           'detail': 'user supplies the confidential client secret in 1Password'})
    return report


def collect_protection(path, catalog_data):
    """Validates one services/<name>/protection.yaml and reports coverage."""
    document = load_document(path)
    service = path.parent.name
    if (not isinstance(document, dict) or document.get('service') != service or
            not isinstance(document.get('protection'), dict)):
        fail('Protection declaration must match its service directory: ' + str(path))
    declared = document['protection']
    if declared.get('profile') != PROTECTION_PROFILE:
        fail('Unsupported protection profile in ' + str(path))
    resources = declared.get('resources')
    if not isinstance(resources, list) or not 1 <= len(resources) <= 8:
        fail('Protection requires one to eight resources in ' + str(path))
    requests = catalog_data.get(service, {})
    rows = []
    for resource in resources:
        if (not isinstance(resource, dict) or set(resource) - {'kind', 'reference'} or
                resource.get('kind') not in ('database', 'bucket', 'pvc')):
            fail('Invalid protection resource in ' + str(path))
        kind, reference = resource['kind'], resource.get('reference')
        if kind == 'pvc':
            if reference != requests.get('workload'):
                fail('PVC protection must reference the approved workload in ' + str(path))
            # Chart-owned claims hold no verified backup coverage yet.
            rows.append({'kind': kind, 'reference': reference, 'coverage': 'uncovered',
                         'detail': 'service PVCs need separately verified backup coverage'})
        else:
            if reference not in requests.get(kind, set()):
                fail('Protection resource must match a catalog data request in ' + str(path))
            rows.append({'kind': kind, 'reference': reference, 'coverage': 'covered',
                         'detail': 'data owner monthly export covers shared SQL/S3 volumes'})
    destination = title(declared.get('destinationReference'),
                        'protection destination in ' + str(path))
    return {'service': service, 'file': path.name, 'profile': PROTECTION_PROFILE,
            'resources': rows, 'destination': destination}


def check_protection(private_directory, catalog_data, inventory):
    titles = {item.get('title') for item in inventory} if inventory is not None else None
    report = []
    for path in sorted(Path(private_directory).glob('services/*/protection.yaml')) + \
            sorted(Path(private_directory).glob('services/*/protection.yml')):
        row = collect_protection(path, catalog_data)
        if titles is None:
            row['destinationStatus'] = 'unknown'
        elif row['destination'] in titles:
            row['destinationStatus'] = 'ready'
        else:
            row['destinationStatus'] = 'awaiting-administrator'
            row['destinationDetail'] = 'shared destination credentials need administrator bootstrap'
        report.append(row)
    return report


def catalog_requests(document):
    """Indexes catalog data requests and workloads for protection validation."""
    requests = {}
    for entry in document.get('catalog', []):
        if not isinstance(entry, dict):
            continue
        approval, definition = entry.get('approval', {}), entry.get('definition', {})
        name = approval.get('name') if isinstance(approval, dict) else None
        if not isinstance(name, str) or not isinstance(definition, dict):
            continue
        data = definition.get('data', {})
        if not isinstance(data, dict):
            continue
        requests[name] = {
            'database': {request.get('name') for kind, request in data.items()
                         if kind == 'database' and isinstance(request, dict)},
            'bucket': {request.get('name') for kind, request in data.items()
                       if kind == 'bucket' and isinstance(request, dict)},
            'workload': definition.get('name') if isinstance(definition.get('persistence'), dict)
            and definition['persistence'].get('enabled') is True else None,
        }
    return requests


def cycle(arguments, profiles):
    if arguments.catalog_file:
        catalog_path = Path(arguments.catalog_file)
        document = load_document(catalog_path)
        source = {'selected': catalog_path.name}
    else:
        private = Path(arguments.private_dir)
        if not CATALOG_PATH_PATTERN.fullmatch(arguments.catalog_path):
            fail('Service catalog path must be a bounded catalog file directly under services')
        if arguments.fetch:
            run_git(private, 'fetch', 'origin')
        try:
            revision = run_git(private, 'rev-parse', 'HEAD').strip()
            dirty = run_git(private, 'status', '--porcelain').strip()
        except ValueError:
            fail('Private checkout must be a git repository at a reviewed commit')
        if dirty or not re.fullmatch(r'[a-f0-9]{40}', revision):
            fail('Private checkout must be clean at a reviewed commit')
        catalog_path = private / arguments.catalog_path
        document = load_document(catalog_path)
        source = {'selected': arguments.catalog_path, 'revision': revision}
    definitions, oidc_checks = collect_catalog(profiles, document)
    token = token_from(arguments.workspace)
    inventory = provision.inventory_items(token)
    provisioned = provision.ensure_items(token, definitions, placeholders=True) \
        if definitions else {'created': [], 'preserved': [], 'pending': {}}
    oidc = check_oidc(token, oidc_checks, inventory)
    protection = []
    if not arguments.catalog_file or Path(arguments.private_dir).is_dir():
        protection = check_protection(arguments.private_dir, catalog_requests(document),
                                      inventory)
    awaiting = sorted({row['destination'] for row in protection
                       if row['destinationStatus'] == 'awaiting-administrator'} |
                      {check['service'] + '/' + check['client'] for check in oidc
                       if check['status'] == 'awaiting-administrator'})
    return {'source': source, 'created': provisioned['created'],
            'preserved': provisioned['preserved'], 'pending': provisioned['pending'],
            'oidc': oidc, 'protection': protection,
            'awaitingAdministrator': awaiting}


def persist_report(state_dir, payload):
    """Persist the latest cycle report; the cycle counter proves recurring operation."""
    directory = Path(state_dir)
    previous = {}
    try:
        previous = json.loads((directory / 'report.json').read_text())
    except (OSError, ValueError):
        previous = {}
    if not isinstance(previous, dict):
        previous = {}
    cycles = previous.get('cycles')
    report = dict(payload)
    report['cycles'] = cycles + 1 if type(cycles) is int and cycles >= 0 else 1
    report['completedAt'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    tmp = directory / ('report.json.tmp-' + str(os.getpid()))
    tmp.write_text(json.dumps(report, indent=2, sort_keys=True))
    os.replace(tmp, directory / 'report.json')
    return report


def parse_arguments(argv):
    parser = argparse.ArgumentParser(description='Create missing approved credential placeholders.')
    parser.add_argument('--private-dir', default=os.environ.get('PRIVATE_CONFIG_DIR', '/private-config'))
    parser.add_argument('--catalog-path', default=os.environ.get('CLOUDLAB_CATALOG_PATH', 'services/catalog.json'))
    parser.add_argument('--catalog-file', default=None)
    parser.add_argument('--workspace', default='/workspace')
    parser.add_argument('--state-dir', default=os.environ.get('CLOUDLAB_STATE_DIR', '/reconciler-state'))
    parser.add_argument('--interval', type=int, default=0)
    parser.add_argument('--fetch', action='store_true')
    arguments = parser.parse_args(argv)
    if arguments.interval < 0:
        parser.error('interval must be zero or positive')
    return arguments


def main(argv=None):
    arguments = parse_arguments(argv if argv is not None else sys.argv[1:])
    try:
        profiles = load_profiles()
        handle = acquire_lock(arguments.state_dir)
    except (RuntimeError, ValueError, OSError) as error:
        print('credential reconciler: ' + str(error), file=sys.stderr, flush=True)
        return 1
    try:
        while True:
            try:
                report = persist_report(arguments.state_dir, cycle(arguments, profiles))
                print(json.dumps(report, sort_keys=True), flush=True)
            except (RuntimeError, ValueError, OSError) as error:
                print('credential reconciler: ' + str(error), file=sys.stderr, flush=True)
                if not arguments.interval:
                    return 1
            if not arguments.interval:
                return 0
            time.sleep(arguments.interval)
    except KeyboardInterrupt:
        return 0
    finally:
        handle.close()


if __name__ == '__main__':
    raise SystemExit(main())
