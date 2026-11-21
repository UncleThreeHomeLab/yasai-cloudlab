"""Provision missing credential placeholders from authenticated Git snapshots.

The read-only App authenticates public service intent and the private revision.
Provisioning creates empty fields only and never changes existing values.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
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


def title(value, what):
    if not isinstance(value, str) or not TITLE_PATTERN.fullmatch(value):
        fail('Invalid vault item title for ' + what)
    return value


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


def oidc_placeholders(checks):
    """Empty credential map for declared confidential clients, sorted for stable bytes."""
    realms = {}
    for check in sorted(checks, key=lambda row: (row['realm'], row['client'])):
        realms.setdefault(check['realm'], {})[check['client']] = ''
    return realms


def create_oidc_item(token, checks):
    """Create the missing shared identity item with empty declared keys only.

    Sent through standard input like every provisioned item; no secret value
    travels in arguments. Existing items never reach this path, so stored
    values, including sibling realm and client keys, are never rewritten.
    """
    current = provision.inventory_items(token)
    if any(item.get('title') == OIDC_ITEM for item in current):
        raise RuntimeError('CloudLab item appeared during provisioning; rerun to validate it')
    document = {'title': OIDC_ITEM, 'category': 'SECURE_NOTE',
                'tags': ['cloudlab-managed'],
                'fields': [{'id': OIDC_FIELD, 'label': OIDC_FIELD, 'type': 'CONCEALED',
                            'value': json.dumps(oidc_placeholders(checks), sort_keys=True)}]}
    created = provision.command(['item', 'create', '-', '--vault', 'CloudLab'], token, document)
    if (not isinstance(created, dict) or not isinstance(created.get('id'), str) or
            not created['id'] or created.get('title') != OIDC_ITEM):
        raise RuntimeError('Created item response is incomplete; inspect existence before retrying')
    return created


def check_oidc(token, checks, inventory):
    """Ensure declared confidential client keys exist; report ready or pending.

    Creates the missing shared item with empty placeholders for declared
    clients only. Existing items are read, never rewritten: every stored
    value, including sibling keys owned by other consumers, is preserved
    exactly. The user completes empty keys in 1Password; later cycles
    detect completion and report ready.
    """
    matches = [item for item in inventory if item.get('title') == OIDC_ITEM]
    if len(matches) > 1:
        raise RuntimeError('Duplicate CloudLab item title: ' + OIDC_ITEM)
    if not checks:
        return []
    if not matches:
        create_oidc_item(token, checks)
        return [{**check, 'status': 'pending',
                 'detail': 'shared identity placeholders created; user supplies the confidential client secret in 1Password'}
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


def collect_protection(path, document, catalog_data):
    """Validates one services/<name>/protection.yaml and reports coverage."""
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


def check_protection(rows, inventory):
    titles = {item.get('title') for item in inventory}
    for row in rows:
        if row['destination'] in titles:
            row['destinationStatus'] = 'ready'
        else:
            row['destinationStatus'] = 'awaiting-administrator'
            row['destinationDetail'] = 'shared destination credentials need administrator bootstrap'
    return rows


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


def accepted_source(workspace):
    """Capture one complete immutable private snapshot under authenticated public intent."""
    from playbooks.argocd.files import github_app, private_sources, service_activation
    from playbooks.argocd.files.github_setup import repository

    if dotenv_values is None:
        raise RuntimeError('Source credentials are unavailable')
    values = dotenv_values(str(Path(workspace) / '.env'), interpolate=False)
    read_token = os.environ.get('OP_SERVICE_ACCOUNT_TOKEN') or values.get('OP_SERVICE_ACCOUNT_TOKEN')
    if not read_token:
        raise RuntimeError('Missing read-only source credentials')
    previous = os.environ.get('OP_SERVICE_ACCOUNT_TOKEN')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = read_token
    try:
        public = yaml.load((Path(workspace) / 'gitops/roots/public/values.yaml').read_bytes(),
                           Loader=private_sources.strict_loader('Public service input is invalid'))
        repo_url = values.get('PRIVATE_CONFIG_REPOSITORY')
        repo = repository(repo_url)
        contract = private_sources.consumer_contract(public, 'services')
        if not contract['enabled']:
            raise ValueError('Service owner is disabled')
        paths = service_activation.consumer_paths(public.get('services', {}).get('catalogPath'))

        def read(client, revision):
            evidence = private_sources.consumer_payload(values, public, repo_url, revision, 'services')
            if not evidence or evidence['sourceRevision'] != revision or evidence['contract'] != contract:
                raise ValueError('Service owner approval differs')
            for settings in (values, os.environ):
                if 'CLOUDLAB_CATALOG_PATH' in settings and settings['CLOUDLAB_CATALOG_PATH'] != paths[0]:
                    raise ValueError('Legacy catalog setting differs from authenticated intent')
            tree = client.request('GET', 'repos/' + repo + '/git/trees/' + revision + '?recursive=1')
            if (not isinstance(tree, dict) or tree.get('truncated') is not False or
                    not isinstance(tree.get('tree'), list)):
                raise ValueError('Private source tree is incomplete')
            entries = {}
            for entry in tree['tree']:
                if not isinstance(entry, dict) or not isinstance(entry.get('path'), str):
                    raise ValueError('Private source tree is invalid')
                name = entry['path']
                if name in entries:
                    raise ValueError('Private source tree contains duplicate paths')
                entries[name] = entry
            protection = sorted(name for name in entries if re.fullmatch(
                r'services/[^/]+/protection[.](?:yaml|yml)', name))
            services = [name.split('/')[1] for name in protection]
            if (any(not NAME_PATTERN.fullmatch(name) for name in services) or
                    len(set(services)) != len(services)):
                raise ValueError('Private protection paths are invalid or duplicated')
            if len(protection) > 100 or len(tree['tree']) > 10000:
                raise ValueError('Private source tree exceeds its limit')
            documents = {}
            for name in paths + protection:
                entry = entries.get(name)
                if (not isinstance(entry, dict) or entry.get('type') != 'blob' or
                        entry.get('mode') not in ('100644', '100755') or
                        type(entry.get('size')) is not int or not 0 < entry['size'] <= 1048576 or
                        not re.fullmatch(r'[a-f0-9]{40}', entry.get('sha', ''))):
                    raise ValueError('Private source requires bounded regular files')
                obj = client.request('GET', 'repos/' + repo + '/contents/' + name + '?ref=' + revision)
                if (not isinstance(obj, dict) or obj.get('type') != 'file' or
                        obj.get('encoding') != 'base64' or obj.get('sha') != entry['sha'] or
                        obj.get('size') != entry['size']):
                    raise ValueError('Private source file differs from its snapshot')
                raw = private_sources.decode_contents(obj)
                digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
                if len(raw) != entry['size'] or digest != entry['sha']:
                    raise ValueError('Private source file size differs')
                documents[name] = yaml.load(raw, Loader=private_sources.strict_loader('Private source input is invalid'))
            for name in paths[1:]:
                if not isinstance(documents[name], dict) or {'catalog', 'dataApprovals'} & documents[name].keys():
                    raise ValueError('Private service values conflict with the catalog')
            activation = {'required': True, 'repository': public['repository'],
                'revision': public.get('services', {}).get('revision'),
                'private_repository': repo_url, 'private_revision': revision,
                'telemetry': public.get('observability', {}).get('enabled', False),
                'catalog': documents[paths[0]], 'catalogPath': paths[0],
                'applicationSet': evidence['applicationSet']}
            service_activation.validate(activation, {'valuesRepository': repo_url,
                'valuesRevision': revision}, allow_missing_namespace_guard=True)
            return revision, evidence['publicRevision'], paths[0], documents, protection
        return github_app.configuration_revision(values, read=read)
    except Exception:
        raise RuntimeError('Authenticated service source unavailable or invalid; private diagnostics withheld') from None
    finally:
        if previous is None:
            os.environ.pop('OP_SERVICE_ACCOUNT_TOKEN', None)
        else:
            os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = previous


def cycle(arguments, profiles):
    revision, public_revision, selected, documents, paths = accepted_source(arguments.workspace)
    document = documents[selected]
    definitions, oidc_checks = collect_catalog(profiles, document)
    requests = catalog_requests(document)
    protection = [collect_protection(Path(path), documents[path], requests) for path in paths]
    token = token_from(arguments.workspace)
    inventory = provision.inventory_items(token)
    provisioned = provision.ensure_items(token, definitions, placeholders=True) \
        if definitions else {'created': [], 'preserved': [], 'pending': {}}
    oidc = check_oidc(token, oidc_checks, inventory)
    protection = check_protection(protection, inventory)
    awaiting = sorted({row['destination'] for row in protection
                       if row['destinationStatus'] == 'awaiting-administrator'})
    return {'source': {'selected': selected, 'revision': revision, 'publicRevision': public_revision},
            'created': provisioned['created'], 'preserved': provisioned['preserved'],
            'pending': provisioned['pending'], 'oidc': oidc, 'protection': protection,
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
    parser.add_argument('--workspace', default='/workspace')
    parser.add_argument('--state-dir', default=os.environ.get('CLOUDLAB_STATE_DIR', '/reconciler-state'))
    parser.add_argument('--interval', type=int, default=0)
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
