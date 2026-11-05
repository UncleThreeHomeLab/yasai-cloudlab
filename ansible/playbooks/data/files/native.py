"""Operation-scoped data settings authenticated against their independent Git owners."""
import base64
import copy
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import resource
import stat
import subprocess
import tempfile
import time

import yaml

from playbooks.argocd.files import source_snapshot
from playbooks.argocd.files.github_app import app_token, verify_installation
from playbooks.argocd.files.github_setup import GitHub, repository
from playbooks.argocd.files.private_sources import PEM_TEMPLATE
from playbooks.argocd.files.source_revision import matches_revision, identity_project_rules
from playbooks.istio.files.kube import condition, get, kube, wait

APP = 'cloudlab-data-configuration'
SEAWEED = 'cloudlab-seaweedfs'
SETTINGS = 'cloudlab-data-settings'
BINDING = Path('/var/lib/cloudlab/gitops/identity-values-binding.json')
COMPONENTS = ('master', 'volume', 'filer', 's3')
VALUE_FILES = ('platform/certificates.yaml', 'platform/data.yaml', 'services/catalog.json')
TRACKING = 'cloudlab-public-root:argoproj.io/'
ESO_FINALIZER = 'externalsecrets.external-secrets.io/externalsecret-cleanup'


def delegations():
    return [{'group': 'argoproj.io', 'kind': 'Application', 'name': APP, 'namespace': 'argocd',
             'jsonPointers': ['/spec/sources/0/helm/valuesObject/' + field for field in ('maintenance', 'hibernated')]},
            {'group': 'argoproj.io', 'kind': 'Application', 'name': SEAWEED, 'namespace': 'argocd',
             'jsonPointers': ['/spec/source/helm/valuesObject/seaweedfs/' + name + '/replicas' for name in COMPONENTS]}]


def project_spec(name, public, target):
    kinds = ([('', 'ConfigMap'), ('', 'ResourceQuota'), ('postgresql.cnpg.io', 'Cluster'), ('postgresql.cnpg.io', 'Database'),
              ('external-secrets.io', 'ExternalSecret'), ('cert-manager.io', 'Certificate'), ('networking.k8s.io', 'NetworkPolicy'),
              ('gateway.networking.k8s.io', 'HTTPRoute'), ('gateway.networking.k8s.io', 'BackendTLSPolicy')] if name == APP else
             [('', 'ServiceAccount'), ('', 'Service'), ('', 'ConfigMap'), ('apps', 'Deployment'), ('apps', 'StatefulSet'),
              ('cert-manager.io', 'Issuer'), ('cert-manager.io', 'Certificate'), ('networking.k8s.io', 'NetworkPolicy')])
    return {'sourceRepos': [public['repository']] + ([target['valuesRepository']] if name == APP else []),
        'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-data'}],
        'clusterResourceWhitelist': [{'group': '', 'kind': 'Namespace'}, {'group': 'storage.k8s.io', 'kind': 'StorageClass'}] if name == APP else [],
        'namespaceResourceWhitelist': [{'group': group, 'kind': kind} for group, kind in kinds]}


def authority_path(path, *, missing=False):
    for current in (*reversed(path.parents), path):
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing:
                return None
            raise
        if (info.st_uid != 0 or stat.S_ISLNK(info.st_mode)
                or (current == path and (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600))
                or (current != path and (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022))):
            raise RuntimeError('Data authority receipt has unsafe ownership or permissions')
    return info


def receipt(path, *, missing=False):
    if authority_path(path, missing=missing) is None:
        return {}
    return json.loads(path.read_text())


def project_guard(name, obj, public, target, *, legacy=False, transitioning=False):
    desired = project_spec(name, public, target)
    old = copy.deepcopy(desired)
    if name == APP:
        old['sourceRepos'] = [public['repository']]
        old['namespaceResourceWhitelist'].remove({'group': '', 'kind': 'ConfigMap'})
    allowed = (old, desired) if transitioning else (old,) if legacy else (desired,)
    if (not quiet(obj) or obj.get('spec') not in allowed
            or obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                TRACKING + 'AppProject:argocd/' + name):
        raise RuntimeError('Data project ownership or resource scope changed')


def native_application(obj):
    meta = (obj or {}).get('metadata', {})
    return bool((obj or {}).get('spec', {}).get('sources') or
                meta.get('labels', {}).get('cloudlab.io/owner') == 'data-platform' or
                meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id'))


def quiet(obj):
    meta = (obj or {}).get('metadata', {})
    return bool(obj and meta.get('uid') and not meta.get('deletionTimestamp') and
                not meta.get('ownerReferences') and not meta.get('finalizers') and obj.get('operation') is None and
                str(meta.get('annotations', {}).get('argocd.argoproj.io/skip-reconcile', '')).lower() != 'true' and
                obj.get('status', {}).get('operationState', {}).get('phase') in (None, 'Succeeded'))


def operational_values(app, seaweed):
    sources = app.get('spec', {}).get('sources')
    source = sources[0] if sources else app.get('spec', {}).get('source', {})
    values = source.get('helm', {}).get('valuesObject', {})
    selected = seaweed.get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {}).get('seaweedfs', {})
    flags = {key: values.get(key, False) for key in ('maintenance', 'hibernated')}
    replicas = {key: selected.get(key, {}).get('replicas', 1) for key in COMPONENTS}
    if (any(type(value) is not bool for value in flags.values()) or set(selected) - set(COMPONENTS)
            or any(type(value) is not int or value not in (0, 1) for value in replicas.values())):
        raise RuntimeError('Data operation fields are malformed')
    return dict(flags, seaweedfs=replicas)


def recorded_operation(state, app, seaweed):
    from playbooks.data.files import control
    path = control.BASE / 'cold-maintenance.json'
    if not path.exists():
        return False
    record = receipt(path).get('operation', {})
    actual = operational_values(app, seaweed)
    valid = (isinstance(record, dict) and set(record) == {'applications', 'before', 'requested', 'revisions'}
        and record['applications'] == state.get('applications')
        and all(obj.get('metadata', {}).get('uid') == record['applications'].get(name)
                for obj, name in ((app, APP), (seaweed, SEAWEED)))
        and isinstance(record['revisions'], dict) and set(record['revisions']) == {APP, SEAWEED}
        and all(isinstance(revisions, list) and 1 <= len(revisions) <= 2 and
                all(isinstance(value, str) and re.fullmatch('[a-f0-9]{40}', value) for value in revisions)
                for revisions in record['revisions'].values())
        and json.dumps(actual, sort_keys=True) in (json.dumps(record['before'], sort_keys=True), json.dumps(record['requested'], sort_keys=True)))
    return record if valid else False


def record_operation(apps, name, values):
    from playbooks.data.files import control
    path = control.BASE / 'cold-maintenance.json'
    if not path.exists():
        return
    state = receipt(control.BASE / 'ownership.json')
    before = operational_values(apps[APP], apps[SEAWEED])
    requested = copy.deepcopy(before)
    if name == APP:
        requested.update(values)
    else:
        requested['seaweedfs'].update({key: value['replicas'] for key, value in values['seaweedfs'].items()})
    if any(apps[name]['metadata']['uid'] != state.get('applications', {}).get(name) for name in (APP, SEAWEED)):
        raise RuntimeError('Data operation checkpoint owner changed')
    revisions = {}
    for app_name, obj in apps.items():
        sources = obj['spec'].get('sources')
        pin = obj['spec'].get('source', {}).get('targetRevision') if obj['spec'].get('source') else None
        active = obj.get('operation') or (obj.get('status', {}).get('operationState', {}).get('operation')
            if obj.get('status', {}).get('operationState', {}).get('phase') == 'Running' else None) or {}
        sync = active.get('sync', {})
        selected = ([source['targetRevision'] for source in sources] if sources else [pin] if pin and re.fullmatch('[a-f0-9]{40}', pin)
                    else sync.get('revisions') or [sync.get('revision') or obj.get('status', {}).get('sync', {}).get('revision')])
        if not isinstance(selected, list) or any(not isinstance(value, str) or not re.fullmatch('[a-f0-9]{40}', value) for value in selected):
            raise RuntimeError('Data operation requires each observed immutable source revision')
        revisions[app_name] = selected
    checkpoint = receipt(path)
    checkpoint['operation'] = {'applications': state['applications'], 'before': before, 'requested': requested, 'revisions': revisions}
    control.atomic(path, checkpoint)


def quiet_operation(obj, revisions):
    active = obj.get('operation')
    if active is None and obj.get('status', {}).get('operationState', {}).get('phase') == 'Running':
        active = obj.get('status', {}).get('operationState', {}).get('operation')
    if not isinstance(active, dict):
        return quiet(obj)
    sync = active.get('sync', {})
    if (active.get('initiatedBy', {}).get('automated') is not True
            or not (sync.get('revisions') == revisions or (len(revisions) == 1 and sync.get('revision') == revisions[0]))
            or sync.get('prune') or sync.get('resources')):
        return False
    sanitized = copy.deepcopy(obj)
    sanitized.pop('operation', None)
    sanitized.setdefault('status', {}).setdefault('operationState', {})['phase'] = 'Succeeded'
    return quiet(sanitized)


class PrivateLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ValueError('Private data input must not expand aliases')
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result or key == '<<':
                raise ValueError('Private data input requires unique string keys without merges')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def validate_private_input(path, value):
    if not isinstance(value, dict):
        raise ValueError('Private data input must be an object')
    if path == 'platform/data.yaml':
        required = {'database', 'applicationRole', 'migrationRole', 'backupRole', 'bucket', 'identity'}
        identity = value.get('identity')
        if (set(value) != required or any(not isinstance(value.get(key), str) or not value[key] for key in required - {'identity'})
                or not isinstance(identity, dict) or set(identity) != {'enabled', 'database', 'role'}
                or type(identity.get('enabled')) is not bool
                or any(not isinstance(identity.get(key), str) or not identity[key] for key in ('database', 'role'))):
            raise ValueError('Data profile requires its exact bounded shared identity contract')
    elif path == 'platform/certificates.yaml':
        if (set(value) != {'zone', 'production'} or not isinstance(value.get('zone'), str) or not value['zone']
                or type(value.get('production')) is not bool):
            raise ValueError('Data requires the exact typed private certificate input')
    elif re.fullmatch(r'services/catalog(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?[.](?:json|yaml)', path):
        if (set(value) != {'catalog', 'dataApprovals'} or not isinstance(value.get('catalog'), list)
                or len(value['catalog']) > 20 or not isinstance(value.get('dataApprovals'), dict) or len(value['dataApprovals']) > 40):
            raise ValueError('Data requires the exact bounded catalog input')
        for entry in value['catalog']:
            if (not isinstance(entry, dict) or set(entry) != {'definition', 'approval', 'publication'}
                    or not isinstance(entry['definition'], dict) or not isinstance(entry['definition'].get('data'), dict)
                    or not isinstance(entry['approval'], dict)
                    or any(not isinstance(entry['approval'].get(key), str) for key in ('name', 'namespace'))
                    or entry['publication'] not in ('ready', 'published', 'retired')):
                raise ValueError('Data catalog requires complete typed service entries')
            data = entry['definition']['data']
            if set(data) - {'database', 'bucket'}:
                raise ValueError('Data catalog contains an unsupported request kind')
            for request in data.values():
                if (not isinstance(request, dict) or set(request) != {'name', 'credentialReference', 'retention'}
                        or any(not isinstance(item, str) or not item for item in request.values())
                        or request['retention'] != 'retain'):
                    raise ValueError('Data requests require complete typed retained scopes')
        for approval in value['dataApprovals'].values():
            if not isinstance(approval, dict) or any(not isinstance(item, str) or not item for item in approval.values()):
                raise ValueError('Data approval metadata must contain typed fields')
            required = {'kind', 'service', 'name', 'item'}
            if approval.get('kind') == 'database':
                required.add('migrationItem')
                roles = set(approval) & {'applicationRole', 'migrationRole'}
                if roles and roles != {'applicationRole', 'migrationRole'}:
                    raise ValueError('Data approval role metadata must be paired')
                required |= roles
            elif approval.get('kind') != 'bucket':
                raise ValueError('Data approval kind is unsupported')
            if set(approval) != required:
                raise ValueError('Data approval requires its exact typed metadata')
    else:
        raise ValueError('Unsupported private data input path')
    return value


def private_file(client, repo, revision, path, *, missing=False):
    document = client.request('GET', 'repos/' + repository(repo) + '/contents/' + path + '?ref=' + revision, missing=missing)
    if document is None and missing:
        return None
    if (not isinstance(document, dict) or document.get('type') != 'file' or document.get('encoding') != 'base64'
            or document.get('path') != path or type(document.get('size')) is not int
            or not 0 < document['size'] <= 1024 * 1024 or not isinstance(document.get('content'), str)
            or len(document['content']) > 2 * 1024 * 1024):
        raise RuntimeError('Data source requires a bounded exact regular file')
    try:
        raw = base64.b64decode(document['content'].replace('\n', '').replace('\r', ''), validate=True)
        digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if len(raw) != document['size'] or digest != document.get('sha'):
            raise ValueError()
        result = yaml.load(raw, Loader=PrivateLoader)
        return validate_private_input(path, result)
    except (ValueError, TypeError, yaml.YAMLError):
        raise RuntimeError('Data source content, raw schema or Git blob identity is invalid') from None


def render_objects(files, documents):
    """Use Helm's pinned schema and normalization without importing runner modules."""
    with tempfile.TemporaryDirectory(prefix='cloudlab-data-owner-') as directory:
        root = Path(directory) / 'chart'
        root.mkdir()
        for name, raw in files.items():
            path = root.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        command = ['helm', 'template', APP, str(root), '-n', 'cloudlab-data', '--kube-version', '1.36.5']
        for index, document in enumerate(documents):
            path = Path(directory) / ('input-' + str(index) + '.json')
            path.write_text(json.dumps(document)); path.chmod(0o600)
            command += ['-f', str(path)]
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL, timeout=30,
                env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': directory, 'HELM_PLUGINS': directory + '/plugins', 'HELM_CONFIG_HOME': directory + '/config', 'HELM_CACHE_HOME': directory + '/cache', 'HELM_DATA_HOME': directory + '/data'},
                preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024)))
            if result.returncode or output.tell() > 2 * 1024 * 1024:
                raise RuntimeError('Pinned data chart rejected its authenticated inputs')
            output.seek(0)
            return [obj for obj in yaml.safe_load_all(output) if obj]


def render_settings(files, documents):
    objects = render_objects(files, documents)
    selected = [obj for obj in objects if obj.get('kind') == 'ConfigMap' and obj.get('metadata', {}).get('name') == SETTINGS]
    if len(selected) != 1 or set(selected[0].get('data', {})) != {'settings'}:
        raise RuntimeError('Pinned data chart lacks its unique settings projection')
    return json.loads(selected[0]['data']['settings'])


def reader_spec(repo, name='cloudlab-argocd-identity-source', project='cloudlab-platform'):
    return {'refreshInterval': '24h', 'secretStoreRef': {'name': 'cloudlab', 'kind': 'ClusterSecretStore'},
        'target': {'name': name, 'creationPolicy': 'Owner', 'deletionPolicy': 'Retain',
            'template': {'engineVersion': 'v2', 'mergePolicy': 'Replace',
                'metadata': {'labels': {'argocd.argoproj.io/secret-type': 'repository'}},
                'data': {'type': 'git', 'url': repo, 'project': project,
                    'githubAppID': '{{ .APP_ID }}', 'githubAppInstallationID': '{{ .INSTALLATION_ID }}',
                    'githubAppPrivateKey': PEM_TEMPLATE}}}, 'dataFrom': [{'extract': {'key': 'github-argocd'}}]}


def source_credentials(repo, name='cloudlab-argocd-identity-source', project='cloudlab-platform', *, pending=False):
    external = get('externalsecret.external-secrets.io', name, 'argocd') or {}
    secret = get('secret', name, 'argocd') or {}
    meta = external.get('metadata', {}); owners = secret.get('metadata', {}).get('ownerReferences', [])
    if external and (not meta.get('uid') or (not pending and not condition(external, 'Ready'))
            or meta.get('deletionTimestamp') or meta.get('ownerReferences')
            or meta.get('finalizers', []) not in ([], [ESO_FINALIZER])
            or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                'cloudlab-public-root:external-secrets.io/ExternalSecret:argocd/' + name or external.get('spec') != reader_spec(repo, name, project)):
        raise RuntimeError('Data source credential is not owned by the accepted ready identity source')
    if ((not pending and (not external or not secret)) or (secret and (not external
            or secret.get('metadata', {}).get('deletionTimestamp') or secret.get('metadata', {}).get('finalizers')
            or not secret.get('metadata', {}).get('uid') or len(owners) != 1
            or owners[0].get('uid') != meta.get('uid') or owners[0].get('kind') != 'ExternalSecret'
            or owners[0].get('name') != name or owners[0].get('apiVersion') != 'external-secrets.io/v1'
            or owners[0].get('controller') is not True
            or secret.get('metadata', {}).get('labels', {}).get('argocd.argoproj.io/secret-type') != 'repository'))):
        raise RuntimeError('Data source credential is not owned by the accepted ready identity source')
    data = {key: base64.b64decode(value, validate=True).decode() for key, value in secret.get('data', {}).items()}
    if secret and (set(data) != set(reader_spec(repo, name, project)['target']['template']['data']) or data.get('url') != repo
            or data.get('project') != project or data.get('type') != 'git'
            or not all(data.get(key) for key in ('githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey'))):
        raise RuntimeError('Data source credential fields or repository scope changed')
    credentials = get('secrets', namespace='argocd') or {}
    matches = []
    for obj in credentials.get('items', []):
        if obj.get('metadata', {}).get('labels', {}).get('argocd.argoproj.io/secret-type') != 'repository':
            continue
        decoded = {key: base64.b64decode(obj.get('data', {}).get(key, ''), validate=True).decode() for key in ('url', 'project')}
        if decoded == {'url': repo, 'project': project}:
            matches.append(obj)
    if (len(matches) != (1 if secret else 0) or (secret and
            matches[0].get('metadata', {}).get('uid') != secret.get('metadata', {}).get('uid'))):
        raise RuntimeError('Data source has duplicate or changed repository credentials')
    if not secret:
        return None
    return dict(zip(('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'),
                    (data['githubAppID'], data['githubAppInstallationID'], data['githubAppPrivateKey'])))


def authenticated_inputs(repo, revision, deadline):
    credentials = source_credentials(repo)
    api = GitHub(app_token(credentials), deadline=deadline, max_response=3 * 1024 * 1024)
    path = 'app/installations/' + credentials['INSTALLATION_ID']
    verify_installation(api.request('GET', path), credentials['APP_ID'])
    token = api.request('POST', path + '/access_tokens', {
        'repositories': [repository(repo).split('/')[1]], 'permissions': {'contents': 'read'}})['token']
    client = GitHub(token, deadline=deadline, max_response=3 * 1024 * 1024)
    try:
        actual = client.request('GET', 'repos/' + repository(repo))
        if (actual.get('full_name', '').lower() != repository(repo).lower() or actual.get('private') is not True
                or actual.get('fork') or actual.get('archived') or actual.get('disabled') or actual.get('default_branch') != 'main'):
            raise RuntimeError('Data source repository identity changed')
        return [private_file(client, repo, revision, path) for path in VALUE_FILES]
    finally:
        # Revocation has its own bounded deadline, including acquisition timeout.
        client.deadline = time.monotonic() + 15
        client.request('DELETE', 'installation/token')


def published_source(state, *, deadline):
    coordinates = state.get('publicSource')
    if not isinstance(coordinates, dict) or set(coordinates) != {'repository', 'branch'} or coordinates['branch'] != 'main':
        raise RuntimeError('Data public owner coordinates require trusted published-input attestation')
    repo = repository(coordinates['repository'])
    branch = source_snapshot.request('repos/' + repo + '/branches/main', deadline)
    revision = branch.get('commit', {}).get('sha')
    if branch.get('protected') is not True or not re.fullmatch('[a-f0-9]{40}', revision or ''):
        raise RuntimeError('Data public owner requires its protected main branch')
    raw = source_snapshot.read_url('https://raw.githubusercontent.com/' + repo + '/' + revision + '/gitops/roots/public/values.yaml', deadline, 65536)
    public = yaml.safe_load(raw)
    if not isinstance(public, dict) or public.get('repository') != coordinates['repository'] or public.get('revision') != 'main':
        raise RuntimeError('Data public coordinates differ from committed root settings')
    return public, revision


def root_guard(state, public, revision, *, recovery=False, preparation=False):
    binding = receipt(BINDING)
    if (not isinstance(binding, dict) or binding.get('phase') != 'accepted'
            or set(binding) != {'phase', 'target', 'root_uid', 'project_uid', 'controller_uid'}):
        raise RuntimeError('Data requires the accepted identity binding')
    objects = {}
    for key, kind, name in (('root_uid', 'application.argoproj.io', 'cloudlab-public-root'),
                           ('project_uid', 'appproject.argoproj.io', 'cloudlab-root'),
                           ('controller_uid', 'statefulset', 'argocd-application-controller')):
        obj = get(kind, name, 'argocd') or {}
        if obj.get('metadata', {}).get('uid') != binding[key] or obj.get('metadata', {}).get('deletionTimestamp'):
            raise RuntimeError('Data accepted root, controller or project identity changed')
        objects[key] = obj
    project = objects['project_uid']
    if project.get('spec', {}).get('namespaceResourceWhitelist') != identity_project_rules(project):
        raise RuntimeError('Data accepted root project private source grant changed')
    root = objects['root_uid']; spec = root.get('spec', {}); source = spec.get('source', {})
    helm = source.get('helm', {}); overrides = helm.get('valuesObject', {})
    if (not quiet(root) or spec.get('project') != 'cloudlab-root' or spec.get('sources')
            or source.get('repoURL') != state['publicSource']['repository'] or source.get('targetRevision') != 'main'
            or source.get('path') != 'gitops/roots/public' or set(helm) - {'releaseName', 'valuesObject'}
            or helm.get('releaseName') != 'cloudlab-public-root' or not isinstance(overrides, dict)
            or objects['controller_uid'].get('spec', {}).get('replicas') != 1
            or objects['project_uid'].get('spec', {}).get('sourceRepos') != [public['repository']]
            or not matches_revision(root, revision) or root.get('status', {}).get('sync', {}).get('status') != 'Synced'
            or (not recovery and root.get('status', {}).get('health', {}).get('status') != 'Healthy')
            or root.get('status', {}).get('sync', {}).get('comparedTo', {}).get('source') != source
            or spec.get('ignoreDifferences', []) != ([] if preparation and not public['data']['configuration']['enabled'] else delegations())
            or spec.get('syncPolicy', {}).get('syncOptions') !=
                (['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'] +
                 ([] if preparation and not public['data']['configuration']['enabled'] else ['RespectIgnoreDifferences=true']))
            or any(c.get('type', '').endswith('Error') for c in root.get('status', {}).get('conditions', []))):
        raise RuntimeError('Data public root has not converged at its independently resolved revision')
    def compatible(actual, expected):
        return (isinstance(expected, dict) and all(key in expected and compatible(value, expected[key]) for key, value in actual.items())
                if isinstance(actual, dict) else type(actual) is type(expected) and actual == expected)
    approved = copy.deepcopy(public)
    approved['identity']['argo'] = binding['target']
    if not compatible(overrides, approved) or overrides.get('identity', {}).get('argo') != binding['target']:
        raise RuntimeError('Data public root override conflicts with committed settings or accepted binding')
    target = binding['target']
    repository(target.get('valuesRepository'))
    if (target['valuesRepository'].lower() == public['repository'].lower()
            or repository(target['valuesRepository']).split('/')[0].lower() != repository(public['repository']).split('/')[0].lower()
            or not re.fullmatch('[a-f0-9]{40}', target.get('valuesRevision') or '')):
        raise RuntimeError('Data private binding has foreign or mutable coordinates')
    return target


def legacy_guard(state, app, seaweed, *, recovery=False):
    from playbooks.data.files import control
    if state.get('settings_uid'):
        raise RuntimeError('Registered native data ownership cannot downgrade to legacy settings')
    coordinates = state.get('publicSource')
    recorded = recovery and recorded_operation(state, app, seaweed)
    source_repo = None
    for obj, name, path in ((app, APP, 'configuration'), (seaweed, SEAWEED, 'seaweedfs')):
        meta = obj.get('metadata', {}); spec = obj.get('spec', {}); source = spec.get('source', {})
        helm = source.get('helm', {})
        idle = quiet_operation(obj, recorded['revisions'][name]) if recorded else quiet(obj)
        if (not idle or meta.get('uid') != state.get('applications', {}).get(name)
                or meta.get('labels', {}).get('cloudlab.io/owner') != control.OWNER or native_application(obj)
                or set(spec) != {'project', 'source', 'destination', 'syncPolicy'} or spec.get('project') != name
                or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-data'}
                or set(source) != {'repoURL', 'targetRevision', 'path', 'helm'} or source.get('targetRevision') != 'main'
                or source.get('path') != 'platform/data/' + path or set(helm) != {'releaseName', 'valuesObject'}
                or helm.get('releaseName') != name or not isinstance(helm.get('valuesObject'), dict)
                or (coordinates is not None and coordinates != {'repository': source.get('repoURL'), 'branch': 'main'})
                or spec.get('syncPolicy') != {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                    'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'],
                    'retry': {'limit': 5, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '1m'}}}):
            raise RuntimeError('Data legacy identity, ownership or source changed')
        repository(source['repoURL'])
        if source_repo is not None and source_repo != source['repoURL']:
            raise RuntimeError('Data legacy owners disagree on their public source')
        source_repo = source['repoURL']


def operation(*, recovery=False, read=None):
    from playbooks.data.files import control
    read = get if read is None else read
    app = read('application.argoproj.io', APP, 'argocd') or {}
    seaweed = read('application.argoproj.io', SEAWEED, 'argocd') or {}
    state = receipt(control.BASE / 'ownership.json')
    if not native_application(app) and not native_application(seaweed):
        legacy_guard(state, app, seaweed, recovery=recovery)
        from playbooks.data.files.handoff import legacy_scope
        legacy_scope(state, app, seaweed)
        return False
    if not native_application(app) or not native_application(seaweed):
        raise RuntimeError('Data source ownership is an unsupported legacy/native hybrid')
    snapshot = projection(state, recovery=recovery)
    if recovery and recorded_operation(state, app, seaweed):
        snapshot.pending.update((APP, SEAWEED))
    snapshot.observe(initial=True, recovery=recovery)
    snapshot.settings()
    return snapshot


def projection(state, *, recovery=False, preparation=False):
    """Acquire authenticated inputs; this alone never authorizes a settings read."""
    deadline = time.monotonic() + 120
    public, revision = published_source(state, deadline=deadline)
    config = public.get('data', {}).get('configuration', {})
    if public.get('data', {}).get('enabled') is not True or (not preparation and config.get('enabled') is not True):
        raise RuntimeError('Native data consumer conflicts with its independently disabled owner')
    target = root_guard(state, public, revision, recovery=recovery, preparation=preparation)
    files = source_snapshot.chart_files({'repository': public['repository'], 'revision': config['revision'],
                                        'path': 'platform/data/configuration'}, deadline=deadline)
    documents = authenticated_inputs(target['valuesRepository'], target['valuesRevision'], deadline)
    expected = render_settings(files, documents + [{'sharedInputs': True, 'maintenance': False, 'hibernated': False}])
    if time.monotonic() >= deadline:
        raise RuntimeError('Data source acquisition exceeded its total deadline')
    return Observation(state, public, revision, target, expected)


def application_sources(name, public, target, flags, replicas):
    config = public['data']['configuration']
    if name == APP:
        return {'source': None, 'sources': [
            {'repoURL': public['repository'], 'targetRevision': config['revision'], 'path': 'platform/data/configuration',
             'helm': {'releaseName': APP, 'valueFiles': ['$values/' + path for path in VALUE_FILES],
                      'valuesObject': dict(sharedInputs=True, **flags)}},
            {'repoURL': target['valuesRepository'], 'targetRevision': target['valuesRevision'], 'ref': 'values'}]}
    return {'source': {'repoURL': public['repository'], 'targetRevision': config['seaweedfsRevision'],
        'path': 'platform/data/seaweedfs', 'helm': {'releaseName': SEAWEED,
        'valuesObject': {'seaweedfs': {c: {'replicas': replicas[c]} for c in COMPONENTS}}}}}


class Observation:
    def __init__(self, state, public, revision, target, expected):
        self.state, self.public, self.revision, self.target = state, public, revision, target
        self.expected = copy.deepcopy(expected)
        self.flags = {'maintenance': False, 'hibernated': False}
        self.replicas = {name: 1 for name in COMPONENTS}
        self.previous_settings = None
        self.pending = set()

    def observe(self, *, initial=False, recovery=False):
        observed = {}
        config = self.public['data']['configuration']
        for name, pin in ((APP, config['revision']), (SEAWEED, config['seaweedfsRevision'])):
            obj = get('application.argoproj.io', name, 'argocd') or {}
            observed[name] = obj
            meta = obj.get('metadata', {}); spec = obj.get('spec', {})
            revisions = [pin, self.target['valuesRevision']] if name == APP else [pin]
            idle = quiet_operation(obj, revisions) if name in self.pending else quiet(obj)
            if (set(spec) - {'project', 'source', 'sources', 'destination', 'syncPolicy'} or not idle or meta.get('uid') != self.state.get('applications', {}).get(name)
                    or meta.get('labels', {}).get('cloudlab.io/owner') != 'data-platform'
                    or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') != TRACKING + 'Application:argocd/' + name
                    or spec.get('project') != name
                    or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-data'}
                    or spec.get('syncPolicy') != {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                        'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'],
                        'retry': {'limit': 5, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '1m'}}}):
                raise RuntimeError('Data native Application identity or ownership changed')
            if name == APP:
                values = (spec.get('sources') or [{}])[0].get('helm', {}).get('valuesObject', {})
                if initial:
                    if set(values) != {'sharedInputs', 'maintenance', 'hibernated'} or values.get('sharedInputs') is not True or any(type(values.get(k)) is not bool for k in self.flags):
                        raise RuntimeError('Data operational settings are malformed')
                    self.flags = {key: values[key] for key in self.flags}
                    self.expected.update(self.flags)
                expected_sources = application_sources(name, self.public, self.target, self.flags, self.replicas)
                valid = spec.get('source') is None and spec.get('sources') == expected_sources['sources']
            else:
                values = spec.get('source', {}).get('helm', {}).get('valuesObject', {})
                if initial:
                    selected = values.get('seaweedfs', {})
                    if set(values) != {'seaweedfs'} or set(selected) != set(COMPONENTS) or any(
                            set(selected[c]) != {'replicas'} or type(selected[c]['replicas']) is not int or selected[c]['replicas'] not in (0, 1) for c in COMPONENTS):
                        raise RuntimeError('Data operational replica settings are malformed')
                    self.replicas = {c: selected[c]['replicas'] for c in COMPONENTS}
                valid = not spec.get('sources') and spec.get('source') == application_sources(
                    name, self.public, self.target, self.flags, self.replicas)['source']
            if not valid:
                raise RuntimeError('Data native source differs from its independently committed owner')
            project = get('appproject.argoproj.io', name, 'argocd') or {}
            project_guard(name, project, self.public, self.target)
            if initial and (not matches_revision(obj, pin) or (name not in self.pending and obj.get('status', {}).get('sync', {}).get('status') != 'Synced')
                    or (not recovery and obj.get('status', {}).get('health', {}).get('status') != 'Healthy')):
                raise RuntimeError('Data native source has not converged')
        return observed

    def settings(self, *, lag=False):
        source_credentials(self.target['valuesRepository'], APP + '-source', APP)
        root_guard(self.state, self.public, self.revision, recovery=self.flags["hibernated"] or bool(self.pending))
        self.observe()
        return self._settings(self.state.get('settings_uid'), lag=lag)

    def _settings(self, uid, *, lag=False):
        obj = get('configmap', SETTINGS, 'cloudlab-data') or {}; meta = obj.get('metadata', {})
        if (not uid or meta.get('uid') != uid
                or meta.get('deletionTimestamp') or meta.get('ownerReferences') or meta.get('finalizers')
                or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') != APP + ':/ConfigMap:cloudlab-data/' + SETTINGS
                or set(obj.get('data', {})) != {'settings'} or obj.get('binaryData')):
            raise RuntimeError('Data settings require their explicitly registered native identity and tracking')
        value = json.loads(obj['data']['settings'])
        # JSON equality must preserve boolean/number types as well as every field.
        canonical = lambda content: json.dumps(content, sort_keys=True, separators=(',', ':'))
        if canonical(value) != canonical(self.expected):
            if lag and self.previous_settings is not None and canonical(value) == canonical(self.previous_settings):
                return None
            raise RuntimeError('Data settings content differs from authenticated pinned Helm inputs')
        return copy.deepcopy(value)

    def patch(self, name, values):
        self.settings()
        apps = self.observe()
        obj = apps[name]
        if name == APP and values and set(values) <= set(self.flags) and all(type(v) is bool for v in values.values()):
            path = '/spec/sources/0/helm/valuesObject'
            desired = dict(self.flags, **{'sharedInputs': True}) | values
        elif name == SEAWEED and set(values) == {'seaweedfs'} and values['seaweedfs'] and set(values['seaweedfs']) <= set(COMPONENTS):
            selected = values['seaweedfs']
            if any(set(v) != {'replicas'} or type(v['replicas']) is not int or v['replicas'] not in (0, 1) for v in selected.values()):
                raise RuntimeError('Data operation exceeds its replica delegation')
            path = '/spec/source/helm/valuesObject'
            desired = {'seaweedfs': {c: {'replicas': selected.get(c, {}).get('replicas', self.replicas[c])} for c in COMPONENTS}}
        else:
            raise RuntimeError('Data operation exceeds its six delegated fields')
        record_operation(apps, name, values)
        kube('patch', 'application.argoproj.io', name, '-n', 'argocd', '--type=json', '--field-manager=cloudlab-data-bootstrap',
            '-p', json.dumps([{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': obj['metadata']['resourceVersion']},
                {'op': 'test', 'path': '/spec', 'value': obj['spec']}, {'op': 'replace', 'path': path, 'value': desired}]))
        self.pending.add(name)
        if name == APP:
            self.previous_settings = copy.deepcopy(self.expected)
            self.flags.update(values); self.expected.update(values)
            wait(lambda: self.settings(lag=True), 'authenticated data operational settings convergence')
            self.previous_settings = None
        else:
            self.replicas = {c: desired['seaweedfs'][c]['replicas'] for c in COMPONENTS}
            self.observe()


def prerequisite(payload, *, recovery=None):
    from playbooks.data.files import control
    if recovery is not None:
        from playbooks.argocd.files.data_activation import guard
        checkpoint = recovery.get('checkpoint', {})
        target = checkpoint.get('target')
        root = get('application.argoproj.io', 'cloudlab-public-root', 'argocd')
        def read(kind, name):
            return get(kind, name, 'argocd')
        evidence = guard(checkpoint.get('dataActivation'), target, read, root,
                         patched=recovery.get('sourceState') == 'patched')
        return evidence['settings'] if evidence['settings'] is not None else control.settings(False)
    source = operation()
    if source:
        return source.settings()
    from playbooks.istio.files.kube import application_ready
    if not application_ready(APP, payload['revision']):
        raise RuntimeError('Identity prerequisite data Application is not converged')
    return control.settings(False)
