"""Authenticated Harbor installation ownership; no routine Application writer."""
import base64
import copy
import fcntl
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import ipaddress
import json
import importlib.util
import io
import marshal
from pathlib import Path
import re
import os
import stat
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from playbooks.data.files import native as source
from playbooks.istio.files.kube import application_ready, get

REVISION = 'd3d639cf80e8cfecebeb756d666a24db92a6bb74'
PUBLIC = 'https://github.com/UncleThreeHomeLab/yasai-cloudlab.git'
NAMESPACE, OWNER = 'cloudlab-harbor', 'harbor-platform'
SECRETS = ('harbor-emergency', 'harbor-database', 'harbor-runtime', 'harbor-token-signing', 'harbor-oidc',
           'harbor-browser-key', 'harbor-browser-oidc', 'harbor-recovery-verifier')
BASE = Path('/var/lib/cloudlab/harbor')
LOCK = Path('/run/lock/cloudlab-harbor.lock')
RUNTIME = Path('/opt/cloudlab/playbooks/harbor/files')
RETIRED_BOOTSTRAP_SHA256 = 'c4fd117b7dc6aa194b0fd002070a685280d7e3536ec312a48aaeac6b8cd7ea90'
RECORD = 'native-ownership.json'
APPS = ('cloudlab-harbor', 'cloudlab-harbor-configuration')
READER = 'cloudlab-harbor-installation-source'
REPLICAS = [('harbor', name, 'replicas') for name in ('nginx', 'portal', 'core', 'jobservice', 'registry')] + [
    ('harbor', name, 'internal', 'replicas') for name in ('database', 'redis')]
ACTIVE = ContextVar('harbor_native_operation', default=None)


def same(actual, expected):
    try:
        return json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError):
        return False


def security_fields(obj):
    return {**{key: obj.get(key) for key in ('spec', 'data', 'type')},
        **{key: obj.get('metadata', {}).get(key) for key in ('uid', 'ownerReferences', 'finalizers', 'deletionTimestamp', 'labels', 'annotations')}}


def profile(document):
    if (not isinstance(document, dict) or set(document) != {'installationRevision', 'harborHost', 'loginHost', 'gatewayIP'}
            or any(not isinstance(value, str) for value in document.values()) or document['installationRevision'] != REVISION
            or not document['loginHost'].startswith('login.')
            or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', document['loginHost'])
            or len(document['loginHost']) > 240 or document['harborHost'] != 'harbor.internal.' + document['loginHost'][6:]):
        raise RuntimeError('Harbor installation profile refused')
    try:
        address = ipaddress.IPv4Address(document['gatewayIP'])
        if str(address) != document['gatewayIP'] or not any(address in ipaddress.IPv4Network(network)
                for network in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
            raise ValueError()
    except ValueError:
        raise RuntimeError('Harbor installation requires a canonical private IPv4 gateway') from None
    return copy.deepcopy(document)


def values(document, name):
    document = profile(document)
    if name == APPS[1]:
        return dict(enabled=True, maintenance=False, **{key: document[key] for key in ('harborHost', 'loginHost', 'gatewayIP')})
    if name != APPS[0]: raise RuntimeError('Unknown Harbor installation Application')
    result = {'harbor': {'externalURL': 'https://' + document['harborHost'], 'core': {
        'hostAliases': [{'ip': document['gatewayIP'], 'hostnames': [document['loginHost']]}]}}}
    for path in REPLICAS:
        cursor = result
        for key in path[:-1]: cursor = cursor.setdefault(key, {})
        cursor[path[-1]] = 1
    return result


def paths(name):
    if name not in APPS: raise RuntimeError('Unknown Harbor operational scope')
    return [('maintenance',)] if name == APPS[1] else REPLICAS


def normalize(name, actual, document, charts):
    """Recognize only native overlays or historical complete R defaults."""
    if not isinstance(actual, dict): raise RuntimeError('Harbor installation values must be an object')
    expected = values(document, name)
    for path in paths(name):
        cursor = actual
        for key in path[:-1]: cursor = cursor.get(key, {}) if isinstance(cursor, dict) else {}
        flag = cursor.get(path[-1], False if name == APPS[1] else 1) if isinstance(cursor, dict) else None
        if (name == APPS[1] and type(flag) is not bool) or (name == APPS[0] and (type(flag) is not int or flag not in (0, 1))):
            raise RuntimeError('Harbor operational fields require bounded typed values')
        cursor = expected
        for key in path[:-1]: cursor = cursor[key]
        cursor[path[-1]] = flag
    historical = copy.deepcopy(expected)
    if name == APPS[0]:
        historical = json.loads(charts[name]['values.json'])
        historical['harbor']['externalURL'] = expected['harbor']['externalURL']
        historical['harbor']['core']['hostAliases'] = expected['harbor']['core']['hostAliases']
        for path in REPLICAS:
            cursor, value = historical, expected
            for key in path[:-1]: cursor, value = cursor[key], value[key]
            cursor[path[-1]] = value[path[-1]]
    else:
        historical.pop('maintenance')
    if not same(actual, expected) and not same(actual, historical):
        raise RuntimeError('Harbor immutable installation values differ from authenticated R defaults')
    return expected


def read_profiles(targets, credentials, deadline):
    if not isinstance(targets, list) or not 1 <= len(targets) <= 2:
        raise RuntimeError('Harbor source reads require one accepted or two recorded revisions')
    repo = targets[0]['valuesRepository']
    if any(target['valuesRepository'] != repo or not re.fullmatch('[a-f0-9]{40}', target['valuesRevision']) for target in targets):
        raise RuntimeError('Harbor requires recorded immutable sources in one repository')
    work_deadline = deadline - 15
    if time.monotonic() >= work_deadline: raise RuntimeError('Harbor source budget cannot reserve token revocation')
    api = source.GitHub(source.app_token(credentials), deadline=work_deadline, max_response=3 * 1024 * 1024)
    installation = 'app/installations/' + credentials['INSTALLATION_ID']
    source.verify_installation(api.request('GET', installation), credentials['APP_ID'])
    token = api.request('POST', installation + '/access_tokens', {
        'repositories': [source.repository(repo).split('/')[1]], 'permissions': {'contents': 'read'}})['token']
    client = source.GitHub(token, deadline=work_deadline, max_response=3 * 1024 * 1024)
    profiles = []
    try:
        actual = client.request('GET', 'repos/' + source.repository(repo))
        if (actual.get('full_name', '').lower() != source.repository(repo).lower() or actual.get('private') is not True
                or actual.get('fork') or actual.get('archived') or actual.get('disabled') or actual.get('default_branch') != 'main'):
            raise RuntimeError('Harbor private repository identity changed')
        for revision in dict.fromkeys(target['valuesRevision'] for target in targets):
            path = 'platform/harbor.yaml'
            document = client.request('GET', 'repos/' + source.repository(repo) + '/contents/' + path + '?ref=' + revision)
            if (not isinstance(document, dict) or document.get('type') != 'file' or document.get('path') != path
                    or document.get('encoding') != 'base64' or type(document.get('size')) is not int
                    or not 0 < document['size'] <= 65536 or not isinstance(document.get('content'), str) or len(document['content']) > 128 * 1024):
                raise RuntimeError('Harbor requires its bounded exact private profile')
            try:
                raw = base64.b64decode(document['content'].replace('\r', '').replace('\n', ''), validate=True)
                if (len(raw) != document['size'] or hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != document.get('sha')):
                    raise ValueError()
                profiles.append(profile(source.yaml.load(raw, Loader=source.PrivateLoader)))
            except (ValueError, TypeError, source.yaml.YAMLError):
                raise RuntimeError('Harbor private profile content or Git identity refused') from None
    finally:
        client.deadline = min(deadline, time.monotonic() + 15)
        if client.request('DELETE', 'installation/token') is not None:
            raise RuntimeError('Harbor source token revocation was not acknowledged')
    if any(document != profiles[0] for document in profiles):
        raise RuntimeError('Pending binding changes the Harbor installation profile')
    return profiles[0]


def context(*, preparing=False, recovery=None, deadline=None):
    from playbooks.argocd.files.source_transition import pending_root_context
    deadline = min(time.monotonic() + 180, deadline) if deadline is not None else time.monotonic() + 180
    coordinates = {'publicSource': {'repository': PUBLIC, 'branch': 'main'}}
    public, head = source.published_source(coordinates, deadline=deadline)
    enabled = public.get('harbor', {}).get('installation', {}).get('enabled')
    if type(enabled) is not bool: raise RuntimeError('Harbor requires explicit public installation intent')
    if not enabled and not preparing: return None
    if public.get('harbor', {}).get('enabled') is not True: raise RuntimeError('Harbor installation is disabled')
    if recovery is None:
        targets = [source.root_guard(coordinates, public, head)]
        root = get('application.argoproj.io', 'cloudlab-public-root', 'argocd') or {}
        binding = source.receipt(source.BINDING)
    else:
        root, targets = pending_root_context(recovery, public)
        binding = recovery['checkpoint']
    root_files = source.source_snapshot.chart_files({'repository': PUBLIC, 'revision': head, 'path': 'gitops/roots/public'}, deadline=deadline)
    contracts = []
    for target in targets:
        settings = copy.deepcopy(public); settings['identity']['argo'] = target
        settings['harbor']['installation']['enabled'] = True
        objects = source.render_objects(root_files, [settings])
        desired = {(obj['kind'], obj['metadata']['name']): obj for obj in objects
            if (obj['kind'], obj.get('metadata', {}).get('name')) in (
                ('ApplicationSet', APPS[0]), ('ApplicationSet', APPS[1]), ('AppProject', APPS[0]), ('ExternalSecret', READER))}
        if len(desired) != 4: raise RuntimeError('Authenticated Root lacks the complete Harbor contract')
        contracts.append(desired)
    state = receipt()
    if enabled and state.get('phase') == 'accepted':
        if (state.get('root_uid') != root.get('metadata', {}).get('uid')
                or any((get(kind, READER, 'argocd') or {}).get('metadata', {}).get('uid') != state.get(key)
                    for kind, key in (('externalsecret.external-secrets.io', 'reader_uid'), ('secret', 'secret_uid')))):
            raise RuntimeError('Harbor registered source was replaced before credential issuance')
    credentials = source.source_credentials(targets[0]['valuesRepository'], *((READER, APPS[0]) if enabled else ()))
    document = read_profiles(targets, credentials, deadline)
    charts = {name: source.source_snapshot.chart_files({'repository': PUBLIC, 'revision': REVISION,
        'path': 'platform/harbor' + ('/server' if name == APPS[0] else '')}, deadline=deadline,
        require_schema=False, comparison_defaults='values.json' if name == APPS[0] else 'values.yaml') for name in APPS}
    if recovery is not None: pending_root_context(recovery, public)
    if time.monotonic() >= deadline: raise RuntimeError('Harbor source acquisition exceeded its budget')
    return {'public': public, 'head': head, 'root': root, 'targets': targets, 'contracts': contracts, 'recovery': recovery,
        'authority': {key: binding[key] for key in ('root_uid', 'controller_uid', 'project_uid')},
        'profile': document, 'charts': charts, 'enabled': enabled}


def receipt():
    return source.receipt(BASE / RECORD, missing=True)


def safe_absence(*, recorded=False):
    for name in APPS:
        if any(get(kind, name, 'argocd') for kind in ('application.argoproj.io', 'applicationset.argoproj.io')):
            raise RuntimeError('Fresh Harbor intent refuses existing installation owners')
    for kind, name, namespace in [('namespace', NAMESPACE, None), ('storageclass', NAMESPACE, None),
            ('externalsecret.external-secrets.io', READER, 'argocd'), ('secret', READER, 'argocd')]:
        if get(kind, name, namespace): raise RuntimeError('Fresh Harbor intent refuses existing boundaries or reader')
    for name in ('harbor-registry', 'harbor-database', 'harbor-redis'):
        if get('pvc', name, NAMESPACE): raise RuntimeError('Fresh Harbor intent refuses existing storage')
    for name in SECRETS:
        if any(get(kind, name, NAMESPACE) for kind in ('secret', 'externalsecret.external-secrets.io')):
            raise RuntimeError('Fresh Harbor intent refuses existing credentials')
    for kind, namespace in (('pv', None), ('volumes.longhorn.io', 'longhorn-system')):
        entries = (get(kind, namespace=namespace) or {}).get('items')
        if not isinstance(entries, list) or len(entries) > 10000: raise RuntimeError('Harbor storage discovery is incomplete')
        for obj in entries:
            claim = obj.get('spec', {}).get('claimRef', {}) if kind == 'pv' else obj.get('status', {}).get('kubernetesStatus', {})
            if (claim.get('namespace') == NAMESPACE or claim.get('pvcName') in ('harbor-registry', 'harbor-database', 'harbor-redis')
                    or obj.get('spec', {}).get('storageClassName') == NAMESPACE):
                raise RuntimeError('Fresh Harbor intent refuses retained storage references')
    if any(path.name != RECORD or not recorded for path in BASE.iterdir()):
        raise RuntimeError('Fresh Harbor intent refuses existing operation or ownership files')


def expected_app(snapshot, name):
    if name not in APPS: raise RuntimeError('Unknown Harbor installation Application')
    templates = [declaration[('ApplicationSet', name)]['spec']['template'] for declaration in snapshot['contracts']]
    template = copy.deepcopy(templates[0])
    if any(not same(template, candidate) for candidate in templates):
        raise RuntimeError('Recorded Harbor parents disagree on the fixed installation contract')
    spec = template.get('spec', {})
    source_spec = {'repoURL': PUBLIC, 'targetRevision': REVISION,
        'path': 'platform/harbor' + ('/server' if name == APPS[0] else ''), 'helm': {'releaseName': APPS[0]}}
    if name == APPS[0]: source_spec['helm']['valueFiles'] = ['values.json']
    policy = {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
        'syncOptions': ['FailOnSharedResource=true', 'ServerSideApply=true', 'DisableClientSideApplyMigration=true'],
        'retry': {'limit': 5, 'backoff': {'duration': '10s', 'factor': 2, 'maxDuration': '1m'}}}
    metadata = template.get('metadata', {})
    if (set(spec) != {'project', 'source', 'destination', 'syncPolicy'} or spec.get('project') != APPS[0]
            or not same(spec.get('source'), source_spec) or not same(spec.get('syncPolicy'), policy)
            or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE}
            or metadata.get('name') != name or metadata.get('namespace') != 'argocd'
            or metadata.get('labels', {}).get('cloudlab.io/owner') != OWNER
            or metadata.get('ownerReferences') or metadata.get('finalizers')):
        raise RuntimeError('Authenticated Harbor template exceeds its fixed installation scope')
    spec['source']['helm']['valuesObject'] = values(snapshot['profile'], name)
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': metadata, 'spec': spec}

def child(snapshot, name, *, accepted=None):
    app = get('application.argoproj.io', name, 'argocd') or {}
    if not app: raise RuntimeError('Harbor accepted Application is missing')
    actual = copy.deepcopy(app.get('spec', {}))
    normalized = normalize(name, actual.get('source', {}).get('helm', {}).get('valuesObject'), snapshot['profile'], snapshot['charts'])
    actual.setdefault('source', {}).setdefault('helm', {})['valuesObject'] = values(snapshot['profile'], name)
    if (not same(actual, expected_app(snapshot, name)['spec']) or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
            or app['metadata'].get('deletionTimestamp') or app['metadata'].get('finalizers')
            or accepted is not None and app['metadata'].get('uid') != accepted):
        raise RuntimeError('Harbor installation source, scope or identity changed')
    return app, normalized


def observe(snapshot, state, *, register=False):
    from playbooks.harbor.files.recovery import atomic
    fields = {'version', 'phase', 'root_uid', 'authority', 'project_uid', 'profile', 'revision', 'repository', 'applications'}
    if state.get('phase') == 'accepted': fields |= {'parents', 'reader_uid', 'secret_uid'}
    if snapshot['recovery'] is None:
        coordinates = {'publicSource': {'repository': PUBLIC, 'branch': 'main'}}
        if source.root_guard(coordinates, snapshot['public'], snapshot['head']) != snapshot['targets'][0]:
            raise RuntimeError('Harbor accepted private binding changed during operation')
        binding = source.receipt(source.BINDING)
    else:
        from playbooks.argocd.files.source_transition import pending_root_context
        pending_root_context(snapshot['recovery'], snapshot['public'])
        binding = snapshot['recovery']['checkpoint']
    if (set(state) != fields or state.get('version') != 'cloudlab-harbor-native/v1' or state.get('phase') not in ('initial', 'prepared', 'accepted')
            or state.get('root_uid') != snapshot['root'].get('metadata', {}).get('uid')
            or state.get('authority') != snapshot['authority']
            or snapshot['authority'] != {key: binding.get(key) for key in ('root_uid', 'controller_uid', 'project_uid')}
            or state.get('profile') != snapshot['profile'] or state.get('revision') != REVISION
            or state.get('repository') != snapshot['targets'][0]['valuesRepository']):
        raise RuntimeError('Harbor native ownership intent changed or is missing')
    applications = state.get('applications')
    if (not isinstance(applications, dict) or set(applications) != (set() if state['phase'] == 'initial' else set(APPS))
            or any(not isinstance(uid, str) or not uid for uid in applications.values())):
        raise RuntimeError('Harbor native intent has incomplete Application identities')
    desired = snapshot['contracts'][-1]
    project = get('appproject.argoproj.io', APPS[0], 'argocd') or {}
    if (not source.quiet(project) or project.get('metadata', {}).get('uid') != state['project_uid']
            or not same(project.get('spec'), desired[('AppProject', APPS[0])]['spec'])
            or project['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != 'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APPS[0]):
        raise RuntimeError('Harbor project was replaced or broadened')
    observed = {}; applications = {}; changed = False
    for name in APPS:
        parent = get('applicationset.argoproj.io', name, 'argocd') or {}
        if (not source.quiet(parent) or not any(same(parent.get('spec'), candidate[('ApplicationSet', name)]['spec']) for candidate in snapshot['contracts'])
                or parent['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + name
                or not source.condition(parent, 'ParametersGenerated') or source.condition(parent, 'ErrorOccurred')):
            raise RuntimeError('Harbor native parent contract or readiness changed')
        app, operational = child(snapshot, name, accepted=state.get('applications', {}).get(name))
        if register and state['phase'] != 'accepted' and operational != values(snapshot['profile'], name):
            raise RuntimeError('Harbor registration must preserve its idle installation fields')
        if app['metadata'].get('ownerReferences') != [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet',
                'name': name, 'uid': parent['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}]:
            raise RuntimeError('Harbor child has another controller owner')
        observed[name] = parent['metadata']['uid']; applications[name] = app['metadata']['uid']
    before = {kind: copy.deepcopy(get(kind, READER, 'argocd') or {}) for kind in ('externalsecret.external-secrets.io', 'secret')}
    source.source_credentials(state['repository'], READER, APPS[0])
    if any(not same(security_fields(before[kind]), security_fields(get(kind, READER, 'argocd') or {})) for kind in before):
        raise RuntimeError('Harbor source credential changed during authentication')
    identities = {'parents': observed, 'reader_uid': before['externalsecret.external-secrets.io'].get('metadata', {}).get('uid'),
        'secret_uid': before['secret'].get('metadata', {}).get('uid')}
    if state['phase'] == 'accepted':
        if any(state.get(key) != value for key, value in identities.items()): raise RuntimeError('Harbor registered native owner was replaced')
    elif register:
        if not all(application_ready(name, REVISION) for name in APPS): raise RuntimeError('Harbor native children must converge before registration')
        atomic(BASE / RECORD, dict(state, phase='accepted', applications=applications, **identities))
        changed = True
    else:
        raise RuntimeError('Complete Harbor native ownership registration before operations')
    return changed


def prepare(*, initial=False):
    """Called only under the existing host lock, before public activation."""
    from playbooks.harbor.files.recovery import atomic, handoff_pending
    pending = handoff_pending()
    if initial and pending['manifest'] is not None:
        raise RuntimeError('Fresh Harbor intent refuses pending recovery')
    snapshot = context(preparing=True)
    existing = receipt()
    if existing:
        if existing.get('phase') == 'initial' and pending['manifest'] is not None:
            raise RuntimeError('Fresh Harbor intent refuses pending recovery')
        if snapshot['enabled']:
            handoff_pending(expected=pending)
            changed = observe(snapshot, existing, register=True)
            handoff_pending(expected=pending)
            return changed
        if (existing.get('profile') != snapshot['profile'] or existing.get('root_uid') != snapshot['root']['metadata']['uid']
                or existing.get('authority') != snapshot['authority'] or existing.get('repository') != snapshot['targets'][0]['valuesRepository']
                or existing.get('revision') != REVISION or existing.get('phase') not in ('initial', 'prepared')
                or (get('appproject.argoproj.io', APPS[0], 'argocd') or {}).get('metadata', {}).get('uid') != existing.get('project_uid')):
            raise RuntimeError('Harbor recorded handoff cannot be replaced')
        if existing['phase'] == 'initial': safe_absence(recorded=True)
        else:
            if set(existing.get('applications', {})) != set(APPS): raise RuntimeError('Harbor prepared identities are incomplete')
            for name in APPS:
                app, normalized = child(snapshot, name, accepted=existing['applications'][name])
                if app['metadata'].get('ownerReferences') or normalized != values(snapshot['profile'], name):
                    raise RuntimeError('Harbor prepared scope changed before activation')
        handoff_pending(expected=pending)
        return False
    if snapshot['enabled']: raise RuntimeError('Harbor native activation requires its prior protected intent')
    from playbooks.harbor.files.configuration import client
    from playbooks.keycloak.files.ownership import accepted_application, public_installation_revision
    identity_revision = accepted_application(get('application.argoproj.io', 'cloudlab-identity', 'argocd') or {})
    if snapshot['public']['identity']['application']['enabled'] and identity_revision != public_installation_revision(snapshot['public']):
        raise RuntimeError('Harbor preparation requires the accepted native identity installation')
    identity = get('configmap', 'identity-private-state', 'cloudlab-identity') or {}
    desired = json.loads(identity.get('data', {}).get('desired_state', '{}'))
    revoked = json.loads(identity.get('data', {}).get('revocations', '{}')).get('realms', {}).get('platform', {})
    expected_client = client('https://' + snapshot['profile']['loginHost'] + '/realms/platform', 'https://' + snapshot['profile']['harborHost'])
    if ([entry for entry in desired.get('realms', {}).get('platform', {}).get('clients', []) if entry.get('id') == 'harbor'] != [expected_client]
            or 'harbor' in revoked.get('clients', []) + revoked.get('removed_clients', [])):
        raise RuntimeError('Harbor preparation requires its active accepted identity client')
    project = get('appproject.argoproj.io', APPS[0], 'argocd') or {}
    legacy_project = copy.deepcopy(snapshot['contracts'][0][('AppProject', APPS[0])]['spec']); legacy_project['sourceRepos'] = [PUBLIC]
    if (not source.quiet(project) or not same(project.get('spec'), legacy_project)
            or project['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APPS[0]):
        raise RuntimeError('Harbor preparation requires the exact existing Root project')
    applications = {}; captured_apps = {}
    if initial:
        safe_absence()
    else:
        if any(get(kind, name, 'argocd') for kind, name in [('applicationset.argoproj.io', name) for name in APPS] +
                [('externalsecret.external-secrets.io', READER), ('secret', READER)]):
            raise RuntimeError('Harbor preparation refuses premature native controls')
        for name in APPS:
            app, actual = child(snapshot, name)
            if app['metadata'].get('ownerReferences') or not application_ready(name, REVISION) or actual != values(snapshot['profile'], name):
                raise RuntimeError('Harbor handoff requires both idle ownerless Applications at R')
            helm_values = app['spec']['source']['helm']['valuesObject']
            documents = [json.loads(snapshot['charts'][name]['values.json'])] if name == APPS[0] else []
            old = source.render_objects(snapshot['charts'][name], [*documents, helm_values], release=APPS[0], namespace=NAMESPACE)
            new = source.render_objects(snapshot['charts'][name], [*documents, values(snapshot['profile'], name)], release=APPS[0], namespace=NAMESPACE)
            if old != new: raise RuntimeError('Harbor native handoff changes effective immutable chart resources')
            applications[name] = app['metadata']['uid']
            captured_apps[name] = copy.deepcopy(app)
        handoff_pending(expected=pending)
    if source.root_guard({'publicSource': {'repository': PUBLIC, 'branch': 'main'}}, snapshot['public'], snapshot['head']) != snapshot['targets'][0]:
        raise RuntimeError('Harbor binding changed during native preparation')
    fresh_project = get('appproject.argoproj.io', APPS[0], 'argocd') or {}
    if (fresh_project.get('metadata', {}).get('uid') != project['metadata']['uid'] or not same(fresh_project.get('spec'), project.get('spec'))
            or not source.quiet(fresh_project)):
        raise RuntimeError('Harbor project changed during native preparation')
    for name, before in captured_apps.items():
        after = get('application.argoproj.io', name, 'argocd') or {}
        if (after.get('metadata', {}).get('uid') != before['metadata']['uid'] or not same(after.get('spec'), before.get('spec'))
                or after.get('metadata', {}).get('ownerReferences') or after.get('metadata', {}).get('deletionTimestamp')
                or after.get('metadata', {}).get('finalizers') or not application_ready(name, REVISION)):
            raise RuntimeError('Harbor idle installation changed before protected intent')
    handoff_pending(expected=pending)
    atomic(BASE / RECORD, {'version': 'cloudlab-harbor-native/v1', 'phase': 'initial' if initial else 'prepared',
        'root_uid': snapshot['root']['metadata']['uid'], 'authority': snapshot['authority'],
        'project_uid': project['metadata']['uid'], 'profile': snapshot['profile'],
        'revision': REVISION, 'repository': snapshot['targets'][0]['valuesRepository'], 'applications': applications})
    return True


@contextmanager
def operation(*, deadline=None):
    existing = ACTIVE.get()
    if existing is not None:
        limit = existing.get('read_deadline')
        if deadline is not None: limit = min(limit, deadline) if limit is not None else deadline
        if limit is not None and time.monotonic() >= limit: raise RuntimeError('Harbor read operation exceeded its budget')
        scoped = dict(existing, read_deadline=limit)
        observe(scoped, receipt())
        token = ACTIVE.set(scoped)
        try:
            yield scoped
            if limit is not None and time.monotonic() >= limit: raise RuntimeError('Harbor read operation exceeded its budget')
        finally:
            ACTIVE.reset(token)
        return
    if not receipt():
        raise RuntimeError('Harbor native operation requires its protected accepted installation intent')
    snapshot = context(deadline=deadline)
    state = receipt()
    if state and snapshot is None: raise RuntimeError('Harbor prepared native intent forbids legacy operation fallback')
    if snapshot is not None: observe(snapshot, state)
    snapshot['read_deadline'] = deadline
    token = ACTIVE.set(snapshot)
    try:
        yield snapshot
        if deadline is not None and time.monotonic() >= deadline: raise RuntimeError('Harbor read operation exceeded its budget')
    finally:
        ACTIVE.reset(token)


def guard(name, app, *, write=False):
    snapshot = ACTIVE.get()
    if snapshot is None:
        if receipt() and not write:
            with operation(): return guard(name, app)
        raise RuntimeError('Harbor native operations require their authenticated lock context')
    state = receipt()
    observe(snapshot, state)
    current, normalized = child(snapshot, name, accepted=state['applications'][name])
    if (current.get('spec') != app.get('spec') or any(current.get('metadata', {}).get(key) != app.get('metadata', {}).get(key)
            for key in ('uid', 'ownerReferences', 'labels', 'annotations', 'finalizers', 'deletionTimestamp'))):
        raise RuntimeError('Harbor Application changed during operational read')
    return snapshot, normalized


def binding_guard(binding, root, *, read=None):
    from playbooks.argocd.files.source_transition import binding_source
    read = (lambda kind, name: get(kind, name, 'argocd')) if read is None else read
    if not receipt():
        if any(read('applicationset.argoproj.io', name) for name in APPS):
            raise RuntimeError('Harbor native binding recovery lost its protected ownership intent')
        return
    recovery = {'checkpoint': binding, 'sourceState': binding_source(binding, root), 'rootSource': copy.deepcopy(root['spec']['source'])}
    snapshot = context(recovery=recovery)
    if snapshot is not None: observe(snapshot, receipt())


def regular_runtime(path):
    """Inspect exact retired paths without following redirected ancestors."""
    for ancestor in reversed(path.parents):
        try: info = ancestor.lstat()
        except FileNotFoundError: return None
        if info.st_uid != 0 or not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022:
            raise RuntimeError('Harbor retired runtime has unsafe ancestors')
    try: info = path.lstat()
    except FileNotFoundError: return None
    if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > 2 * 1024 * 1024:
        raise RuntimeError('Harbor retired runtime must be an owned regular bounded file')
    return info


def retire():
    """Under the existing lock, remove only the attested replaced H1 writer."""
    from playbooks.harbor.files.recovery import handoff_pending
    with operation() as snapshot:
        pending = handoff_pending()
        path = RUNTIME / 'bootstrap.py'
        info = regular_runtime(path)
        raw = path.read_bytes() if info is not None else None
        if raw is not None and hashlib.sha256(raw).hexdigest() != RETIRED_BOOTSTRAP_SHA256:
            raise RuntimeError('Harbor retired writer differs from the published H1 checksum')
        cache = RUNTIME / '__pycache__'
        # This validates the cache directory/ancestors even when its leaf is absent.
        regular_runtime(cache / 'bootstrap.absence-check')
        candidates = []
        if cache.exists():
            for entry in sorted(cache.iterdir()):
                if not entry.name.startswith('bootstrap.'): continue
                match = re.fullmatch(r'bootstrap[.]cpython-([0-9]{2,3})(?:[.]opt-([12]))?[.]pyc', entry.name)
                if not match or raw is None: raise RuntimeError('Harbor retired bytecode has unknown provenance')
                regular_runtime(entry)
                data = entry.read_bytes()
                if len(data) < 16 or data[:4] != importlib.util.MAGIC_NUMBER:
                    raise RuntimeError('Harbor retired bytecode has an unknown interpreter header')
                flags = int.from_bytes(data[4:8], 'little')
                if flags == 0:
                    valid = data[8:12] == (int(info.st_mtime) & 0xffffffff).to_bytes(4, 'little') and data[12:16] == len(raw).to_bytes(4, 'little')
                else:
                    valid = flags in (1, 3) and data[8:16] == importlib.util.source_hash(raw)
                if not valid: raise RuntimeError('Harbor retired bytecode does not match its approved writer')
                try:
                    encoded = io.BytesIO(data[16:])
                    code = marshal.load(encoded)
                    expected = compile(raw, str(path), 'exec', dont_inherit=True, optimize=int(match[2] or 0))
                    if type(code) is not type(expected) or code != expected or encoded.tell() != len(data) - 16:
                        raise ValueError()
                except (ValueError, EOFError, TypeError, MemoryError, RecursionError):
                    raise RuntimeError('Harbor retired bytecode body is foreign or invalid') from None
                candidates.append((entry, data))
        for entry, data in candidates:
            observe(snapshot, receipt()); handoff_pending(expected=pending)
            regular_runtime(entry)
            if entry.read_bytes() != data: raise RuntimeError('Harbor retired bytecode changed before removal')
            entry.unlink()
        if raw is not None:
            observe(snapshot, receipt()); handoff_pending(expected=pending)
            regular_runtime(path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != RETIRED_BOOTSTRAP_SHA256:
                raise RuntimeError('Harbor retired writer changed before removal')
            path.unlink()
        return bool(candidates) or raw is not None


def run(request):
    if (not isinstance(request, dict) or set(request) - {'native_handoff', 'native_initial', 'retire'}
            or any(type(value) is not bool for value in request.values())
            or request.get('native_initial') and not request.get('native_handoff')
            or request.get('retire') and (request.get('native_handoff') or request.get('native_initial'))):
        raise RuntimeError('Harbor retained owner accepts only its explicit lifecycle flags')
    os.umask(0o077)
    with LOCK.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if request.get('retire'):
            changed = retire()
        elif request.get('native_handoff'):
            changed = prepare(initial=request.get('native_initial', False))
        else:
            with operation(): pass
            changed = False
    return {'changed': changed, 'owner': 'argocd', 'native_installation': True}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin)), sort_keys=True))
    except Exception:
        raise SystemExit('Harbor native ownership incomplete; existing owners, credentials and data retained') from None
