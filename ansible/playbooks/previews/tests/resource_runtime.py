"""Explicit synthetic fixture resources; never part of continuous convergence."""
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

sys.path.insert(0, '/opt/cloudlab')
from playbooks.previews.files import contract
from playbooks.previews.files.kube import APIError, Kubernetes, identity, path
from playbooks.previews.files.lifecycle import namespace_disposable, owned
from playbooks.istio.files.kube import contains, kube

ROOT = Path('/var/lib/cloudlab/preview-fixtures')
OWNER = 'cloudlab-preview-fixture'
ACTIONS = ('custody-install', 'probe-prepare', 'probe-observe', 'probe-cleanup', 'retained-create', 'retained-observe', 'retained-delete',
           'outage-prepare', 'outage-observe', 'outage-fault', 'outage-restore', 'outage-cleanup')
REDUCING = ('probe-observe', 'probe-cleanup', 'retained-observe', 'retained-delete', 'outage-observe', 'outage-restore', 'outage-cleanup')


def validate(request):
    if (not isinstance(request, dict) or set(request) != {'action', 'nonce', 'revision', 'rows'} or
            request['action'] not in ACTIONS or not re.fullmatch('[a-f0-9]{32}', request.get('nonce', '')) or
            not re.fullmatch('[a-f0-9]{40}', request.get('revision', '')) or not isinstance(request['rows'], list) or
            len(request['rows']) > 2):
        raise ValueError('Invalid bounded resource fixture request')
    for row in request['rows']:
        (contract.stored_approval if request['action'] in REDUCING else contract.approval)(row)
        if row['definition']['profile'] != 'synthetic' or (request['action'] not in REDUCING and row['platformRevision'] != request['revision']):
            raise ValueError('Resource fixture requires the exact synthetic platform approval')
    if len({row['instance'] for row in request['rows']}) != len(request['rows']):
        raise ValueError('Repeated fixture approval')
    count = 2 if request['action'].startswith('probe-') else 1 if request['action'].startswith('retained-') else 0
    if len(request['rows']) != count:
        raise ValueError('Resource action requires its fixed approval count')


class HostKubernetes(Kubernetes):
    def __init__(self):
        pass

    def request(self, method, route, value=None):
        if method == 'GET':
            raw = kube('get', '--raw', route)
        elif method in ('POST', 'PUT', 'DELETE'):
            result = kube({'POST': 'create', 'PUT': 'replace', 'DELETE': 'delete'}[method], '--raw', route, '-f', '-', document=value,
                          allow_failure=True)
            if result.returncode:
                # kubectl --raw can return a structured Status body; no raw diagnostic escapes.
                try: status = json.loads(result.stdout)
                except (ValueError, TypeError): status = {}
                if status.get('kind') == 'Status' and type(status.get('code')) is int:
                    raise APIError(status['code'])
                if re.search(r'(?i)error from server|\((?:AlreadyExists|Forbidden|Invalid|BadRequest|Unauthorized|Conflict|NotFound)\)', result.stderr):
                    raise APIError(400)
                raise RuntimeError('Fixture API write ambiguous; ownership remains quarantined')
            raw = result.stdout
        else:
            raise ValueError('Unsupported fixture API method')
        return json.loads(raw) if raw else None

    def get(self, key):
        from playbooks.istio.files.kube import get
        version, kind, namespace, name = key
        resource = kind.lower() + ('.' + version.split('/')[0] if '/' in version else '')
        return get(resource, name or None, namespace or None)


def metadata(nonce, name, namespace=None):
    return {'name': name, **({'namespace': namespace} if namespace else {}),
            'labels': {'cloudlab.io/owner': OWNER, 'cloudlab.io/fixture': nonce}}


def obj(nonce, version, kind, name, namespace=None, **fields):
    return dict(apiVersion=version, kind=kind, metadata=metadata(nonce, name, namespace), **fields)


def coordinates(nonce, group):
    return 'cloudlab-fixture-' + group + '-' + nonce


def restricted_namespace(nonce, group):
    ns = coordinates(nonce, group)
    result = obj(nonce, 'v1', 'Namespace', ns)
    result['metadata']['labels'].update({'pod-security.kubernetes.io/enforce': 'restricted',
        'pod-security.kubernetes.io/enforce-version': 'v1.36'})
    return result


class Receipts:
    def __init__(self, directory, state, api):
        self.directory, self.state, self.api = directory, state, api

    def save(self):
        temporary = self.directory / ('.state-' + secrets.token_hex(8))
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                json.dump(self.state, stream, sort_keys=True)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, self.directory / 'state.json')
            descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    def check(self, actual, record):
        if (not actual or not contains(actual, record['desired']) or
                not actual['metadata'].get('uid') or not actual['metadata'].get('resourceVersion') or
                actual['metadata'].get('ownerReferences') or actual['metadata'].get('deletionTimestamp') or
                actual['metadata'].get('finalizers') or
                record.get('uid', actual['metadata']['uid']) != actual['metadata']['uid']):
            raise ValueError('Fixture resource identity or declaration changed')
        if actual.get('kind') == 'ConfigMap' and any(actual.get(field, {}) != record['desired'].get(field, {}) for field in ('data', 'binaryData')):
            raise ValueError('Fixture ConfigMap data changed')
        if actual.get('kind') == 'ApplicationSet' and actual.get('spec') != record['desired'].get('spec'):
            raise ValueError('Fixture ApplicationSet specification changed')
        annotations = actual['metadata'].get('annotations', {})
        desired_annotations = record['desired']['metadata'].get('annotations', {})
        if any(value != desired_annotations.get(key) for key, value in annotations.items()
               if key.endswith('/retention') or key == 'helm.sh/resource-policy'):
            raise ValueError('Additional fixture retention blocks deletion')
        return actual

    def create(self, desired):
        key = identity(desired); label = '/'.join(key)
        records = self.state.setdefault('resources', {})
        actual = self.api.get(key)
        if label not in records:
            if actual:
                raise ValueError('Pre-existing fixture resources cannot be adopted')
            records[label] = {'desired': copy.deepcopy(desired), 'intent': True}
            self.save()
        record = records[label]
        if record['desired'] != desired or record.get('deleted') or record.get('rejected'):
            raise ValueError('Fixture declaration cannot change or recreate')
        if not actual:
            if record.get('uid'):
                raise ValueError('Recorded fixture resource disappeared')
            try:
                actual = self.api.create(desired)
            except APIError as error:
                if 400 <= error.code < 500:
                    record['rejected'] = error.code; self.save()
                raise
        self.check(actual, record)
        if 'uid' not in record:
            record['uid'] = actual['metadata']['uid']; self.save()
        return actual

    def recorded(self, key):
        record = self.state.get('resources', {}).get('/'.join(key))
        if not record or record.get('rejected'):
            raise ValueError('Fixture lacks its exact creation receipt')
        if not record.get('uid'):
            actual = self.api.get(key)
            self.check(actual, record)
            record['uid'] = actual['metadata']['uid']; self.save()
        return record

    def observe(self, key):
        record = self.recorded(key)
        return self.check(self.api.get(key), record)

    def delete(self, key, *, orphan=False):
        record = self.state.get('resources', {}).get('/'.join(key))
        actual = self.api.get(key)
        if record is None:
            if actual: raise ValueError('Unrecorded fixture coordinates cannot be deleted')
            return
        if record.get('rejected'): raise ValueError('Rejected fixture creation has no deletion ownership')
        if not record.get('uid'):
            if actual:
                self.check(actual, record)
                record['uid'] = actual['metadata']['uid']; self.save()
            else:
                record.update(deleteIntent=True, deleted=True); self.save()
                return
        if actual:
            self.check(actual, record)
            record['deleteIntent'] = True; self.save()
            self.api.delete(key, record['uid'], actual['metadata']['resourceVersion'], orphan=orphan)
        elif not record.get('deleteIntent'):
            raise ValueError('Fixture disappeared without its deletion intent')
        if self.api.get(key):
            raise RuntimeError('Fixture deletion still converging')
        record['deleted'] = True; self.save()


def platform(request, api):
    controller = api.get(('argoproj.io/v1alpha1', 'Application', 'argocd', 'cloudlab-previews')) or {}
    source = controller.get('spec', {}).get('sources', [{}])[0]
    if (source.get('targetRevision') != request['revision'] or
            controller.get('status', {}).get('sync', {}).get('revisions', [None])[0] != request['revision'] or
            controller.get('status', {}).get('health', {}).get('status') != 'Healthy' or controller.get('operation')):
        raise ValueError('Published preview owner is not ready')
    repository = source.get('repoURL', '')
    if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git', repository):
        raise ValueError('Fixture requires its accepted public platform source')
    return repository


def retained(request, receipts):
    row = request['rows'][0]; ns = contract.names(row)['namespace']
    key = ('v1', 'ConfigMap', ns, 'retained-proof')
    desired = obj(request['nonce'], 'v1', 'ConfigMap', 'retained-proof', ns,
                  data={'synthetic': 'retained-' + request['nonce']})
    desired['metadata']['annotations'] = {'cloudlab.io/retention': 'retain'}
    record = receipts.state.get('resources', {}).get('/'.join(key))
    if request['action'] == 'retained-delete' and (record is None or not record.get('uid')):
        if record is not None and (record.get('intent') is not True or record.get('rejected') or record.get('desired') != desired):
            raise ValueError('Retained cleanup lacks its exact nonrejected preparation')
        actual = receipts.api.get(key)
        if actual is None:
            if record is not None: receipts.delete(key)
            return {'retained': False, 'fixtureCMAbsent': True}
        if record is None: raise ValueError('Unrecorded retained fixture data cannot be deleted')
    state = receipts.api.get(('v1', 'ConfigMap', 'argocd', contract.STATE))
    entry = json.loads(state['data']['state.json'])['entries'][row['instance']]
    if entry.get('approvalDigest') != contract.digest(contract.canonical(row)):
        raise ValueError('Retained fixture approval changed')
    namespace = receipts.api.get(('v1', 'Namespace', '', ns))
    if not namespace and request['action'] == 'retained-delete' and receipts.recorded(key).get('deleteIntent'):
        receipts.delete(key)
        return {'retained': False, 'namespaceUID': receipts.state['retainedNamespaceUID'],
                'phase': entry['phase'], 'dataHash': contract.digest(contract.canonical(receipts.recorded(key)['desired']['data']))}
    namespace_receipts = [item for item in entry.get('resources', []) if item['key'] == ['v1', 'Namespace', '', ns]]
    if len(namespace_receipts) != 1 or not namespace_receipts[0].get('uid'):
        raise ValueError('Retained fixture requires authoritative namespace UID')
    owned(namespace, row, state['metadata']['uid'], namespace_receipts[0]['uid'])
    if request['action'] == 'retained-create':
        if entry['phase'] != 'active': raise ValueError('Retained data requires active owned slot D')
        if row['definition']['message'] != 'synthetic fixture d revision 0': raise ValueError('Retained fixture is limited to owned slot D')
        receipts.state.setdefault('retainedNamespaceUID', namespace['metadata']['uid'])
        if receipts.state['retainedNamespaceUID'] != namespace['metadata']['uid']:
            raise ValueError('Retained namespace identity changed')
        receipts.create(desired)
    elif receipts.state.get('retainedNamespaceUID') != namespace['metadata']['uid']:
        raise ValueError('Retained namespace lacks exact fixture receipt')
    elif request['action'] == 'retained-delete':
        receipts.delete(key)
    else:
        receipts.observe(key)
    return {'retained': request['action'] != 'retained-delete', 'namespaceUID': namespace['metadata']['uid'],
            'phase': entry['phase'], 'dataHash': contract.digest(contract.canonical(desired['data']))}


def probe_objects(request):
    nonce = request['nonce']; ns = coordinates(nonce, 'probe')
    code = {name: Path(__file__).with_name(name).read_text() for name in ('probe_program.py',)}
    code['traffic.py'] = Path(__file__).parents[2].joinpath('access/files/traffic.py').read_text()
    labels = {'app.kubernetes.io/name': 'fixture-probe'}
    security = {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True, 'capabilities': {'drop': ['ALL']}}
    pod = obj(nonce, 'v1', 'Pod', 'probe', ns, spec={'automountServiceAccountToken': False, 'restartPolicy': 'Never',
        'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'seccompProfile': {'type': 'RuntimeDefault'}},
        'containers': [{'name': 'probe', 'image': contract.IMAGE, 'command': ['python', '-B', '/fixture/probe_program.py', 'serve'],
            'securityContext': security, 'resources': {'requests': {'cpu': '25m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}},
            'ports': [{'containerPort': 8080, 'name': 'http'}],
            'readinessProbe': {'httpGet': {'path': '/', 'port': 'http'}},
            'volumeMounts': [{'name': 'code', 'mountPath': '/fixture', 'readOnly': True}]}],
        'volumes': [{'name': 'code', 'configMap': {'name': 'probe-code', 'defaultMode': 0o444}}]})
    pod['metadata']['labels'].update(labels)
    targets = [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': contract.names(row)['namespace']}}}
               for row in request['rows']]
    return [restricted_namespace(nonce, 'probe'),
        obj(nonce, 'v1', 'ResourceQuota', 'budget', ns, spec={'hard': {'pods': '1', 'requests.cpu': '100m', 'requests.memory': '64Mi',
            'limits.cpu': '200m', 'limits.memory': '128Mi', 'count/secrets': '0', 'persistentvolumeclaims': '0',
            'services.loadbalancers': '0', 'services.nodeports': '0'}}),
        obj(nonce, 'networking.k8s.io/v1', 'NetworkPolicy', 'probe', ns, spec={'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'],
            'ingress': [{'from': [{'podSelector': {'matchLabels': labels}}], 'ports': [{'port': 8080, 'protocol': 'TCP'}]}],
            'egress': [{'to': [{'podSelector': {'matchLabels': labels}}], 'ports': [{'port': 8080, 'protocol': 'TCP'}]},
                {'to': targets, 'ports': [{'port': 8080, 'protocol': 'TCP'}]},
                {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'cloudlab-gateway-private'}}}],
                 'ports': [{'port': 443, 'protocol': 'TCP'}]},
                {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                         'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}],
                 'ports': [{'port': 53, 'protocol': protocol} for protocol in ('TCP', 'UDP')]}]}),
        obj(nonce, 'v1', 'ConfigMap', 'probe-code', ns, data=code),
        obj(nonce, 'v1', 'Service', 'control', ns, spec={'selector': labels, 'ports': [{'port': 8080, 'targetPort': 'http', 'protocol': 'TCP'}]}), pod]


def cleanup_namespace(receipts, namespace):
    key = ('v1', 'Namespace', '', namespace)
    record = receipts.state.get('resources', {}).get('/'.join(key))
    current = receipts.api.get(key)
    if current:
        if not record or record.get('rejected'): raise ValueError('Unowned namespace cannot be deleted')
        receipts.check(current, record)
        namespace_disposable(receipts.api.namespace_inventory(namespace), set(), record.get('uid') or current['metadata']['uid'])
    receipts.delete(key)


def probe(request, receipts):
    objects = probe_objects(request)
    if request['action'] == 'probe-prepare':
        if receipts.state.get('probeRows', request['rows']) != request['rows']:
            raise ValueError('Probe approvals cannot change within a fixture')
        receipts.state['probeRows'] = copy.deepcopy(request['rows']); receipts.save()
        for desired in objects: receipts.create(desired)
    elif request['action'] == 'probe-cleanup':
        for desired in reversed(objects[1:]): receipts.delete(identity(desired))
        cleanup_namespace(receipts, coordinates(request['nonce'], 'probe'))
        return {'probeAbsent': True}
    from playbooks.previews.tests.probe_state import bound_probe
    observed = bound_probe(receipts.state)
    return {'probePrepared': True, 'namespaceUID': observed['Namespace']['metadata']['uid'],
            'podUID': observed['Pod']['metadata']['uid']}


def outage_objects(request, repository):
    nonce = request['nonce']; name = coordinates(nonce, 'git'); chart = 'ansible/playbooks/previews/tests/git-outage'
    project = obj(nonce, 'argoproj.io/v1alpha1', 'AppProject', name, 'argocd', spec={
        'sourceRepos': [repository], 'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': name}],
        'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [{'group': '', 'kind': 'ConfigMap'}]})
    appset = obj(nonce, 'argoproj.io/v1alpha1', 'ApplicationSet', name, 'argocd', spec={
        'goTemplate': True, 'goTemplateOptions': ['missingkey=error'],
        'generators': [{'git': {'repoURL': repository, 'revision': request['revision'], 'directories': [{'path': chart}]}}],
        'syncPolicy': {'applicationsSync': 'create-update', 'preserveResourcesOnDeletion': True},
        'template': {'metadata': metadata(nonce, name), 'spec': {'project': name,
            'source': {'repoURL': repository, 'targetRevision': request['revision'], 'path': chart,
                'helm': {'releaseName': name, 'valuesObject': {'nonce': nonce}}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': name},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true']}}}})
    return [restricted_namespace(nonce, 'git'),
        obj(nonce, 'v1', 'ResourceQuota', 'budget', name, spec={'hard': {'pods': '0', 'count/secrets': '0',
            'persistentvolumeclaims': '0', 'services.loadbalancers': '0', 'services.nodeports': '0'}}),
        obj(nonce, 'networking.k8s.io/v1', 'NetworkPolicy', 'deny', name,
            spec={'podSelector': {}, 'policyTypes': ['Ingress', 'Egress']}), project, appset]


def outage_data(nonce, receipts, data, baseline=None):
    desired = obj(nonce, 'v1', 'ConfigMap', 'persistent-proof', coordinates(nonce, 'git'),
                  data={'synthetic': 'persistent-' + nonce})
    desired['metadata']['annotations'] = {'cloudlab.io/retention': 'retain'}
    record = {'desired': desired}
    if baseline: record['uid'] = baseline['dataUID']
    receipts.check(data, record)
    metadata = data['metadata']
    captured = {'dataUID': metadata['uid'], 'dataHash': contract.digest(contract.canonical(data['data'])),
        'dataMetadata': {field: copy.deepcopy(metadata.get(field, [] if field in ('ownerReferences', 'finalizers') else {}))
                         for field in ('labels', 'annotations', 'ownerReferences', 'finalizers')}}
    if baseline and any(captured[field] != baseline.get(field) for field in captured):
        raise ValueError('Persistent fixture ownership, retention or data changed')
    return captured


def outage_application(receipts, application, appset, baseline=None):
    parent = receipts.recorded(identity(appset))
    desired = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', **copy.deepcopy(appset['spec']['template'])}
    desired['metadata']['namespace'] = 'argocd'
    checked = copy.deepcopy(application)
    references = checked['metadata'].pop('ownerReferences', [])
    record = {'desired': desired}
    if baseline: record['uid'] = baseline['applicationUID']
    receipts.check(checked, record)
    if application.get('spec', {}).get('sources'):
        raise ValueError('Generated fixture Application cannot add another source')
    metadata = application['metadata']
    captured = {'applicationUID': metadata['uid'], 'applicationSpec': copy.deepcopy(application['spec']),
        'applicationMetadata': {field: copy.deepcopy(metadata.get(field, [] if field in ('ownerReferences', 'finalizers') else {}))
                                for field in ('labels', 'annotations', 'ownerReferences', 'finalizers')}}
    if baseline:
        original = baseline['applicationMetadata']['ownerReferences']
        if references != original:
            if references or not parent.get('deleteIntent') or receipts.api.get(identity(appset)) is not None:
                raise ValueError('Generated fixture Application ownership changed')
            # Native orphan propagation may remove only the previously captured own parent.
            captured['applicationMetadata']['ownerReferences'] = copy.deepcopy(original)
        if any(captured[field] != baseline.get(field) for field in captured):
            raise ValueError('Generated fixture Application specification or metadata changed')
    elif (len(references) != 1 or references[0].get('kind') != 'ApplicationSet' or
            references[0].get('uid') != parent['uid'] or references[0].get('name') != appset['metadata']['name']):
        raise ValueError('Generated fixture Application lacks its exact native parent')
    return captured


def outage_observe(request, receipts, appset):
    nonce = request['nonce']; name = coordinates(nonce, 'git')
    actual = receipts.api.get(identity(appset)); record = receipts.recorded(identity(appset))
    expected = copy.deepcopy(record['desired'])
    if receipts.state.get('outageFault'):
        expected['spec']['generators'][0]['git']['revision'] = 'missing-fixture-' + nonce
    receipts.check(actual, dict(record, desired=expected))
    application = receipts.api.get(('argoproj.io/v1alpha1', 'Application', 'argocd', name))
    data = receipts.api.get(('v1', 'ConfigMap', name, 'persistent-proof'))
    if (not application or not data or
            data.get('data') != {'synthetic': 'persistent-' + nonce} or data.get('binaryData')):
        raise ValueError('Native persistent fixture has not converged with exact data')
    captured = {**outage_application(receipts, application, appset, receipts.state.get('outageBaseline')),
                **outage_data(nonce, receipts, data, receipts.state.get('outageBaseline'))}
    if not receipts.state.get('outageFault') and (application.get('status', {}).get('sync', {}).get('status') != 'Synced' or
            application['status']['sync'].get('revision') != request['revision'] or
            application['status'].get('health', {}).get('status') != 'Healthy'):
        raise ValueError('Native fixture is not healthy at its original revision')
    if 'outageBaseline' not in receipts.state:
        if receipts.state.get('outageFault'): raise ValueError('Git fault requires prior native positive convergence')
        if application.get('status', {}).get('sync', {}).get('status') != 'Synced' or application['status']['sync'].get('revision') != request['revision']:
            raise ValueError('Native persistent fixture is not synced')
        receipts.state['outageBaseline'] = captured; receipts.save()
    if captured != receipts.state['outageBaseline']: raise ValueError('Git outage changed persistent fixture identities or data')
    faulted = any(condition.get('status') == 'True' and condition.get('type') == 'ErrorOccurred'
                  for condition in actual.get('status', {}).get('conditions', []))
    if bool(receipts.state.get('outageFault')) != faulted:
        raise ValueError('Native Git generator error/recovery has not converged')
    return dict(captured, generatorFailed=faulted)


def outage(request, receipts, repository=None):
    objects = outage_objects(request, repository or platform(request, receipts.api)); appset = objects[-1]
    action = request['action']
    if action in REDUCING:
        original = receipts.state.get('resources', {}).get('/'.join(identity(appset)))
        if original: appset = copy.deepcopy(original['desired'])
    if action == 'outage-prepare':
        for desired in objects: receipts.create(desired)
    elif action in ('outage-fault', 'outage-restore'):
        fault = action == 'outage-fault'
        if fault and receipts.state.get('outageIntent') != action and not receipts.state.get('outageFault'):
            outage_observe(request, receipts, appset)
        key = identity(appset); record = receipts.recorded(key); actual = receipts.api.get(key)
        before = copy.deepcopy(record['desired'])
        if receipts.state.get('outageFault'): before['spec']['generators'][0]['git']['revision'] = 'missing-fixture-' + request['nonce']
        if not fault and receipts.state.get('outageIntent') == 'outage-fault':
            pending = copy.deepcopy(record['desired'])
            pending['spec']['generators'][0]['git']['revision'] = 'missing-fixture-' + request['nonce']
            if actual.get('spec') == pending['spec']: before = pending
        after = copy.deepcopy(record['desired'])
        if fault: after['spec']['generators'][0]['git']['revision'] = 'missing-fixture-' + request['nonce']
        allowed = [before]
        if receipts.state.get('outageIntent') == action: allowed.append(after)
        matched = next((desired for desired in allowed if actual.get('spec') == desired['spec']), None)
        if matched is None:
            raise ValueError('Git fixture changed outside its exact fault/restore intent')
        receipts.check(actual, dict(record, desired=matched))
        receipts.state['outageIntent'] = action; receipts.save()
        if actual['spec'] != after['spec']:
            actual['spec'] = after['spec']; receipts.api.replace(actual)
        receipts.state['outageFault'] = fault; receipts.state.pop('outageIntent', None); receipts.save()
        return {'generatorFaultRequested': fault}
    elif action == 'outage-cleanup':
        if receipts.state.get('outageFault') or receipts.state.get('outageIntent'):
            raise ValueError('Restore valid Git generator before fixture cleanup')
        if not receipts.state.get('outageCleanupStarted'):
            if 'outageBaseline' in receipts.state:
                outage_observe(request, receipts, appset)
            else:
                name = coordinates(request['nonce'], 'git')
                if (receipts.api.get(('argoproj.io/v1alpha1', 'Application', 'argocd', name)) or
                        receipts.api.get(('v1', 'ConfigMap', name, 'persistent-proof'))):
                    outage_observe(request, receipts, appset)
                else:
                    receipts.state['outageEmpty'] = True
            receipts.state['outageCleanupStarted'] = True; receipts.save()
        name = coordinates(request['nonce'], 'git'); baseline = receipts.state.get('outageBaseline', {})
        appkey = ('argoproj.io/v1alpha1', 'Application', 'argocd', name)
        application = receipts.api.get(appkey)
        if application:
            if not baseline: raise ValueError('Generated fixture Application lacks its original observation')
            outage_application(receipts, application, appset, baseline)
        elif baseline and not receipts.state.get('outageAppDeleteIntent'):
            raise ValueError('Generated Application disappeared without deletion intent')
        datakey = ('v1', 'ConfigMap', name, 'persistent-proof')
        data = receipts.api.get(datakey)
        if baseline and data:
            outage_data(request['nonce'], receipts, data, baseline)
        elif baseline and not receipts.state.get('outageDataDeleteIntent'):
            raise ValueError('Fixture data disappeared without deletion intent')
        receipts.delete(identity(appset), orphan=True)
        application = receipts.api.get(appkey)
        if application:
            if not baseline: raise ValueError('Generated fixture Application lacks its original observation')
            outage_application(receipts, application, appset, baseline)
            receipts.state['outageAppDeleteIntent'] = True; receipts.save()
            receipts.api.delete(appkey, baseline['applicationUID'], application['metadata']['resourceVersion'], orphan=True)
            if receipts.api.get(appkey): raise RuntimeError('Generated fixture Application deletion still converging')
        elif not receipts.state.get('outageAppDeleteIntent') and not receipts.state.get('outageEmpty'): raise ValueError('Generated Application disappeared without deletion intent')
        data = receipts.api.get(datakey)
        if data:
            if not baseline: raise ValueError('Persistent fixture data lacks its original observation')
            outage_data(request['nonce'], receipts, data, baseline)
            receipts.state['outageDataDeleteIntent'] = True; receipts.save()
            receipts.api.delete(datakey, baseline['dataUID'], data['metadata']['resourceVersion'], orphan=True)
            if receipts.api.get(datakey): raise RuntimeError('Persistent fixture data deletion still converging')
        elif not receipts.state.get('outageDataDeleteIntent') and not receipts.state.get('outageEmpty'): raise ValueError('Fixture data disappeared without deletion intent')
        for desired in reversed(objects[1:-1]): receipts.delete(identity(desired))
        cleanup_namespace(receipts, name)
        return {'outageFixtureAbsent': True}
    return outage_observe(request, receipts, appset)


def run(request):
    validate(request)
    if request['action'] == 'custody-install':
        raise ValueError('Custody installation belongs only to its Ansible owner')
    directory = ROOT / request['nonce']
    if ROOT.is_symlink() or directory.is_symlink(): raise ValueError('Fixture receipt path changed')
    ROOT.mkdir(mode=0o700, exist_ok=True); directory.mkdir(mode=0o700, exist_ok=True)
    if any(target.stat().st_mode & 0o077 or target.stat().st_uid != 0 for target in (ROOT, directory)):
        raise ValueError('Fixture receipts must be private root-owned directories')
    descriptor = os.open(directory / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        target = directory / 'state.json'
        if target.is_symlink(): raise ValueError('Fixture receipt link refused')
        if target.exists() and (not target.is_file() or target.stat().st_size > 262144 or
                                target.stat().st_mode & 0o077 or target.stat().st_uid != 0):
            raise ValueError('Fixture receipt is not private and bounded')
        state = json.loads(target.read_text()) if target.exists() else {'nonce': request['nonce'], 'revision': request['revision']}
        if state.get('nonce') != request['nonce'] or (state.get('revision') != request['revision'] and request['action'] not in REDUCING):
            raise ValueError('Fixture source identity changed')
        if any(row['platformRevision'] != state['revision'] for row in request['rows']):
            raise ValueError('Fixture cleanup requires its original approval revision')
        receipts = Receipts(directory, state, HostKubernetes())
        repository = platform(request, receipts.api)
        request = dict(request, revision=state['revision'])
        if request['action'].startswith('retained-'):
            return retained(request, receipts)
        if request['action'].startswith('probe-'):
            return probe(request, receipts)
        return outage(request, receipts, repository)
    finally:
        os.close(descriptor)


if __name__ == '__main__':
    try:
        raw = sys.stdin.buffer.read(32769)
        if len(raw) > 32768: raise ValueError('Resource request too large')
        print(json.dumps(run(json.loads(raw))))
    except Exception:
        print('Resource fixture refused; diagnostics withheld', file=sys.stderr)
        raise SystemExit(1)
