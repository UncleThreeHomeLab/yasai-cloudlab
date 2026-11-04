"""Read-only access source ownership and independent identity prerequisites."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import stat
import sys

try:
    from playbooks.argocd.files import access_activation as authority
    from playbooks.istio.files.kube import application_ready, condition, contains, get, kube
except ModuleNotFoundError:
    sys.path.insert(0, '/var/lib/cloudlab/mesh')
    import access_activation as authority
    from kube import application_ready, condition, contains, get, kube

APP = 'cloudlab-access'
BASE = Path('/var/lib/cloudlab/connectivity')
BINDING_RECEIPT = Path('/var/lib/cloudlab/gitops/identity-values-binding.json')
TRACKING = authority.TRACKING


def quiet(obj):
    meta = obj.get('metadata', {})
    return (not meta.get('deletionTimestamp') and not meta.get('ownerReferences') and not meta.get('finalizers')
        and obj.get('operation') is None and obj.get('status', {}).get('operationState', {}).get('phase') in (None, 'Succeeded')
        and str(meta.get('annotations', {}).get('argocd.argoproj.io/skip-reconcile', '')).lower() != 'true')


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def binding_receipt():
    for path in (*reversed(BINDING_RECEIPT.parents), BINDING_RECEIPT):
        info = path.lstat()
        if (info.st_uid != 0 or stat.S_ISLNK(info.st_mode)
                or (path == BINDING_RECEIPT and (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600))
                or (path != BINDING_RECEIPT and (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022))):
            raise RuntimeError('Accepted identity binding receipt ownership is unsafe')
    return json.loads(BINDING_RECEIPT.read_text())


def binding(payload):
    root = get('application.argoproj.io', 'cloudlab-public-root', 'argocd') or {}
    source = root.get('spec', {}).get('source', {})
    identity = source.get('helm', {}).get('valuesObject', {}).get('identity', {})
    if (not quiet(root) or root.get('spec', {}).get('project') != 'cloudlab-root' or root['spec'].get('sources')
            or source.get('repoURL') != payload['repository'] or source.get('targetRevision') != payload['branch']
            or source.get('path') != 'gitops/roots/public' or not application_ready('cloudlab-public-root', payload['revision'])
            or not isinstance(identity, dict)):
        raise RuntimeError('Access requires its unchanged ready public root')
    if 'argo' not in identity:
        if BINDING_RECEIPT.exists() or BINDING_RECEIPT.is_symlink():
            raise RuntimeError('Recorded identity approval requires explicit recovery; prebinding fallback refused')
        return None
    target = identity['argo']
    if (not isinstance(target, dict) or set(target) != {'valuesRepository', 'valuesRevision'}
            or target['valuesRepository'] != payload['private_repository']
            or not isinstance(target['valuesRevision'], str) or not re.fullmatch('[a-f0-9]{40}', target['valuesRevision'])):
        raise RuntimeError('Access private binding is malformed or foreign')
    receipt = binding_receipt()
    if (not isinstance(receipt, dict) or set(receipt) != {'phase', 'target', 'root_uid', 'project_uid', 'controller_uid'}
            or receipt['phase'] != 'accepted' or receipt['target'] != target
            or receipt['root_uid'] != root['metadata'].get('uid')):
        raise RuntimeError('Access private binding is not the accepted identity approval')
    for key, kind, name in (('project_uid', 'appproject.argoproj.io', 'cloudlab-root'),
                            ('controller_uid', 'statefulset', 'argocd-application-controller')):
        obj = get(kind, name, 'argocd') or {}
        if obj.get('metadata', {}).get('uid') != receipt[key] or obj.get('metadata', {}).get('deletionTimestamp'):
            raise RuntimeError('Accepted identity binding resource identity changed')
    return target


def retained(state, public_revision, expected_credentials=None):
    if state.get('phase') != 'configured' or set(state.get('identities', {})) != {
            'proxygroup/cloudlab-ingress', 'proxygroup/cloudlab-api', 'service/cloudlab-tailnet',
            'secret/operator-oauth', 'secret/cloudflared-runtime'}:
        raise RuntimeError('Configured access resource receipt is incomplete')
    if not application_ready('cloudlab-tailscale-operator', public_revision):
        raise RuntimeError('Access operator is not at the active public revision')
    credentials = {}
    for kind, name, namespace in [('proxygroup', 'cloudlab-ingress', None), ('proxygroup', 'cloudlab-api', None),
            ('service', 'cloudlab-tailnet', 'cloudlab-gateway-private'),
            ('secret', 'operator-oauth', 'tailscale'), ('secret', 'cloudflared-runtime', 'cloudlab-connectors')]:
        obj = get(kind, name, namespace) or {}; meta = obj.get('metadata', {})
        if meta.get('uid') != state['identities'][kind + '/' + name] or meta.get('deletionTimestamp'):
            raise RuntimeError('Retained access resource identity changed')
        if kind == 'proxygroup' and not any(c.get('type') == 'ProxyGroupReady' and c.get('status') == 'True'
                and meta.get('generation') is not None and c.get('observedGeneration') == meta['generation']
                for c in obj.get('status', {}).get('conditions', [])):
            raise RuntimeError('Access proxy group current generation is not ready')
        if kind == 'service':
            spec = obj.get('spec', {})
            if (spec.get('type') != 'LoadBalancer' or spec.get('loadBalancerClass') != 'tailscale'
                    or spec.get('allocateLoadBalancerNodePorts') is not False or spec.get('externalIPs')
                    or spec.get('selector') != {'gateway.networking.k8s.io/gateway-name': 'cloudlab'}
                    or len(spec.get('ports', [])) != 1 or any(p.get('port') != 443 or p.get('targetPort') != 443
                        or p.get('protocol', 'TCP') != 'TCP' or p.get('nodePort') for p in spec['ports'])):
                raise RuntimeError('Access tailnet service exposure policy changed')
        if kind == 'secret':
            external = get('externalsecret.external-secrets.io', name, namespace) or {}
            owners = meta.get('ownerReferences', [])
            if (not condition(external, 'Ready') or external.get('metadata', {}).get('deletionTimestamp')
                    or len(owners) != 1 or owners[0].get('uid') != external.get('metadata', {}).get('uid')
                    or owners[0].get('name') != name or owners[0].get('kind') != 'ExternalSecret'
                    or owners[0].get('apiVersion') != 'external-secrets.io/v1' or owners[0].get('controller') is not True
                    or not obj.get('data')):
                raise RuntimeError('Access runtime credential lacks its ready ESO owner')
            credentials[namespace + '/' + name] = {'uid': meta['uid'], 'content': digest(obj['data'])}
    if expected_credentials is not None and credentials != expected_credentials:
        raise RuntimeError('Access runtime credentials changed during handoff')
    return credentials


def observe_legacy(payload):
    state = authority.receipt()
    credentials = retained(state, payload['revision'])
    authority.administrator_binding(state, lambda kind, name: get(kind, name, 'argocd'))
    app = get('application.argoproj.io', APP, 'argocd') or {}
    spec = app.get('spec', {}); source = spec.get('source', {})
    administrator = source.get('helm', {}).get('valuesObject', {}).get('administrator')
    if (not quiet(app) or app.get('metadata', {}).get('uid') != state['application_uid']
            or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != 'cloudlab-access-bootstrap'
            or app['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') or spec.get('sources')
            or spec.get('project') != APP or spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'tailscale'}
            or not isinstance(administrator, str) or hashlib.sha256(administrator.encode()).hexdigest() != state['administrator']
            or source != {'repoURL': payload['repository'], 'targetRevision': payload['branch'], 'path': 'platform/connectivity/access',
                'helm': {'releaseName': APP, 'valuesObject': {'administrator': administrator}}}
            or spec.get('syncPolicy') != {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '1m'}}}
            or set(spec) != {'project', 'source', 'destination', 'syncPolicy'}
            or not application_ready(APP, payload['revision'])):
        raise RuntimeError('Configured initial access seed changed; explicit recovery review required')
    return {'native_owner_verified': False, 'credentials': credentials}


def guard(native, *, stage='native', expected_credentials=None):
    state = authority.receipt()
    if (stage not in ('legacy', 'native') or not isinstance(native, dict)
            or any(not isinstance(native.get(k), str) or not re.fullmatch('[a-f0-9]{40}', native[k])
                   for k in ('public_revision', 'configuration_revision', 'private_revision'))):
        raise RuntimeError('Native access inputs are invalid')
    expected_sources = [
        {'repoURL': native['repository'], 'targetRevision': native['configuration_revision'], 'path': 'platform/connectivity/access',
         'helm': {'releaseName': APP, 'valueFiles': ['$values/platform/access.yaml']}},
        {'repoURL': native['private_repository'], 'targetRevision': native['private_revision'], 'ref': 'values'}]
    if (native.get('application', {}).get('spec', {}).get('sources') != expected_sources
            or native.get('evidence', {}).get('revision') != native['configuration_revision']
            or native['evidence'].get('required') is not True
            or native.get('project', {}).get('spec', {}).get('sourceRepos') != [native['repository'], native['private_repository']]):
        raise RuntimeError('Native access observation coordinates are inconsistent')
    payload = {'repository': native['repository'], 'branch': 'main', 'revision': native['public_revision'],
               'private_repository': native['private_repository']}
    target = binding(payload)
    if target != {'valuesRepository': native['private_repository'], 'valuesRevision': native['private_revision']}:
        raise RuntimeError('Access source is not the approved identity binding')
    def read(kind, name): return get(kind, name, 'argocd')
    authority.guard(native['evidence'], target, read, get('application.argoproj.io', 'cloudlab-public-root', 'argocd'))
    credentials = retained(state, native['public_revision'], expected_credentials)
    app = read('application.argoproj.io', APP) or {}
    if not quiet(app) or app.get('metadata', {}).get('uid') != state['application_uid']:
        raise RuntimeError('Access Application identity or operation changed')
    if stage == 'legacy':
        observe_legacy(payload)
        managers = [f.get('manager') for f in app['metadata'].get('managedFields', []) if 'f:spec' in f.get('fieldsV1', {})]
        if not managers or set(managers) != {'cloudlab-access-bootstrap'}:
            raise RuntimeError('Legacy access field ownership changed')
    else:
        desired = copy.deepcopy(native['application']); desired['spec'].pop('source', None)
        actual = copy.deepcopy(app['spec'])
        if actual.get('source') is None: actual.pop('source', None)
        if (actual != desired['spec'] or not contains(app['metadata'], desired['metadata'])
                or app['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != TRACKING
                or not application_ready(APP, native['configuration_revision'])):
            raise RuntimeError('Native access source is not converged under its root owner')
    project = read('appproject.argoproj.io', APP) or {}
    expected = copy.deepcopy(native['project']['spec'])
    if stage == 'legacy': expected['sourceRepos'] = [native['repository']]
    if (not quiet(project) or project.get('spec') != expected
            or project.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APP):
        raise RuntimeError('Access project ownership or scope changed')
    reader_guard(native, stage)
    return {'native_owner_verified': stage == 'native', 'credentials': credentials}


def reader_guard(native, stage):
    reader_name = APP + '-source'
    external = get('externalsecret.external-secrets.io', reader_name, 'argocd')
    secret = get('secret', reader_name, 'argocd')
    repository_secrets = json.loads(kube('get', 'secrets', '-n', 'argocd', '-l',
        'argocd.argoproj.io/secret-type=repository', '-o', 'json'))['items']
    matches = [item for item in repository_secrets if all(base64.b64decode(item.get('data', {}).get(key, ''), validate=True).decode() == expected
               for key, expected in (('url', native['private_repository']), ('project', APP)))]
    if stage == 'legacy':
        if external or secret or matches:
            raise RuntimeError('Access reader name is occupied; implicit adoption refused')
    else:
        if stage == 'recovery' and external is None and secret is None:
            if matches: raise RuntimeError('Access recovery reader has foreign credentials')
            return
        if (not external or (stage != 'recovery' and not condition(external, 'Ready')) or external.get('spec') != native['reader']['spec']
                or external['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                    'cloudlab-public-root:external-secrets.io/ExternalSecret:argocd/' + reader_name
                or external['metadata'].get('ownerReferences') or external['metadata'].get('deletionTimestamp')
                or (secret is None and stage != 'recovery') or (secret is not None and secret['metadata'].get('deletionTimestamp'))):
            raise RuntimeError('Native access reader ownership or desired state changed')
        if secret is None:
            if matches: raise RuntimeError('Access recovery reader has foreign credentials')
            return
        owners = secret['metadata'].get('ownerReferences', [])
        if (len(owners) != 1 or owners[0].get('kind') != 'ExternalSecret' or owners[0].get('name') != reader_name
                or owners[0].get('apiVersion') != 'external-secrets.io/v1'
                or owners[0].get('uid') != external['metadata']['uid'] or owners[0].get('controller') is not True
                or secret['metadata'].get('labels', {}).get('argocd.argoproj.io/secret-type') != 'repository'):
            raise RuntimeError('Access reader credential lacks its exact ESO owner')
        data = {key: base64.b64decode(value, validate=True).decode() for key, value in secret.get('data', {}).items()}
        if (set(data) != set(native['reader']['spec']['target']['template']['data'])
                or data.get('url') != native['private_repository'] or data.get('project') != APP or data.get('type') != 'git'
                or not all(data.get(key) for key in ('githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey'))):
            raise RuntimeError('Access reader credential is incomplete or has another scope')
        if len(matches) != 1 or matches[0]['metadata']['uid'] != secret['metadata']['uid']:
            raise RuntimeError('Access project has duplicate or changed repository credentials')


def expected_contract(payload, target):
    template = copy.deepcopy(payload.get('access_observation'))
    if (not isinstance(template, dict) or set(template) != {'revision', 'application', 'project', 'reader'}
            or not isinstance(template['revision'], str) or not re.fullmatch('[a-f0-9]{40}', template['revision'])):
        raise RuntimeError('Published access observation metadata is missing or invalid')
    for key, kind, name in (('application', 'Application', APP), ('project', 'AppProject', APP), ('reader', 'ExternalSecret', APP + '-source')):
        obj = template[key]
        version = 'external-secrets.io/v1' if key == 'reader' else 'argoproj.io/v1alpha1'
        if (obj.get('apiVersion') != version or obj.get('kind') != kind or obj.get('metadata', {}).get('name') != name
                or obj['metadata'].get('namespace') != 'argocd'):
            raise RuntimeError('Access observation template scope changed')
    application = template['application']
    sources = application.get('spec', {}).get('sources')
    if (application.get('spec', {}).get('source') is not None
            or application['spec'].get('project') != APP
            or application['spec'].get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'tailscale'}
            or application['metadata'].get('labels', {}).get('cloudlab.io/owner') != 'access-platform'
            or template['reader'].get('spec', {}).get('target', {}).get('name') != APP + '-source'
            or template['reader'].get('spec', {}).get('target', {}).get('template', {}).get('data', {}).get('project') != APP
            or sources != [
            {'repoURL': payload['repository'], 'targetRevision': template['revision'], 'path': 'platform/connectivity/access',
             'helm': {'releaseName': APP, 'valueFiles': ['$values/platform/access.yaml']}},
            {'repoURL': payload['private_repository'], 'targetRevision': '0' * 40, 'ref': 'values'}]
            or template['project'].get('spec', {}).get('sourceRepos') != [payload['repository'], payload['private_repository']]
            or template['reader'].get('spec', {}).get('target', {}).get('template', {}).get('data', {}).get('url') != payload['private_repository']):
        raise RuntimeError('Access observation template source slots changed')
    sources[1]['targetRevision'] = target['valuesRevision']
    state = authority.receipt()
    evidence = {'required': True, 'enabled': True, 'repository': payload['repository'], 'revision': template['revision'],
        'private_repository': payload['private_repository'], 'private_revision': target['valuesRevision'], 'administratorHash': state['administrator']}
    contract = {'repository': payload['repository'], 'public_revision': payload['revision'], 'configuration_revision': template['revision'],
        'private_repository': payload['private_repository'], 'private_revision': target['valuesRevision'], 'evidence': evidence,
        **{k: template[k] for k in ('application', 'project', 'reader')}}
    return contract


def prerequisite(payload, *, recovery=None):
    if recovery is not None:
        return recovery_observer(payload, recovery)
    target = binding(payload)
    if target is None:
        return observe_legacy(payload)
    return guard(expected_contract(payload, target))


def recovery_observer(payload, context):
    if (payload.get('argo', {}).get('recovery') is not True or not isinstance(context, dict)
            or set(context) != {'checkpoint', 'sourceState', 'rootSource'}):
        raise RuntimeError('Access recovery requires explicit authenticated context')
    checkpoint = binding_receipt()
    target = payload['argo']['target']
    root = get('application.argoproj.io', 'cloudlab-public-root', 'argocd') or {}
    source = root.get('spec', {}).get('source', {})
    if (checkpoint != context['checkpoint'] or checkpoint.get('phase') not in ('prepared', 'paused', 'source-updated', 'resumed')
            or checkpoint.get('target') != target or target.get('valuesRepository') != payload['private_repository']
            or not isinstance(target.get('valuesRevision'), str) or not re.fullmatch('[a-f0-9]{40}', target['valuesRevision'])
            or context['sourceState'] not in ('original', 'patched') or source != context['rootSource']
            or root.get('spec', {}).get('project') != 'cloudlab-root' or root['spec'].get('sources')
            or source.get('repoURL') != payload['repository'] or source.get('targetRevision') != payload['branch']
            or source.get('path') != 'gitops/roots/public' or root['metadata'].get('deletionTimestamp')
            or root['metadata'].get('finalizers') or root['metadata'].get('ownerReferences')
            or str(root['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile', '')).lower() == 'true'
            or root.get('operation') is not None):
        raise RuntimeError('Access recovery checkpoint or public source changed')
    recorded = checkpoint.get('originalSource' if context['sourceState'] == 'original' else 'patchedSource')
    if recorded is not None and source != recorded:
        raise RuntimeError('Access recovery is outside the recorded handoff')
    if recorded is None:
        current = source.get('helm', {}).get('valuesObject', {}).get('identity', {}).get('argo')
        if ((context['sourceState'] == 'patched' and current != target)
                or (context['sourceState'] == 'original' and (current is not None or checkpoint['phase'] not in ('prepared', 'paused')))):
            raise RuntimeError('Legacy access recovery source is ambiguous')
    for key, kind, name in (('root_uid', 'application.argoproj.io', 'cloudlab-public-root'),
                            ('project_uid', 'appproject.argoproj.io', 'cloudlab-root'),
                            ('controller_uid', 'statefulset', 'argocd-application-controller')):
        obj = get(kind, name, 'argocd') or {}
        if (not checkpoint.get(key) or obj.get('metadata', {}).get('uid') != checkpoint[key]
                or obj.get('metadata', {}).get('deletionTimestamp')
                or (key == 'controller_uid' and obj.get('spec', {}).get('replicas') not in (0, 1))
                or (key == 'project_uid' and obj.get('spec', {}).get('sourceRepos') != [payload['repository']])):
            raise RuntimeError('Access recovery handoff identities changed')
    evidence = authority.guard(payload['argo'].get('accessActivation'), target,
        lambda kind, name: get(kind, name, 'argocd'), root)
    previous = checkpoint.get('accessActivation')
    if previous is not None:
        previous = authority.validate(previous, target, root)
        if any(previous[k] != evidence[k] for k in previous):
            raise RuntimeError('Access recovery cannot replace captured authority')
    state = authority.receipt()
    credentials = retained(state, payload['revision'])
    expected = expected_contract(payload, target)
    app = get('application.argoproj.io', APP, 'argocd') or {}
    if app.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') == 'cloudlab-access-bootstrap':
        observe_legacy(payload)
    else:
        desired = copy.deepcopy(expected['application']); desired['spec'].pop('source', None)
        actual = copy.deepcopy(app.get('spec', {}))
        if actual.get('source') is None: actual.pop('source', None)
        allowed = {target['valuesRevision']}
        original = checkpoint.get('originalSource', {}).get('helm', {}).get('valuesObject', {}).get('identity', {}).get('argo', {})
        if original.get('valuesRepository') == payload['private_repository'] and re.fullmatch('[a-f0-9]{40}', original.get('valuesRevision', '')):
            allowed.add(original['valuesRevision'])
        observed = actual.get('sources', [])
        if len(observed) != 2 or observed[1].get('targetRevision') not in allowed:
            raise RuntimeError('Access recovery native source is outside the handoff')
        desired['spec']['sources'][1]['targetRevision'] = observed[1]['targetRevision']
        if (not quiet(app) or app.get('metadata', {}).get('uid') != state['application_uid'] or actual != desired['spec']
                or not contains(app['metadata'], desired['metadata']) or app['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != TRACKING):
            raise RuntimeError('Pending native access ownership changed')
    project = get('appproject.argoproj.io', APP, 'argocd') or {}
    old = copy.deepcopy(expected['project']['spec']); old['sourceRepos'] = [payload['repository']]
    if (not quiet(project) or project.get('spec') not in (old, expected['project']['spec'])
            or project.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APP):
        raise RuntimeError('Access recovery project has a foreign scope')
    reader_guard(expected, 'recovery')
    return {'native_owner_verified': False, 'credentials': credentials}


def observe(payload):
    if payload.get('native') is not None:
        return guard(payload['native'])
    target = binding(payload)
    if target is not None:
        raise RuntimeError('Approved native access inputs are required; legacy fallback refused')
    return observe_legacy(payload)


if __name__ == '__main__':
    try:
        envelope = json.load(sys.stdin)
        result = guard(envelope['native'], stage=envelope.get('stage', 'native'), expected_credentials=envelope.get('expected_credentials')) if envelope.get('native') is not None else observe(envelope['public'])
        print(json.dumps({'native_owner_verified': result['native_owner_verified'], 'retained_credentials': len(result['credentials'])}))
    except Exception:
        raise SystemExit('Access ownership observation failed; private diagnostics withheld') from None
