"""Read-only gateway handoff and accepted native ownership observation."""
import base64
import copy
import hashlib
import json
import re
import sys
from ownership import APP, BASE, OWNER, retained
from kube import contains, condition, get, kube

TRACKING = 'cloudlab-public-root:argoproj.io/Application:argocd/' + APP


def current_condition(obj, name):
    return bool(obj) and obj['metadata'].get('generation') is not None and any(
        c.get('type') == name and c.get('status') == 'True' and
        c.get('observedGeneration') == obj['metadata']['generation']
        for c in obj.get('status', {}).get('conditions', []))


def quiet(obj):
    meta = obj.get('metadata', {})
    return (not meta.get('deletionTimestamp') and not meta.get('ownerReferences') and not meta.get('finalizers')
            and obj.get('operation') is None
            and str(meta.get('annotations', {}).get('argocd.argoproj.io/skip-reconcile', '')).lower() != 'true'
            and obj.get('status', {}).get('operationState', {}).get('phase') in (None, 'Succeeded'))


def gateway_ready(native):
    app = get('application.argoproj.io', APP, 'argocd') or {}
    status = app.get('status', {})
    return (quiet(app) and status.get('sync', {}).get('status') == 'Synced'
            and status.get('sync', {}).get('revisions') == [native['configuration_revision'], native['private_revision'], native['identity_revision']]
            and status.get('health', {}).get('status') == 'Healthy'
            and not any(c.get('type', '').endswith('Error') for c in status.get('conditions', [])))


def observe_legacy(payload, state):
    from initial_bootstrap import application, argo_routes
    from kube import application_ready
    retained(payload, state)
    app = get('application.argoproj.io', APP, 'argocd') or {}
    values = app.get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {})
    zone = values.get('zone')
    if (not isinstance(zone, str) or hashlib.sha256(zone.encode()).hexdigest() != state['zone_hash']
            or not quiet(app) or app.get('metadata', {}).get('uid') != state['application_uid']
            or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
            or app['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id')
            or app.get('spec') != application(payload, zone, argo_routes(zone, app))['spec']
            or not application_ready(APP, payload['revision'])):
        raise RuntimeError('Accepted initial gateway seed changed; explicit recovery review required')


def guard(native, state, payload, *, stage='native', expected_tls=None):
    from initial_bootstrap import application
    from kube import application_ready
    if (stage not in ('legacy', 'native') or not isinstance(native, dict)
            or any(not isinstance(native.get(k), str) or not re.fullmatch('[a-f0-9]{40}', native[k])
                   for k in ('public_revision', 'configuration_revision', 'private_revision', 'identity_revision'))
            or hashlib.sha256(native['values']['zone'].encode()).hexdigest() != state.get('zone_hash')):
        raise RuntimeError('Gateway handoff inputs differ from accepted ownership')
    tls = retained(payload, state)
    if expected_tls is not None and tls != expected_tls:
        raise RuntimeError('Gateway TLS changed during ownership transition')
    app = get('application.argoproj.io', APP, 'argocd') or {}
    if not quiet(app) or app.get('metadata', {}).get('uid') != state['application_uid']:
        raise RuntimeError('Gateway Application identity or active operation changed')
    desired = copy.deepcopy(native['application'])
    desired['spec'].pop('source', None)
    actual_spec = copy.deepcopy(app.get('spec', {}))
    if actual_spec.get('source') is None:
        actual_spec.pop('source', None)
    if stage == 'legacy':
        hosts = {obj['metadata']['namespace'].rsplit('-', 1)[1]: obj['spec']['hostnames'][0]
                 for obj in native['resources'] if obj['kind'] == 'HTTPRoute'}
        legacy = application(dict(repository=native['repository'], branch='main'), native['values']['zone'], hosts)
        managers = [f.get('manager') for f in app['metadata'].get('managedFields', []) if 'f:spec' in f.get('fieldsV1', {})]
        if (app['spec'] != legacy['spec'] or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                or app['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id')
                or not managers or set(managers) != {OWNER} or not application_ready(APP, native['public_revision'])):
            raise RuntimeError('Legacy gateway source or field ownership changed')
    elif (actual_spec != desired['spec'] or not contains(app['metadata'], desired['metadata'])
            or app['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != TRACKING
            or not gateway_ready(native)):
        raise RuntimeError('Native gateway source has not converged under its root owner')
    project = get('appproject.argoproj.io', APP, 'argocd') or {}
    expected = copy.deepcopy(native['project']['spec'])
    if stage == 'legacy': expected['sourceRepos'] = [native['repository']]
    if (not quiet(project) or project.get('spec') != expected
            or project.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
               'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APP):
        raise RuntimeError('Gateway project ownership or scope changed')
    reader_name = APP + '-source'
    external = get('externalsecret.external-secrets.io', reader_name, 'argocd')
    secret = get('secret', reader_name, 'argocd')
    credentials = json.loads(kube('get', 'secrets', '-n', 'argocd', '-l',
        'argocd.argoproj.io/secret-type=repository', '-o', 'json'))['items']
    matches = [item for item in credentials if all(base64.b64decode(item.get('data', {}).get(key, ''), validate=True).decode() == expected
               for key, expected in (('url', native['private_repository']), ('project', APP)))]
    if stage == 'legacy':
        if external or secret or matches:
            raise RuntimeError('Gateway reader name is occupied; implicit adoption refused')
    else:
        if (not external or not condition(external, 'Ready') or external.get('spec') != native['reader']['spec']
                or not contains(external.get('metadata', {}), native['reader']['metadata'])
                or external['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                    'cloudlab-public-root:external-secrets.io/ExternalSecret:argocd/' + reader_name
                or external['metadata'].get('ownerReferences') or external['metadata'].get('deletionTimestamp')
                or not secret or secret['metadata'].get('deletionTimestamp')):
            raise RuntimeError('Native gateway reader ownership or desired state changed')
        owners = secret['metadata'].get('ownerReferences', [])
        if (len(owners) != 1 or owners[0].get('kind') != 'ExternalSecret' or owners[0].get('name') != reader_name
                or owners[0].get('apiVersion') != 'external-secrets.io/v1'
                or owners[0].get('uid') != external['metadata']['uid'] or owners[0].get('controller') is not True
                or secret['metadata'].get('labels', {}).get('argocd.argoproj.io/secret-type') != 'repository'):
            raise RuntimeError('Gateway reader credential lacks its exact ESO owner')
        data = {key: base64.b64decode(value, validate=True).decode() for key, value in secret.get('data', {}).items()}
        if (set(data) != set(native['reader']['spec']['target']['template']['data'])
                or data.get('url') != native['private_repository'] or data.get('project') != APP or data.get('type') != 'git'
                or not all(data.get(key) for key in ('githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey'))):
            raise RuntimeError('Gateway reader credential is incomplete or has another scope')
        if len(matches) != 1 or matches[0]['metadata']['uid'] != secret['metadata']['uid']:
            raise RuntimeError('Gateway project has duplicate or changed repository credentials')
    for desired_resource in native['resources']:
        kind = desired_resource['kind']
        meta = desired_resource['metadata']
        resource = {'Gateway': 'gateway.gateway.networking.k8s.io', 'HTTPRoute': 'httproute.gateway.networking.k8s.io', 'ConfigMap': 'configmap'}[kind]
        obj = get(resource, meta['name'], meta['namespace']) or {}
        actual = copy.deepcopy(obj.get('spec', {}))
        if kind == 'HTTPRoute':
            for ref in actual.get('parentRefs', []):
                if ref.get('group') == 'gateway.networking.k8s.io': ref.pop('group')
                if ref.get('kind') == 'Gateway': ref.pop('kind')
            for rule in actual.get('rules', []):
                if rule.get('matches') == [{'path': {'type': 'PathPrefix', 'value': '/'}}]: rule.pop('matches')
                for ref in rule.get('backendRefs', []):
                    if ref.get('group') == '': ref.pop('group')
                    if ref.get('kind') == 'Service': ref.pop('kind')
                    if type(ref.get('weight')) is int and ref['weight'] == 1: ref.pop('weight')
        group = desired_resource['apiVersion'].split('/')[0] if '/' in desired_resource['apiVersion'] else ''
        tracking = APP + ':' + group + '/' + kind + ':' + meta['namespace'] + '/' + meta['name']
        if (not contains(obj.get('metadata', {}), meta) or obj.get('metadata', {}).get('deletionTimestamp')
                or obj.get('metadata', {}).get('ownerReferences')
                or obj.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id') != tracking
                or (kind == 'ConfigMap' and obj.get('data') != desired_resource['data'])
                or (kind != 'ConfigMap' and actual != desired_resource['spec'])):
            raise RuntimeError('Gateway desired resources differ from authenticated Git')
        if kind == 'Gateway' and (not current_condition(obj, 'Accepted') or not current_condition(obj, 'Programmed')):
            raise RuntimeError('Gateway current generation is not ready')
        if kind == 'HTTPRoute':
            parents = obj.get('status', {}).get('parents', [])
            defaults = {'group': 'gateway.networking.k8s.io', 'kind': 'Gateway', 'namespace': meta['namespace']}
            expected_parent = defaults | desired_resource['spec']['parentRefs'][0]
            if obj['metadata'].get('generation') is None or not any(
                    p.get('controllerName') == 'istio.io/gateway-controller'
                    and isinstance(p.get('parentRef'), dict)
                    and (defaults | p['parentRef']) == expected_parent and all(any(
                    c.get('type') == key and c.get('status') == 'True' and
                    c.get('observedGeneration') == obj['metadata'].get('generation')
                    for c in p.get('conditions', [])) for key in ('Accepted', 'ResolvedRefs')) for p in parents):
                raise RuntimeError('Gateway route current generation is not ready')
    return {'native_owner_verified': stage == 'native', 'tls': tls}


if __name__ == '__main__':
    try:
        envelope = json.load(sys.stdin)
        state = json.loads((BASE / 'ownership.json').read_text())
        if envelope['native'] is None:
            observe_legacy(envelope['public'], state)
            result = {'native_owner_verified': False, 'tls': {}}
        else:
            result = guard(envelope['native'], state, envelope['public'],
                           stage=envelope.get('stage', 'native'), expected_tls=envelope.get('expected_tls'))
        print(json.dumps({'native_owner_verified': result['native_owner_verified'], 'retained_gateways': len(result['tls'])}))
    except Exception:
        raise SystemExit('Gateway ownership observation failed; private diagnostics withheld') from None
