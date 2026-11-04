"""Read-only certificate ownership handoff and accepted native-source observation."""
import base64
import copy
import hashlib
import json
import re
import sys

from kube import BASE, application_ready, contains, get, kube, ready

APP = 'cloudlab-certificates'
LEGACY = 'cloudlab-certificates-bootstrap'
TRACKING = 'cloudlab-public-root:argoproj.io/Application:argocd/' + APP


def digest(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def receipt(state):
    if (not isinstance(state, dict) or state.get('phase') != 'accepted'
            or not isinstance(state.get('application_uid'), str) or not state['application_uid']
            or not re.fullmatch('[a-f0-9]{64}', state.get('zone_hash', ''))
            or set(state.get('identities', {})) != {'public', 'private'}
            or set(state.get('accounts', {})) != {'staging', 'production'}):
        raise RuntimeError('Accepted certificate ownership receipt is incomplete')
    for identity in [state.get('staging', {})] + list(state['identities'].values()):
        if (set(identity) != {'certificate_uid', 'secret_uid'}
                or any(not isinstance(value, str) or not value for value in identity.values())):
            raise RuntimeError('Retained certificate identities are incomplete')
    for account in state['accounts'].values():
        if (set(account) != {'uid', 'content'} or not isinstance(account['uid'], str) or not account['uid']
                or not re.fullmatch('[a-f0-9]{64}', account['content'])):
            raise RuntimeError('Retained account identities are incomplete')


def quiet(obj):
    metadata = obj.get('metadata', {})
    return (not metadata.get('deletionTimestamp') and not metadata.get('ownerReferences')
            and not metadata.get('finalizers') and not obj.get('operation')
            and str(metadata.get('annotations', {}).get('argocd.argoproj.io/skip-reconcile', '')).lower() != 'true'
            and obj.get('status', {}).get('operationState', {}).get('phase') in (None, 'Succeeded'))


def retained(state, *, expected_tls=None):
    result = {}
    for key, name, namespace, identity in (
            ('staging', 'cloudlab-staging', 'cert-manager', state['staging']),
            *[(kind, 'cloudlab-gateway', 'cloudlab-gateway-' + kind, state['identities'][kind])
              for kind in ('public', 'private')]):
        obj = get('certificate.cert-manager.io', name, namespace)
        if not ready(obj) or obj['metadata']['uid'] != identity['certificate_uid']:
            raise RuntimeError('Retained certificate identity or current readiness changed')
        secret = get('secret', obj['spec']['secretName'], namespace)
        if (not secret or secret['metadata'].get('uid') != identity['secret_uid']
                or secret['metadata'].get('deletionTimestamp')
                or secret.get('type') != 'kubernetes.io/tls' or not {'tls.crt', 'tls.key'} <= secret.get('data', {}).keys()
                or secret['metadata'].get('annotations', {}).get('cert-manager.io/certificate-name') != name):
            raise RuntimeError('Retained TLS credential ownership changed')
        result[key] = dict(identity, content=digest(secret['data']))
    for stage, expected in state['accounts'].items():
        secret = get('secret', 'cloudlab-acme-' + stage, 'cert-manager')
        if (not secret or secret['metadata'].get('deletionTimestamp')
                or {'uid': secret['metadata']['uid'], 'content': digest(secret.get('data', {}))} != expected):
            raise RuntimeError('Retained ACME account identity or content changed')
    if expected_tls is not None and result != expected_tls:
        raise RuntimeError('TLS credentials changed during the ownership transition')
    return result


def observe_legacy(payload, state):
    """An accepted initial seed is observed without re-reading provider inputs."""
    receipt(state)
    if not application_ready('cloudlab-cert-manager', payload['revision']):
        raise RuntimeError('Certificate operator has not converged to the active public revision')
    app = get('application.argoproj.io', APP, 'argocd') or {}
    source = app.get('spec', {}).get('source', {})
    values = source.get('helm', {}).get('valuesObject', {})
    if (not quiet(app) or app.get('metadata', {}).get('uid') != state['application_uid']
            or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != LEGACY
            or app['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id')
            or app.get('spec', {}).get('sources') or app.get('spec', {}).get('project') != APP
            or source.get('repoURL') != payload['repository'] or source.get('targetRevision') != payload['branch']
            or source.get('path') != 'platform/certificates/configuration'
            or set(values) != {'zone', 'production'} or values['production'] is not True
            or not isinstance(values['zone'], str)
            or hashlib.sha256(values['zone'].encode()).hexdigest() != state['zone_hash']
            or not application_ready(APP, payload['revision'])):
        raise RuntimeError('Accepted initial certificate source changed; explicit recovery review required')
    from initial_bootstrap import application
    if app['spec'] != application(payload, values['zone'], True)['spec']:
        raise RuntimeError('Accepted initial certificate configuration policy changed')
    retained(state)


def guard(native, state, *, stage='native', expected_tls=None):
    """Expectations come from authenticated private values and reviewed public charts."""
    receipt(state)
    if (stage not in ('legacy', 'native') or not isinstance(native, dict)
            or any(not isinstance(native.get(field), str) or not re.fullmatch('[a-f0-9]{40}', native[field])
                   for field in ('public_revision', 'configuration_revision', 'private_revision'))
            or hashlib.sha256(native['values']['zone'].encode()).hexdigest() != state['zone_hash']
            or (stage == 'legacy' and native['values']['production'] is not True)):
        raise RuntimeError('Certificate handoff inputs differ from accepted ownership')
    if not application_ready('cloudlab-cert-manager', native['public_revision']):
        raise RuntimeError('Certificate operator has not converged to the active public revision')
    app = get('application.argoproj.io', APP, 'argocd') or {}
    if not quiet(app) or app.get('metadata', {}).get('uid') != state['application_uid']:
        raise RuntimeError('Certificate Application identity or active operation changed')
    desired = copy.deepcopy(native['application'])
    desired['spec'].pop('source', None)
    normalized = copy.deepcopy(app)
    if normalized.get('spec', {}).get('source') is None:
        normalized['spec'].pop('source', None)
    if stage == 'legacy':
        legacy_spec = copy.deepcopy(desired['spec'])
        legacy_spec.pop('sources')
        legacy_spec['source'] = {'repoURL': native['repository'], 'targetRevision': 'main',
            'path': 'platform/certificates/configuration', 'helm': {'releaseName': APP, 'valuesObject': native['values']}}
        if (app['metadata'].get('labels', {}).get('cloudlab.io/owner') != LEGACY
                or app['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id')
                or app['spec'] != legacy_spec
                or not any(field.get('manager') == LEGACY and 'f:spec' in field.get('fieldsV1', {})
                           for field in app['metadata'].get('managedFields', []))
                or any(field.get('manager') != LEGACY and 'f:spec' in field.get('fieldsV1', {})
                       for field in app['metadata'].get('managedFields', []))
                or not application_ready(APP, native['public_revision'])):
            raise RuntimeError('Legacy certificate source or field ownership changed')
    elif (app.get('spec', {}).get('source') is not None or normalized.get('spec') != desired['spec']
            or not contains(normalized.get('metadata', {}), desired['metadata'])
            or app['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != TRACKING
            or not application_ready(APP, native['configuration_revision'], native['private_revision'])):
        raise RuntimeError('Native certificate source has not converged under its root owner')
    project = get('appproject.argoproj.io', APP, 'argocd') or {}
    expected = native['project']['spec']
    if (not quiet(project) or project.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
            'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APP
            or any(project.get('spec', {}).get(field) != expected[field] for field in
                   ('destinations', 'clusterResourceWhitelist', 'namespaceResourceWhitelist'))
            or project.get('spec', {}).get('sourceRepos') != ([native['repository']] if stage == 'legacy' else expected['sourceRepos'])
            or project.get('spec', {}).get('roles') or project.get('spec', {}).get('sourceNamespaces')):
        raise RuntimeError('Certificate project ownership or scope changed')
    reader_name = APP + '-source'
    external = get('externalsecret.external-secrets.io', reader_name, 'argocd')
    secret = get('secret', reader_name, 'argocd')
    credentials = json.loads(kube('get', 'secrets', '-n', 'argocd', '-l',
        'argocd.argoproj.io/secret-type=repository', '-o', 'json'))['items']
    matches = [item for item in credentials if all(base64.b64decode(item.get('data', {}).get(key, ''), validate=True).decode() == expected
               for key, expected in (('url', native['private_repository']), ('project', APP)))]
    if stage == 'legacy':
        if external or secret or matches:
            raise RuntimeError('Certificate reader name is occupied; implicit adoption refused')
    else:
        if (not external or not ready(external) or external.get('spec') != native['reader']['spec']
                or external['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                    'cloudlab-public-root:external-secrets.io/ExternalSecret:argocd/' + reader_name
                or external['metadata'].get('ownerReferences') or external['metadata'].get('deletionTimestamp')
                or not secret or secret['metadata'].get('deletionTimestamp')):
            raise RuntimeError('Native certificate reader ownership or desired state changed')
        owners = secret['metadata'].get('ownerReferences', [])
        if (len(owners) != 1 or owners[0].get('kind') != 'ExternalSecret' or owners[0].get('name') != reader_name
                or owners[0].get('apiVersion') != 'external-secrets.io/v1'
                or owners[0].get('uid') != external['metadata']['uid'] or owners[0].get('controller') is not True
                or secret['metadata'].get('labels', {}).get('argocd.argoproj.io/secret-type') != 'repository'):
            raise RuntimeError('Certificate reader credential lacks its exact ESO owner')
        data = {key: base64.b64decode(value, validate=True).decode() for key, value in secret.get('data', {}).items()}
        if (set(data) != set(native['reader']['spec']['target']['template']['data'])
                or data.get('url') != native['private_repository'] or data.get('project') != APP or data.get('type') != 'git'
                or not all(data.get(key) for key in ('githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey'))):
            raise RuntimeError('Certificate reader credential is incomplete or has another scope')
        if len(matches) != 1 or matches[0]['metadata']['uid'] != secret['metadata']['uid']:
            raise RuntimeError('Certificate project has duplicate or changed repository credentials')
    for desired_resource in native['resources']:
        kind = desired_resource['kind']
        resource = {'Namespace': 'namespace', 'ClusterIssuer': 'clusterissuer.cert-manager.io',
                    'Certificate': 'certificate.cert-manager.io'}[kind]
        actual = get(resource, desired_resource['metadata']['name'], desired_resource['metadata'].get('namespace'))
        if (not actual or actual['metadata'].get('deletionTimestamp') or not contains(actual, desired_resource)
                or (kind != 'Namespace' and not ready(actual))):
            raise RuntimeError('Certificate declarations or current readiness differ from accepted Git')
    return {'tls': retained(state, expected_tls=expected_tls), 'native_owner_verified': stage == 'native'}


if __name__ == '__main__':
    try:
        envelope = json.load(sys.stdin)
        result = guard(envelope['native'], json.loads((BASE / 'ownership.json').read_text()),
                       stage=envelope.get('stage', 'native'), expected_tls=envelope.get('expected_tls'))
        print(json.dumps({'native_owner_verified': result['native_owner_verified'], 'retained_certificates': len(result['tls'])}))
    except Exception:
        raise SystemExit('Certificate ownership observation failed; private diagnostics withheld') from None
