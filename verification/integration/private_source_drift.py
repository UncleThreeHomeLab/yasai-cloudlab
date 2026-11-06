"""Explicit drift proof for one disposable private-source ConfigMap.

Source/ownership reads and the ConfigMap patch are not a cross-resource lock.
Recheck immediately before writes; atomic UID/version/data tests protect the ConfigMap.
"""
import json
import re
import sys
import time
import uuid

try:
    from playbooks.argocd.files.bootstrap import kube
    from playbooks.argocd.files.private_verify import application_healthy, contains
except ModuleNotFoundError:
    from bootstrap import kube
    from private_verify import application_healthy, contains

NAME = 'prices-private-source-proof'
NAMESPACE = 'cloudlab-private-prices-onboarding'
APPLICATION = NAMESPACE
SOURCE = {'name': 'prices-onboarding', 'revision': 'main', 'path': 'platform/fixtures/prices-private-source'}


class ProofError(RuntimeError):
    pass


def validate(envelope):
    if not isinstance(envelope, dict) or set(envelope) != {'verification', 'identities', 'fixture'}:
        raise ProofError('Invalid fixed-fixture proof envelope')
    verification, identities, fixture = (envelope[key] for key in ('verification', 'identities', 'fixture'))
    if (not isinstance(verification, dict) or verification.get('catalog_enabled') is not True
            or not isinstance(identities, dict) or set(identities) != {'Namespace', 'Application', 'ConfigMap'}
            or any(not isinstance(uid, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', uid) for uid in identities.values())
            or not isinstance(fixture, dict) or set(fixture) != {'revision', 'manifest'}
            or not isinstance(verification.get('configuration_revision'), str)
            or not re.fullmatch('[a-f0-9]{40}', verification['configuration_revision'])
            or fixture['revision'] != verification['configuration_revision']
            or not isinstance(verification.get('configuration_repository'), str)
            or not re.fullmatch(r'https://github[.]com/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+[.]git',
                                verification['configuration_repository'])):
        raise ProofError('Proof source revision or captured identities are invalid')
    row = SOURCE | {'repository': verification['configuration_repository']}
    if not isinstance(verification.get('sources'), list) or verification['sources'].count(row) != 1:
        raise ProofError('Approved disposable private source is missing')
    manifest = fixture['manifest']
    if (not isinstance(manifest, dict) or set(manifest) != {'apiVersion', 'kind', 'metadata', 'data'}
            or manifest['apiVersion'] != 'v1' or manifest['kind'] != 'ConfigMap'
            or manifest['metadata'] != {'name': NAME, 'namespace': NAMESPACE}
            or not isinstance(manifest['data'], dict) or set(manifest['data']) != {'marker'}
            or not isinstance(manifest['data']['marker'], str)
            or not re.fullmatch(r'v[1-9][0-9]{0,5}', manifest['data']['marker'])):
        raise ProofError('Authenticated fixture differs from the disposable marker profile')
    objects = verification.get('objects')
    if not isinstance(objects, list):
        raise ProofError('Native registration declarations are missing')
    targets = [obj for obj in objects if isinstance(obj, dict) and obj.get('metadata', {}).get('name') == NAMESPACE]
    if len(targets) != 4 or {obj.get('kind') for obj in targets} != {'Namespace', 'Application', 'AppProject', 'ExternalSecret'}:
        raise ProofError('Native registration declarations are incomplete')
    app = next(obj for obj in targets if obj['kind'] == 'Application')
    expected_spec = {'project': APPLICATION,
        'source': {'repoURL': row['repository'], 'targetRevision': 'main', 'path': row['path']},
        'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE},
        'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
            'syncOptions': ['FailOnSharedResource=true', 'ClientSideApplyMigration=false']}}
    namespace = next(obj for obj in targets if obj['kind'] == 'Namespace')
    if (app.get('apiVersion') != 'argoproj.io/v1alpha1' or app.get('spec') != expected_spec
            or app['metadata'].get('namespace') != 'argocd'
            or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != 'private-gitops'
            or namespace.get('apiVersion') != 'v1'
            or namespace['metadata'].get('labels', {}).get('cloudlab.io/owner') != 'private-gitops'):
        raise ProofError('Native registration scope differs from the approved fixture')
    return app, namespace


def read(kind, name, namespace):
    raw = kube('get', kind, name, *(['-n', namespace] if namespace else []), '--request-timeout=30s', '-o', 'json')
    return json.loads(raw)


def metadata_guard(obj, uid, tracking):
    metadata = obj.get('metadata', {})
    if (metadata.get('uid') != uid or not metadata.get('resourceVersion')
            or metadata.get('annotations', {}).get('argocd.argoproj.io/tracking-id') != tracking
            or metadata.get('ownerReferences') or metadata.get('finalizers') or metadata.get('deletionTimestamp')):
        raise ProofError('Fixture identity or ownership changed')


def guard(envelope, declarations, *, ready=False):
    identities, verification = envelope['identities'], envelope['verification']
    expected_app, expected_namespace = declarations
    namespace = read('namespace', NAMESPACE, None)
    metadata_guard(namespace, identities['Namespace'], 'cloudlab-private-sources:/Namespace:argocd/' + NAMESPACE)
    if not contains(namespace, expected_namespace):
        raise ProofError('Fixture namespace differs from its approved declaration')
    app = read('application.argoproj.io', APPLICATION, 'argocd')
    metadata_guard(app, identities['Application'],
                   'cloudlab-private-sources:argoproj.io/Application:argocd/' + APPLICATION)
    if (not contains(app, expected_app) or app.get('spec', {}).get('sources')
            or app.get('spec', {}).get('source') != expected_app['spec']['source']
            or app.get('spec', {}).get('destination') != expected_app['spec']['destination']
            or app.get('status', {}).get('sync', {}).get('revision') != verification['configuration_revision']):
        raise ProofError('Fixture Application source or revision changed')
    if ready and not application_healthy(app):
        raise ProofError('Fixture Application is not ready')
    configmap = read('configmap', NAME, NAMESPACE)
    metadata_guard(configmap, identities['ConfigMap'], APPLICATION + ':/ConfigMap:' + NAMESPACE + '/' + NAME)
    metadata = configmap['metadata']
    if (configmap.get('apiVersion') != 'v1' or configmap.get('kind') != 'ConfigMap'
            or metadata.get('name') != NAME or metadata.get('namespace') != NAMESPACE
            or metadata.get('labels', {}).get('cloudlab.io/owner')
            or 'binaryData' in configmap or configmap.get('immutable')
            or not isinstance(configmap.get('data'), dict) or set(configmap['data']) != {'marker'}):
        raise ProofError('Live fixture contains data outside the disposable profile')
    return configmap, app


def patch(configmap, data):
    operations = [{'op': 'test', 'path': '/metadata/uid', 'value': configmap['metadata']['uid']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': configmap['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/data', 'value': configmap['data']},
        {'op': 'replace', 'path': '/data/marker', 'value': data['marker']}]
    raw = kube('patch', 'configmap', NAME, '-n', NAMESPACE, '--request-timeout=30s', '--type=json', '--patch-file=/dev/stdin',
               '-o', 'json', document=operations)
    result = json.loads(raw)
    if result.get('metadata', {}).get('uid') != configmap['metadata']['uid'] or result.get('data') != data:
        raise ProofError('Fixture patch has no same-identity persistence witness')


def cleanup(envelope, declarations, nonce):
    configmap, app = guard(envelope, declarations)
    expected = envelope['fixture']['manifest']['data']
    if configmap['data'] == expected:
        return False
    if configmap['data'] != {'marker': nonce}:
        raise ProofError('Cleanup refuses drift not owned by this attempt')
    if (app.get('operation') is not None
            or app.get('status', {}).get('operationState', {}).get('phase') in ('Running', 'Terminating')):
        raise ProofError('Cleanup refuses an Application with pending reconciliation intent')
    patch(configmap, expected)
    return True


def run(envelope, *, timeout=180):
    declarations = validate(envelope)
    expected = envelope['fixture']['manifest']['data']
    configmap, _ = guard(envelope, declarations, ready=True)
    if configmap['data'] != expected:
        raise ProofError('Fixture must already match accepted Git before a new attempt')
    nonce = 'cloudlab-drift-' + uuid.uuid4().hex
    result = {'nonce_persisted': False, 'self_heal_verified': False, 'cleanup_restored': False,
              'cleanup_complete': False}
    try:
        configmap, _ = guard(envelope, declarations, ready=True)
        if configmap['data'] != expected:
            raise ProofError('Fixture changed before drift injection')
        patch(configmap, {'marker': nonce})
        result['nonce_persisted'] = True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            configmap, app = guard(envelope, declarations)
            if configmap['data'] == expected:
                if application_healthy(app):
                    result['self_heal_verified'] = True
                    break
            elif configmap['data'] != {'marker': nonce}:
                raise ProofError('Fixture drift changed outside this attempt')
            time.sleep(3)
        if not result['self_heal_verified']:
            raise ProofError('Argo did not repair the disposable marker within the observation limit')
    except ProofError as error:
        result['failure'] = str(error)
    except Exception:
        result['failure'] = 'Fixture drift operation unavailable or uncertain'
    finally:
        try:
            result['cleanup_restored'] = cleanup(envelope, declarations, nonce)
            result['cleanup_complete'] = True
            if result['cleanup_restored']:
                result['self_heal_verified'] = False
                result.setdefault('failure', 'Owned nonce restored by cleanup; Argo repair is not verified')
        except Exception:
            result['self_heal_verified'] = False
            result['failure'] = 'Owned nonce cleanup declined or unavailable; fixture drift may remain'
    return result


if __name__ == '__main__':
    try:
        raw = sys.stdin.read(1048577)
        if len(raw) > 1048576:
            raise ProofError('Proof input exceeds its bounded envelope')
        result = run(json.loads(raw))
    except Exception:
        result = {'self_heal_verified': False, 'failure': 'Fixture proof input or initial guards failed'}
    print(json.dumps(result))
    raise SystemExit(0 if result['self_heal_verified'] else 1)
