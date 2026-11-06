"""Opt-in synthetic ESO proof; run through Compose with --run RUN --namespace NAMESPACE.

Only this fixture's namespace, Fake SecretStore, two rendered ExternalSecrets and
their generated Secrets are mutated. No vault access or application resources.
"""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time


ERROR = 'Required data secret field is missing or empty'
LABEL = 'cloudlab.io/data-secret-proof'


def remote(envelope):
    from playbooks.istio.files.kube import get, kube

    run, namespace = envelope['run'], envelope['namespace']
    if (not re.fullmatch('[a-f0-9]{16}', run) or namespace != 'cloudlab-app-data-proof-' + run):
        raise RuntimeError('Synthetic proof requires its unique scoped namespace')
    store_name = 'data-proof-' + run
    labels = {LABEL: run}
    created = {}
    created_labels = {}
    targets = {}
    paths = {'Namespace': '/api/v1/namespaces/',
             'Secret': '/api/v1/namespaces/' + namespace + '/secrets/',
             'SecretStore': '/apis/external-secrets.io/v1/namespaces/' + namespace + '/secretstores/',
             'ExternalSecret': '/apis/external-secrets.io/v1/namespaces/' + namespace + '/externalsecrets/'}

    def read(kind, name):
        return get(kind, name, None if kind == 'Namespace' else namespace)

    def owned(kind, name):
        obj = read(kind, name)
        if obj and (obj['metadata']['uid'] != created[(kind, name)] or
                    any(obj['metadata'].get('labels', {}).get(key) != value
                        for key, value in created_labels[(kind, name)].items())):
            raise RuntimeError('Synthetic resource identity changed; mutation refused')
        if obj and kind == 'Namespace':
            actual = dict(obj['metadata'].get('labels', {}))
            actual.pop('kubernetes.io/metadata.name', None)
            if (actual != created_labels[(kind, name)] or obj['metadata'].get('ownerReferences') or
                    obj['metadata'].get('finalizers') or
                    obj.get('spec', {}).get('finalizers', []) not in ([], ['kubernetes'])):
                raise RuntimeError('Synthetic namespace native ownership changed; cleanup refused')
        return obj

    def create(obj):
        kind, name = obj['kind'], obj['metadata']['name']
        if read(kind, name):
            raise RuntimeError('Synthetic resource already exists; adoption refused')
        actual = json.loads(kube('create', '-f', '-', '-o', 'json', document=obj))
        created[(kind, name)] = actual['metadata']['uid']
        created_labels[(kind, name)] = dict(obj['metadata'].get('labels', {}))
        return actual

    def wait(check, phase):
        end = time.monotonic() + 240
        while time.monotonic() < end:
            if check():
                return
            time.sleep(3)
        raise RuntimeError('Synthetic proof timed out: ' + phase)

    def events():
        return (get('events', namespace=namespace) or {})['items']

    def errors_before():
        return {obj['metadata']['uid']: obj['metadata']['resourceVersion'] for obj in events()}

    def target(name):
        obj = read('Secret', name)
        if not obj:
            return None
        owner = created[('ExternalSecret', name)]
        if not any(ref.get('uid') == owner and ref.get('controller') is True
                   and ref.get('kind') == 'ExternalSecret' for ref in obj['metadata'].get('ownerReferences', [])):
            raise RuntimeError('Synthetic target has a foreign owner')
        uid = obj['metadata']['uid']
        if name in targets and targets[name] != uid:
            raise RuntimeError('Synthetic target UID changed')
        targets[name] = uid
        return obj

    def failed(before, retained=None):
        fresh = set()
        for event in events():
            ref = event.get('involvedObject', {})
            name = ref.get('name')
            if ref.get('uid') != created.get(('ExternalSecret', name)) or event.get('type') != 'Warning':
                continue
            if before.get(event['metadata']['uid']) == event['metadata']['resourceVersion']:
                continue
            if event.get('reason') != 'UpdateFailed' or ERROR not in event.get('message', ''):
                raise RuntimeError('Synthetic ESO failure differs from required template guard; values withheld')
            fresh.add(name)
        for name in ('database', 'bucket'):
            secret = target(name)
            if retained is None:
                if secret:
                    raise RuntimeError('Incomplete synthetic credentials created a target')
            elif not secret or (secret['metadata']['uid'], secret.get('data')) != retained[name]:
                raise RuntimeError('Incomplete synthetic credentials changed a valid target')
            obj = owned('ExternalSecret', name)
            if not any(c.get('type') == 'Ready' and c.get('status') == 'False'
                       for c in obj.get('status', {}).get('conditions', [])):
                return False
        return fresh == {'database', 'bucket'}

    def delivered(data):
        for name in ('database', 'bucket'):
            obj = owned('ExternalSecret', name)
            if not any(c.get('type') == 'Ready' and c.get('status') == 'True'
                       for c in obj.get('status', {}).get('conditions', [])):
                return False
            secret = target(name)
            if not secret:
                return False
            expected = {key: base64.b64encode(value.encode()).decode()
                        for key, value in data[name].items() if key != 'unapproved'}
            if secret.get('data') != expected:
                return False
        return True

    def update(data):
        obj = owned('SecretStore', store_name)
        obj['spec']['provider']['fake']['data'] = [
            {'key': 'approved-' + name + '-item', 'value': json.dumps(values)} for name, values in data.items()]
        kube('replace', '-f', '-', '-o', 'json', document=obj)

    def injected_default(obj):
        meta = obj['metadata']
        if meta.get('ownerReferences') or meta.get('finalizers') or obj.get('binaryData'):
            return False
        if obj['kind'] == 'ServiceAccount' and meta['name'] == 'default':
            return (not meta.get('labels') and not meta.get('annotations') and not meta.get('managedFields')
                    and not obj.get('secrets') and set(obj) <= {'apiVersion', 'kind', 'metadata', 'secrets'})
        if obj['kind'] != 'ConfigMap' or set(obj) != {'apiVersion', 'kind', 'metadata', 'data'}:
            return False
        name = meta['name']
        if name in ('istio-ca-root-cert', 'istio-ca-crl'):
            manager, field, control_namespace = 'pilot-discovery', (
                'root-cert.pem' if name == 'istio-ca-root-cert' else 'ca-crl.pem'), 'istio-system'
            if meta.get('labels') != {'istio.io/config': 'true'} or meta.get('annotations'):
                return False
        elif name == 'kube-root-ca.crt':
            manager, field, control_namespace = 'k3s', 'ca.crt', 'default'
            if meta.get('labels') or set(meta.get('annotations', {})) != {'kubernetes.io/description'}:
                return False
        else:
            return False
        if set(obj['data']) != {field} or not isinstance(obj['data'][field], str) or (name != 'istio-ca-crl' and not obj['data'][field]):
            return False
        managed = meta.get('managedFields', [])
        if not managed or any(row.get('manager') != manager or row.get('operation') != 'Update'
                              or row.get('apiVersion') != 'v1' or row.get('fieldsType') != 'FieldsV1' for row in managed):
            return False
        if not any('f:' + field in row.get('fieldsV1', {}).get('f:data', {}) and
                   (control_namespace != 'istio-system' or 'f:istio.io/config' in row.get('fieldsV1', {}).get(
                       'f:metadata', {}).get('f:labels', {})) for row in managed):
            return False
        control = get('configmap', name, control_namespace)
        return bool(control and obj['data'] == control.get('data') and
                    meta.get('labels', {}) == control['metadata'].get('labels', {}) and
                    meta.get('annotations', {}) == control['metadata'].get('annotations', {}) and
                    not control.get('binaryData') and not control['metadata'].get('ownerReferences') and
                    not control['metadata'].get('finalizers'))

    def normal_finalizers(obj):
        meta = obj['metadata']
        if not meta.get('finalizers'):
            return True
        return (obj['kind'] == 'ExternalSecret' and created.get(('ExternalSecret', meta['name'])) == meta['uid']
                and meta.get('labels', {}).get(LABEL) == run
                and meta['finalizers'] == ['externalsecrets.external-secrets.io/externalsecret-cleanup']
                and any(row.get('manager') == 'external-secrets' and
                        'f:finalizers' in row.get('fieldsV1', {}).get('f:metadata', {})
                        for row in meta.get('managedFields', [])))

    def cleanup():
        nonlocal stage
        stage = 'cleanup-ownership'
        if ('Namespace', namespace) not in created:
            return
        if not owned('Namespace', namespace):
            return
        for name in ('database', 'bucket'):
            if ('ExternalSecret', name) in created:
                target(name)
        # Complete discovery must succeed before any deletion, including namespace cascading deletion.
        stage = 'cleanup-discovery'
        resources = kube('api-resources', '--cached=false', '--namespaced=true', '--verbs=list', '-o', 'name').splitlines()
        if not resources:
            raise RuntimeError('Synthetic cleanup discovery is incomplete')
        known = set(created.values()) | set(targets.values())
        stage = 'cleanup-inventory'
        for resource in sorted(set(resources)):
            listing = json.loads(kube('get', resource, '-n', namespace, '--chunk-size=0', '--show-managed-fields=true', '-o', 'json'))
            if listing.get('metadata', {}).get('continue') or not isinstance(listing.get('items'), list):
                raise RuntimeError('Synthetic cleanup inventory is incomplete')
            for obj in listing['items']:
                meta = obj['metadata']
                if not normal_finalizers(obj):
                    raise RuntimeError('Unexpected finalizer blocks synthetic cleanup')
                if meta['uid'] in known:
                    continue
                default = injected_default(obj)
                event = obj['kind'] == 'Event' and (obj.get('involvedObject') or obj.get('regarding') or {}).get('uid') in known
                if not default and not event:
                    raise RuntimeError('Foreign namespace resource blocks synthetic cleanup')
        stage = 'cleanup-externalsecrets'
        for name in ('database', 'bucket'):
            obj = owned('ExternalSecret', name) if ('ExternalSecret', name) in created else None
            if obj:
                if not normal_finalizers(obj):
                    raise RuntimeError('Unexpected finalizer blocks synthetic cleanup')
                kube('delete', '--raw=' + paths['ExternalSecret'] + name, '-f', '-', document={
                    'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {
                        'uid': obj['metadata']['uid'], 'resourceVersion': obj['metadata']['resourceVersion']}})
        wait(lambda: all(read('ExternalSecret', name) is None for name in ('database', 'bucket')), 'owner cleanup')
        stage = 'cleanup-targets'
        for name in ('database', 'bucket'):
            obj = target(name)
            if obj:
                kube('delete', '--raw=' + paths['Secret'] + name, '-f', '-', document={
                    'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {
                        'uid': obj['metadata']['uid'], 'resourceVersion': obj['metadata']['resourceVersion']}})
        stage = 'cleanup-store-and-namespace'
        for kind, name in reversed(list(created)):
            if kind == 'ExternalSecret':
                continue
            obj = owned(kind, name)
            if obj:
                if obj['metadata'].get('finalizers'):
                    raise RuntimeError('Unexpected finalizer blocks synthetic cleanup')
                kube('delete', '--raw=' + paths[kind] + name, '-f', '-', document={
                    'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {
                        'uid': obj['metadata']['uid'], 'resourceVersion': obj['metadata']['resourceVersion']}})
        stage = 'cleanup-namespace-wait'
        wait(lambda: read('Namespace', namespace) is None, 'cleanup')

    result = {'initial_blocked': False, 'completed': False, 'partial_retained': False, 'resumed': False, 'cleanup': False}
    cleanup_authorized = not envelope.get('cleanup_only')
    stage = 'preflight-controller'
    try:
        if envelope.get('cleanup_only'):
            stage = 'cleanup-resume-validation'
            selected = envelope['namespace_document']
            if selected['kind'] != 'Namespace' or selected['metadata']['name'] != namespace:
                raise RuntimeError('Cleanup requires the exact selected native namespace')
            expected = {('Namespace', namespace), ('SecretStore', store_name),
                        ('ExternalSecret', 'database'), ('ExternalSecret', 'bucket'),
                        ('Secret', 'database'), ('Secret', 'bucket')}
            identities = envelope['identities']
            if (len(identities) != len(expected) or
                    {(row['kind'], row['name']) for row in identities} != expected):
                raise RuntimeError('Cleanup requires exactly the recorded six synthetic identities')
            for row in identities:
                kind, name, uid = row['kind'], row['name'], row['uid']
                obj = read(kind, name)
                if not isinstance(uid, str) or not uid or not obj or obj['metadata']['uid'] != uid:
                    raise RuntimeError('Recorded synthetic cleanup identity changed or is unavailable')
                if kind == 'Secret':
                    targets[name] = uid
                else:
                    created[(kind, name)] = uid
                    created_labels[(kind, name)] = {**selected['metadata']['labels'], **labels} if kind == 'Namespace' else dict(labels)
            for kind, name in created:
                owned(kind, name)
            for name in targets:
                target(name)
            created = {key: created[key] for key in (
                ('Namespace', namespace), ('SecretStore', store_name), ('ExternalSecret', 'database'), ('ExternalSecret', 'bucket'))}
            cleanup_authorized = True
            # Resource versions may advance normally; cleanup rereads and deletes with each current UID/RV.
            return result
        deployment = get('deployment', 'external-secrets', 'external-secrets') or {}
        containers = deployment.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
        if not any(row.get('image') == envelope['image'] for row in containers):
            raise RuntimeError('Live ESO does not match the pinned controller image')
        status = deployment.get('status', {})
        if (status.get('readyReplicas', 0) < 1 or
                status.get('observedGeneration') != deployment.get('metadata', {}).get('generation')):
            raise RuntimeError('Pinned ESO controller is not ready')
        stage = 'preflight-api'
        api = json.loads(kube('get', '--raw=/apis/external-secrets.io/v1'))
        if not {'externalsecrets', 'secretstores'} <= {row['name'] for row in api['resources']}:
            raise RuntimeError('Pinned ESO v1 APIs unavailable')
        stage = 'namespace-create'
        namespace_document = envelope['namespace_document']
        if (namespace_document['apiVersion'] != 'v1' or namespace_document['kind'] != 'Namespace'
                or namespace_document['metadata']['name'] != namespace):
            raise RuntimeError('Synthetic proof requires its selected native namespace')
        namespace_document['metadata'].setdefault('labels', {}).update(labels)
        create(namespace_document)
        data = {'database': {'username': '0', 'password': 'synthetic\npassword\n', 'unapproved': 'excluded'},
                'bucket': {key: 'synthetic-' + key for key in ('BUCKET', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY', 'ENDPOINT', 'REGION')}}
        data['bucket']['REGION'] = '0'
        initial = copy.deepcopy(data)
        del initial['database']['password']
        initial['bucket']['REGION'] = ''
        store = {'apiVersion': 'external-secrets.io/v1', 'kind': 'SecretStore',
                 'metadata': {'name': store_name, 'namespace': namespace, 'labels': labels},
                 'spec': {'provider': {'fake': {'data': [
                     {'key': 'approved-' + name + '-item', 'value': json.dumps(values)} for name, values in initial.items()]}}}}
        stage = 'store-admission'
        admission = kube('create', '--dry-run=server', '-f', '-', '-o', 'json', document=store, allow_failure=True)
        if admission.returncode:
            raise RuntimeError('Pinned ESO Fake provider admission unavailable; no bypass supported')
        stage = 'store-create'
        create(store)

        def store_ready():
            obj = owned('SecretStore', store_name)
            conditions = obj.get('status', {}).get('conditions', [])
            if any(c.get('status') == 'False' for c in conditions):
                raise RuntimeError('Pinned ESO Fake provider unavailable; fake/all_providers build required')
            return any(c.get('type') == 'Ready' and c.get('status') == 'True' for c in conditions)

        stage = 'store-readiness'
        wait(store_ready, 'Fake provider readiness')
        stage = 'externalsecrets-create'
        before = errors_before()
        documents = envelope['documents']
        if len(documents) != 2 or {obj['metadata']['name'] for obj in documents} != {'database', 'bucket'}:
            raise RuntimeError('Synthetic proof requires exactly two selected data ExternalSecrets')
        for obj in documents:
            if obj['kind'] != 'ExternalSecret' or obj['metadata']['namespace'] != namespace:
                raise RuntimeError('Synthetic proof refuses resources outside selected data ExternalSecrets')
            obj['metadata'].setdefault('labels', {}).update(labels)
            obj['spec']['secretStoreRef'] = {'name': store_name, 'kind': 'SecretStore'}
            obj['spec']['refreshInterval'] = '5s'
            create(obj)
        stage = 'initial-guard'
        wait(lambda: failed(before), 'initial guard')
        result['initial_blocked'] = True
        stage = 'completion-store-update'
        update(data)
        stage = 'completion-delivery'
        wait(lambda: delivered(data), 'initial completion')
        result['completed'] = True
        retained = {name: (target(name)['metadata']['uid'], target(name)['data']) for name in ('database', 'bucket')}
        partial = copy.deepcopy(data)
        partial['database']['password'] = ''
        del partial['bucket']['REGION']
        before = errors_before()
        stage = 'partial-store-update'
        update(partial)
        stage = 'partial-retention'
        wait(lambda: failed(before, retained), 'partial retention')
        result['partial_retained'] = True
        changed = {name: {key: value + '-changed' for key, value in values.items()} for name, values in data.items()}
        stage = 'resumption-store-update'
        update(changed)
        stage = 'resumption-delivery'
        wait(lambda: delivered(changed), 'automatic resumption')
        result['resumed'] = True
    except Exception as error:
        result['failure_stage'] = stage
        result['failure'] = str(error) if type(error) is RuntimeError else 'Synthetic proof operation failed; values withheld'
    finally:
        try:
            if cleanup_authorized:
                cleanup()
                result['cleanup'] = True
        except Exception:
            result['cleanup_failure_stage'] = stage
            result['cleanup_failure'] = 'Synthetic cleanup blocked; inspect scoped resources without force-finalizing'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True)
    parser.add_argument('--namespace', required=True)
    parser.add_argument('--cleanup-only', action='store_true', help='Read six recorded kind/name/uid identities as a JSON list on stdin; only clean up')
    args = parser.parse_args()
    if not re.fullmatch('[a-f0-9]{16}', args.run) or args.namespace != 'cloudlab-app-data-proof-' + args.run:
        parser.error('Use a unique 16-character lowercase hex run and cloudlab-app-data-proof-RUN namespace')
    from dotenv import dotenv_values
    from playbooks.access.files.preflight import ssh
    from playbooks.services.tests.fixtures import data_secret_documents
    root = Path(__file__).resolve().parents[4]
    values = dotenv_values(root / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD', 'VM_PORT'):
        os.environ[key] = values.get(key) or ('22' if key == 'VM_PORT' else '')
    if any(not os.environ[key] for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD')):
        raise RuntimeError('Existing VM inspection credentials required')
    selected = data_secret_documents(args.namespace)
    pin = json.loads((root / 'platform/secrets/external-secrets/artifact.lock.json').read_text())['images']
    image, digest = next(iter(pin.items()))
    envelope = dict(selected, run=args.run, namespace=args.namespace, image=image + '@' + digest)
    if args.cleanup_only:
        envelope.update(cleanup_only=True, identities=json.load(sys.stdin))
    source = Path(__file__).read_text()
    code = "import sys;sys.path.insert(0,'/opt/cloudlab');" + source
    output = ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(code) + ' --remote',
                 input=json.dumps(envelope), timeout=1500)
    result = json.loads(output)
    print(json.dumps(result, sort_keys=True))
    return (result.get('cleanup') is True and not result.get('failure')) if args.cleanup_only else all(
        result.get(key) is True for key in ('initial_blocked', 'completed', 'partial_retained', 'resumed', 'cleanup'))


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--remote']:
            print(json.dumps(remote(json.load(sys.stdin)), sort_keys=True))
        else:
            raise SystemExit(0 if main() else 1)
    except Exception:
        raise SystemExit('Synthetic data secret proof unavailable; values withheld') from None
