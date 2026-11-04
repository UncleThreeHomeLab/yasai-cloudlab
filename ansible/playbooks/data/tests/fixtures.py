"""Synthetic shared data inputs and service approvals."""
import copy
from pathlib import Path
import yaml


def shared_data():
    root = Path(__file__).resolve().parents[4]
    base = yaml.safe_load((root / 'charts/service/values.yaml').read_text())
    catalog, approvals = [], {}
    for name in ('notes', 'fixture'):
        definition = copy.deepcopy(base)
        definition['name'] = name
        definition['data'] = {kind: {'name': name, 'credentialReference': name + '-' + kind, 'retention': 'retain'} for kind in ('database', 'bucket')}
        approval = {'name': name, 'namespace': 'cloudlab-app-' + name, 'repository': 'https://github.com/example/application.git',
            'revision': 'b' * 40, 'valuesPath': 'apps/' + name + '.yaml', 'secretReferences': [name + '-database', name + '-bucket'], 'configMaps': []}
        catalog.append({'definition': definition, 'approval': approval, 'publication': 'retired' if name == 'fixture' else 'published'})
        approvals[name + '-database'] = {'kind': 'database', 'service': name, 'name': name, 'item': 'cnpg-' + name + '-production',
            'migrationItem': 'cnpg-' + name + '-migration', 'applicationRole': name + '_app', 'migrationRole': name + '_migration'}
        approvals[name + '-bucket'] = {'kind': 'bucket', 'service': name, 'name': name, 'item': 's3-' + name + '-production'}
    return {'sharedInputs': True, 'zone': 'example.invalid', 'production': True,
        'database': 'notes', 'applicationRole': 'notes_app', 'migrationRole': 'notes_migration', 'backupRole': 'backup', 'bucket': 'notes',
        'identity': {'enabled': True, 'database': 'keycloak', 'role': 'keycloak'}, 'catalog': catalog, 'dataApprovals': approvals}


def native_observation():
    """Rendered public owners and private inputs, without live services or credentials."""
    import base64
    import json
    import subprocess
    from playbooks.data.files import native
    root = Path(__file__).resolve().parents[4]
    public = yaml.safe_load((root / 'gitops/roots/public/values.yaml').read_text())
    public.update(repository='https://github.com/example/platform.git', revision='main')
    public['data']['configuration'] = {'enabled': True, 'revision': 'a' * 40, 'seaweedfsRevision': 'c' * 40}
    target = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}
    public['identity']['argo'] = target
    rendered = subprocess.run(['helm', 'template', 'root', str(root / 'gitops/roots/public'), '-n', 'argocd', '-f', '-'],
                              input=json.dumps(public), text=True, capture_output=True, check=True, timeout=30)
    objects = {}
    for obj in yaml.safe_load_all(rendered.stdout):
        if not obj:
            continue
        name = obj['metadata']['name']
        kind = {'Application': 'application.argoproj.io', 'AppProject': 'appproject.argoproj.io',
                'ExternalSecret': 'externalsecret.external-secrets.io'}.get(obj['kind'])
        if kind:
            obj['metadata'].update(uid='uid-' + name, resourceVersion='1')
            group = 'external-secrets.io' if obj['kind'] == 'ExternalSecret' else 'argoproj.io'
            obj['metadata'].setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = 'cloudlab-public-root:' + group + '/' + obj['kind'] + ':argocd/' + name
            if obj['kind'] == 'Application':
                source = obj['spec'].get('source')
                revisions = [s['targetRevision'] for s in obj['spec'].get('sources', [])]
                status = {'status': 'Synced', 'revision': source['targetRevision'] if source and len(source['targetRevision']) == 40 else 'd' * 40, 'comparedTo': {'source': copy.deepcopy(source)}}
                if revisions:
                    status.update(revisions=revisions)
                obj['status'] = {'sync': status, 'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}
            objects[kind, name, 'argocd'] = obj
    root_app = objects['application.argoproj.io', 'cloudlab-public-root', 'argocd']
    root_app['metadata'].pop('annotations', None)
    objects['statefulset', 'argocd-application-controller', 'argocd'] = {'metadata': {'uid': 'uid-controller'}, 'spec': {'replicas': 1}}
    binding = {'phase': 'accepted', 'target': target, 'root_uid': root_app['metadata']['uid'],
               'controller_uid': 'uid-controller', 'project_uid': 'uid-cloudlab-root'}
    reader = objects['externalsecret.external-secrets.io', 'cloudlab-argocd-identity-source', 'argocd']
    reader['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
    credential = {'metadata': {'name': reader['metadata']['name'], 'uid': 'uid-reader-secret',
        'labels': {'argocd.argoproj.io/secret-type': 'repository'},
        'ownerReferences': [{'uid': reader['metadata']['uid'], 'name': reader['metadata']['name'],
                            'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'controller': True}]},
        'data': {key: base64.b64encode(value.encode()).decode() for key, value in {
            'type': 'git', 'url': target['valuesRepository'], 'project': 'cloudlab-platform',
            'githubAppID': '1', 'githubAppInstallationID': '2', 'githubAppPrivateKey': 'synthetic-private-key'}.items()}}
    objects['secret', reader['metadata']['name'], 'argocd'] = credential
    data_reader = objects['externalsecret.external-secrets.io', native.APP + '-source', 'argocd']
    data_reader['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
    data_credential = copy.deepcopy(credential)
    data_credential['metadata'].update(name=data_reader['metadata']['name'], uid='uid-data-reader-secret')
    data_credential['metadata']['ownerReferences'][0].update(uid=data_reader['metadata']['uid'], name=data_reader['metadata']['name'])
    data_credential['data']['project'] = base64.b64encode(native.APP.encode()).decode()
    objects['secret', data_reader['metadata']['name'], 'argocd'] = data_credential
    objects['secrets', None, 'argocd'] = {'items': [credential, data_credential]}
    shared = shared_data()
    docs = [{'zone': shared['zone'], 'production': shared['production']},
            {k: shared[k] for k in ('database', 'applicationRole', 'migrationRole', 'backupRole', 'bucket', 'identity')},
            {k: shared[k] for k in ('catalog', 'dataApprovals')}]
    chart = root / 'platform/data/configuration'
    files = {str(p.relative_to(chart)).replace('\\', '/'): p.read_bytes() for p in chart.rglob('*') if p.is_file()}
    expected = native.render_settings(files, docs + [{'sharedInputs': True, 'maintenance': False, 'hibernated': False}])
    objects['configmap', native.SETTINGS, 'cloudlab-data'] = {'metadata': {'uid': 'uid-settings',
        'annotations': {'argocd.argoproj.io/tracking-id': native.APP + ':/ConfigMap:cloudlab-data/' + native.SETTINGS}},
        'data': {'settings': json.dumps(expected)}}
    state = {'revision': 'd' * 40, 'publicSource': {'repository': public['repository'], 'branch': 'main'},
             'applications': {name: 'uid-' + name for name in (native.APP, native.SEAWEED)}, 'settings_uid': 'uid-settings'}
    committed = copy.deepcopy(public)
    committed['identity'].pop('argo')
    return {'public': public, 'committed': committed, 'target': target, 'state': state, 'binding': binding,
            'objects': objects, 'files': files, 'documents': docs, 'expected': expected}
