"""Synthetic authenticated inputs and accepted certificate ownership fixtures."""
import base64
import copy
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock, patch

import yaml
import inputs
import initial_bootstrap
import native


def prepared():
    public = yaml.safe_load((Path(__file__).resolve().parents[4] / 'gitops/roots/public/values.yaml').read_text())
    public['repository'] = 'https://github.com/example/platform.git'
    values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
    binding = {'valuesRepository': values['PRIVATE_CONFIG_REPOSITORY'], 'valuesRevision': 'b' * 40}
    raw = json.dumps({'zone': 'example.invalid', 'production': True}).encode()
    client = Mock(request=Mock(return_value={'type': 'file', 'encoding': 'base64', 'size': len(raw),
                                           'content': base64.b64encode(raw).decode()}))
    def authenticated(values, *, read): return read(client, 'c' * 40)
    with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=authenticated):
        return inputs.prepare(values, public, binding, 'd' * 40), values, public, binding


def accepted(contract, stage):
    state = {'phase': 'accepted', 'application_uid': 'app-uid',
        'zone_hash': hashlib.sha256(contract['values']['zone'].encode()).hexdigest(),
        'staging': {'certificate_uid': 'staging-cert', 'secret_uid': 'staging-tls'},
        'identities': {key: {'certificate_uid': key + '-cert', 'secret_uid': key + '-tls'} for key in ('public', 'private')},
        'accounts': {}}
    objects = {}
    for obj in copy.deepcopy(contract['resources']):
        metadata = obj['metadata']
        kind = {'Certificate': 'certificate.cert-manager.io', 'ClusterIssuer': 'clusterissuer.cert-manager.io', 'Namespace': 'namespace'}[obj['kind']]
        metadata.update(uid=metadata['name'] + '-uid', generation=1)
        if obj['kind'] != 'Namespace': obj['status'] = {'conditions': [{'type': 'Ready', 'status': 'True', 'observedGeneration': 1}]}
        objects[kind, metadata['name'], metadata.get('namespace')] = obj
        if obj['kind'] == 'Certificate':
            key = 'staging' if metadata['name'] == 'cloudlab-staging' else metadata['namespace'].rsplit('-', 1)[1]
            identity = state['staging'] if key == 'staging' else state['identities'][key]
            metadata['uid'] = identity['certificate_uid']
            objects['secret', obj['spec']['secretName'], metadata['namespace']] = {
                'metadata': {'uid': identity['secret_uid'], 'annotations': {'cert-manager.io/certificate-name': metadata['name']}},
                'type': 'kubernetes.io/tls', 'data': {'tls.crt': 'synthetic-certificate', 'tls.key': 'synthetic-key'}}
    for key in ('staging', 'production'):
        secret = {'metadata': {'uid': key + '-account'}, 'data': {'tls.key': key + '-synthetic-account'}}
        objects['secret', 'cloudlab-acme-' + key, 'cert-manager'] = secret
        state['accounts'][key] = {'uid': secret['metadata']['uid'], 'content': native.digest(secret['data'])}
    if stage == 'legacy':
        app = initial_bootstrap.application({'repository': contract['repository'], 'branch': 'main', 'revision': contract['public_revision']},
                                            contract['values']['zone'], True)
        app['metadata']['managedFields'] = [{'manager': native.LEGACY, 'fieldsV1': {'f:spec': {}}}]
        app['status'] = {'sync': {'status': 'Synced', 'revision': contract['public_revision']}, 'health': {'status': 'Healthy'}}
    else:
        app = copy.deepcopy(contract['application'])
        app['spec'].pop('source', None)
        app['metadata'].setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = native.TRACKING
        app['status'] = {'sync': {'status': 'Synced', 'revisions': [contract['configuration_revision'], contract['private_revision']]},
                         'health': {'status': 'Healthy'}}
        external = copy.deepcopy(contract['reader'])
        external['metadata'].update(uid='reader-eso', generation=1)
        external['metadata'].setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = \
            'cloudlab-public-root:external-secrets.io/ExternalSecret:argocd/cloudlab-certificates-source'
        external['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
        objects['externalsecret.external-secrets.io', 'cloudlab-certificates-source', 'argocd'] = external
        fields = {'url': contract['private_repository'], 'project': native.APP, 'type': 'git',
                  'githubAppID': '1', 'githubAppInstallationID': '2', 'githubAppPrivateKey': 'synthetic-key'}
        objects['secret', 'cloudlab-certificates-source', 'argocd'] = {'metadata': {'name': 'cloudlab-certificates-source',
            'uid': 'reader-secret', 'labels': {'argocd.argoproj.io/secret-type': 'repository'},
            'ownerReferences': [{'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret',
                'name': 'cloudlab-certificates-source', 'uid': 'reader-eso', 'controller': True}]},
            'data': {key: base64.b64encode(value.encode()).decode() for key, value in fields.items()}}
    app['metadata']['uid'] = state['application_uid']
    objects['application.argoproj.io', native.APP, 'argocd'] = app
    project = copy.deepcopy(contract['project'])
    project['metadata'].setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = \
        'cloudlab-public-root:argoproj.io/AppProject:argocd/cloudlab-certificates'
    if stage == 'legacy': project['spec']['sourceRepos'] = [contract['repository']]
    objects['appproject.argoproj.io', native.APP, 'argocd'] = project
    operator = {'spec': {'source': {'repoURL': contract['repository'], 'targetRevision': 'main'}},
        'status': {'sync': {'status': 'Synced', 'revision': contract['public_revision']}, 'health': {'status': 'Healthy'}}}
    objects['application.argoproj.io', 'cloudlab-cert-manager', 'argocd'] = operator
    return state, objects
