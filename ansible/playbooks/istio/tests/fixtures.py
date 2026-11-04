"""Synthetic authenticated gateway contracts and accepted mesh inventory."""
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
from playbooks.keycloak.files.integrations import argo
from playbooks.argocd.files.github_setup import MARKER


def documents():
    result = {}
    for sha, host in [('c' * 40, 'future.example.invalid'), ('b' * 40, 'cd.example.invalid')]:
        contract = argo('https://login.example.invalid/realms/platform', 'https://' + host,
                        ['https://cd.internal.example.invalid'])
        result[sha, 'identity/argo-values.yaml'] = contract['helm']
        result[sha, 'identity/configmap.yaml'] = {'apiVersion': 'v1', 'kind': 'ConfigMap',
            'metadata': {'name': 'identity-private-state', 'namespace': 'cloudlab-identity'},
            'data': {'desired_state': json.dumps({'realms': {'platform': {'clients': [contract['client']]}}}),
                     'revocations': json.dumps({'realms': {'platform': {}}})}}
    result['c' * 40, 'platform/certificates.yaml'] = {'zone': 'example.invalid', 'production': True}
    return result


def prepared(docs=None):
    docs = documents() if docs is None else docs
    public = yaml.safe_load((Path(__file__).resolve().parents[4] / 'gitops/roots/public/values.yaml').read_text())
    public['repository'] = 'https://github.com/example/platform.git'
    values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
    binding = {'valuesRepository': values['PRIVATE_CONFIG_REPOSITORY'], 'valuesRevision': 'b' * 40}
    def request(method, path, **kwargs):
        if path == 'repos/example/private':
            return {'full_name': 'example/private', 'private': True, 'description': MARKER + 'private-config'}
        filename, sha = path.split('/contents/')[1].split('?ref=')
        raw = yaml.safe_dump(docs[sha, filename]).encode()
        return {'type': 'file', 'encoding': 'base64', 'size': len(raw), 'content': base64.b64encode(raw).decode()}
    client = Mock(request=Mock(side_effect=request))
    with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=lambda v, read: read(client, 'c' * 40)):
        contract = inputs.prepare(values, public, binding, 'd' * 40)
    return contract, client, public, values, binding


def accepted(contract, stage='native'):
    payload = {'repository': contract['repository'], 'branch': 'main', 'revision': contract['public_revision'],
        'gateway_api': [{'metadata': {'name': 'gateways.gateway.networking.k8s.io'}, 'spec': {'group': 'gateway.networking.k8s.io'}}],
        'mesh_objects': {'base': [{'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'controller', 'namespace': 'istio-system'}}]}}
    objects = {}
    state = {'phase': 'accepted', 'application_uid': 'app-uid',
        'zone_hash': hashlib.sha256(b'example.invalid').hexdigest(),
        'gateway_api': {'gateways.gateway.networking.k8s.io': 'crd-uid'},
        'components': {'ServiceAccount/istio-system/controller': 'controller-uid'}, 'gateways': {}}
    objects['customresourcedefinition', 'gateways.gateway.networking.k8s.io', None] = {
        'metadata': {'uid': 'crd-uid', 'annotations': {'meta.helm.sh/release-name': 'traefik-crd',
            'gateway.networking.k8s.io/bundle-version': 'v1.6.1'}}, 'spec': payload['gateway_api'][0]['spec']}
    objects['ServiceAccount', 'controller', 'istio-system'] = {'metadata': {'uid': 'controller-uid',
        'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-istio-base:/ServiceAccount:istio-system/controller'}}}
    objects['application.argoproj.io', 'cloudlab-istio-base', 'argocd'] = {
        'status': {'sync': {'status': 'Synced', 'revision': contract['public_revision']}, 'health': {'status': 'Healthy'}}}
    ca = {'metadata': {'uid': 'ca-uid'}, 'data': {'ca-cert.pem': 'synthetic-cert', 'ca-key.pem': 'synthetic-key'}}
    objects['secret', 'istio-ca-secret', 'istio-system'] = ca
    state['workload_ca'] = {'uid': 'ca-uid', 'content': hashlib.sha256(json.dumps(ca['data'], sort_keys=True).encode()).hexdigest()}
    for exposure in ('public', 'private'):
        ns = 'cloudlab-gateway-' + exposure
        state['gateways'][exposure] = {'gateway': ns + '-uid', **{k: ns + '-' + k for k in ('deployment', 'service', 'serviceaccount')}}
        for kind in ('deployment', 'service', 'serviceaccount'):
            objects[kind, 'cloudlab-istio', ns] = {'metadata': {'uid': state['gateways'][exposure][kind]}}
        objects['service', 'cloudlab-istio', ns]['spec'] = {'type': 'ClusterIP',
            'ports': [{'name': 'https', 'port': 443, 'targetPort': 443}]}
        objects['certificate.cert-manager.io', 'cloudlab-gateway', ns] = {'metadata': {'generation': 1},
            'spec': {'dnsNames': ['*.example.invalid'] if exposure == 'public' else ['*.internal.example.invalid', 'login.example.invalid']},
            'status': {'conditions': [{'type': 'Ready', 'status': 'True', 'observedGeneration': 1}]}}
        objects['secret', 'cloudlab-gateway-tls', ns] = {'type': 'kubernetes.io/tls',
            'metadata': {'uid': ns + '-tls', 'annotations': {'cert-manager.io/certificate-name': 'cloudlab-gateway'}},
            'data': {'tls.crt': 'synthetic-cert', 'tls.key': 'synthetic-key'}}
    for obj in copy.deepcopy(contract['resources']):
        meta = obj['metadata']; meta.update(uid=meta['namespace'] + '-uid', generation=1)
        kind = {'Gateway': 'gateway.gateway.networking.k8s.io', 'HTTPRoute': 'httproute.gateway.networking.k8s.io', 'ConfigMap': 'configmap'}[obj['kind']]
        group = obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else ''
        meta.setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = native.APP + ':' + group + '/' + obj['kind'] + ':' + meta['namespace'] + '/' + meta['name']
        conditions = [{'type': k, 'status': 'True', 'observedGeneration': 1} for k in ('Accepted', 'Programmed', 'ResolvedRefs')]
        obj['status'] = {'conditions': conditions, 'parents': [{'controllerName': 'istio.io/gateway-controller',
                'parentRef': {'group': 'gateway.networking.k8s.io', 'kind': 'Gateway', 'name': 'cloudlab', 'sectionName': 'https'},
                'conditions': conditions}]}
        objects[kind, meta['name'], meta['namespace']] = obj
    if stage == 'legacy':
        hosts = {o['metadata']['namespace'].rsplit('-', 1)[1]: o['spec']['hostnames'][0] for o in contract['resources'] if o['kind'] == 'HTTPRoute'}
        app = initial_bootstrap.application(payload, 'example.invalid', hosts)
        app['metadata']['managedFields'] = [{'manager': native.OWNER, 'fieldsV1': {'f:spec': {}}}]
        app['status'] = {'sync': {'status': 'Synced', 'revision': contract['public_revision']}, 'health': {'status': 'Healthy'}}
    else:
        app = copy.deepcopy(contract['application']); app['spec'].pop('source')
        app['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = native.TRACKING
        app['status'] = {'sync': {'status': 'Synced', 'revisions': [contract[k] for k in ('configuration_revision', 'private_revision', 'identity_revision')]}, 'health': {'status': 'Healthy'}}
        external = copy.deepcopy(contract['reader']); external['metadata'].update(uid='reader-uid', generation=1)
        external['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'cloudlab-public-root:external-secrets.io/ExternalSecret:argocd/' + native.APP + '-source'
        external['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
        objects['externalsecret.external-secrets.io', native.APP + '-source', 'argocd'] = external
        data = dict(type='git', url=contract['private_repository'], project=native.APP, githubAppID='1', githubAppInstallationID='2', githubAppPrivateKey='synthetic-key')
        objects['secret', native.APP + '-source', 'argocd'] = {'metadata': {'uid': 'reader-secret',
            'labels': {'argocd.argoproj.io/secret-type': 'repository'}, 'ownerReferences': [{'apiVersion': 'external-secrets.io/v1',
                'kind': 'ExternalSecret', 'name': native.APP + '-source', 'uid': 'reader-uid', 'controller': True}]},
            'data': {k: base64.b64encode(v.encode()).decode() for k, v in data.items()}}
    app['metadata']['uid'] = state['application_uid']; objects['application.argoproj.io', native.APP, 'argocd'] = app
    project = copy.deepcopy(contract['project']); project['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/AppProject:argocd/' + native.APP}
    if stage == 'legacy': project['spec']['sourceRepos'] = [contract['repository']]
    objects['appproject.argoproj.io', native.APP, 'argocd'] = project
    return payload, state, objects
