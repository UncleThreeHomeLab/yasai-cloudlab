"""Failure and removal scenarios for local transport fakes only."""
import base64
import copy
import json
from private_verify import healthy, wait
from bootstrap import kube, get


def mutate(name, document):
    kube('patch', 'application.argoproj.io', name, '-n', 'argocd', '--type=merge', '-p', json.dumps(document))


def credential_failure(name, workload, uid):
    """Use an isolated project/credential; never corrupt an ESO-owned Secret."""
    probe = 'cloudlab-private-credential-check'
    label = {'cloudlab.io/verification': 'private-credential-check'}
    kinds = ('application.argoproj.io', 'secret', 'appproject.argoproj.io', 'namespace')

    def cleanup():
        # Inspect all owners before deleting anything, including interrupted runs.
        existing = [(kind, get(kind, probe)) for kind in kinds]
        for kind, obj in existing:
            if obj and (obj['metadata'].get('labels', {}).get('cloudlab.io/verification') !=
                        'private-credential-check' or obj['metadata'].get('ownerReferences') or
                        (kind != 'namespace' and obj['metadata'].get('finalizers'))):
                raise RuntimeError('Private credential fixture cleanup ownership mismatch')
        for kind, obj in existing:
            if obj:
                kube('delete', kind, probe, '-n', 'argocd', '--wait=true', '--timeout=60s')

    def metadata(namespace=True):
        return {'name': probe, 'labels': label, **({'namespace': 'argocd'} if namespace else {})}

    def retained():
        raw = kube('get', 'configmap', 'cloudlab-private-fixture', '-n', probe,
                   '--ignore-not-found', '-o', 'json')
        return json.loads(raw) if raw.strip() else {}

    cleanup()
    secret = get('secret', name)
    app = get('application.argoproj.io', name)
    if not secret or not healthy(name):
        raise RuntimeError('Private credential fixture requires a healthy source')
    original_data = copy.deepcopy(secret['data'])
    probe_data = dict(original_data, project=base64.b64encode(probe.encode()).decode())
    invalid = 'intentionally-invalid-private-fixture-key'
    invalid_data = base64.b64encode(invalid.encode()).decode()
    try:
        namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': metadata(False)}
        namespace['metadata']['labels'] = dict(label, **{'pod-security.kubernetes.io/enforce': 'restricted'})
        project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject', 'metadata': metadata(),
                   'spec': {'sourceRepos': [app['spec']['source']['repoURL']],
                            'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': probe}],
                            'clusterResourceWhitelist': [],
                            'namespaceResourceWhitelist': [{'group': '', 'kind': 'ConfigMap'}]}}
        credential = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': metadata(),
                      'type': 'Opaque', 'data': probe_data}
        credential['metadata']['labels'] = dict(label, **{'argocd.argoproj.io/secret-type': 'repository'})
        application = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': metadata(),
                       'spec': {'project': probe, 'source': copy.deepcopy(app['spec']['source']),
                                'destination': {'server': 'https://kubernetes.default.svc', 'namespace': probe},
                                'syncPolicy': {'automated': {'prune': False, 'selfHeal': True}}}}
        for obj in (namespace, project, credential, application):
            kube('create', '-f', '-', document=obj)
        wait(lambda: healthy(probe) and retained().get('data') == {'proof': 'private-source-converged'},
             'isolated credential baseline')
        probe_uid = retained()['metadata']['uid']
        mutate(probe, {'spec': {'syncPolicy': {'automated': None}}})
        kube('patch', 'secret', probe, '-n', 'argocd', '--type=merge',
             '-p', json.dumps({'data': {'githubAppPrivateKey': invalid_data}}))
        mutate(probe, {'metadata': {'annotations': {'argocd.argoproj.io/refresh': 'hard'}}})
        wait(lambda: any(c['type'] == 'ComparisonError' and
                        any(text in c.get('message', '').lower() for text in
                            ('private key', 'pem encoded', 'invalid key')) for c in
                        (get('application.argoproj.io', probe) or {}).get('status', {}).get('conditions', [])),
             'credential failure detection')
        if retained().get('metadata', {}).get('uid') != probe_uid or (workload() or {}).get('metadata', {}).get('uid') != uid:
            raise RuntimeError('Private credential failure did not retain its workload')
        if not all(healthy(root) for root in ('cloudlab-public-root', 'cloudlab-argocd', name)):
            raise RuntimeError('Private credential failure disrupted public convergence')
        kube('patch', 'secret', probe, '-n', 'argocd', '--type=merge',
             '-p', json.dumps({'data': probe_data}))
        mutate(probe, {'metadata': {'annotations': {'argocd.argoproj.io/refresh': 'hard'}}})
        wait(lambda: healthy(probe), 'isolated credential recovery')
        if retained().get('metadata', {}).get('uid') != probe_uid:
            raise RuntimeError('Private credential recovery replaced its workload')
        if (get('secret', name) or {}).get('data') != original_data:
            raise RuntimeError('Working private credential changed during isolated proof')
    finally:
        cleanup()
