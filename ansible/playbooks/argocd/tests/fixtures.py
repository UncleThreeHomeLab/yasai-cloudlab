"""Synthetic root and service activation inputs without credentials."""
import copy
import hashlib

from service_activation import prepare
from private_activation import prepare as prepare_private


def source_approval(public, repository, revision='d' * 40):
    receipt = {'version': 'cloudlab-private-source-acceptance/v1', 'consumer': 'private-sources',
        'revision': revision, 'nonce': '1' * 64}
    commitment = hashlib.sha256(('\n'.join([receipt['version'], receipt['consumer'], repository,
        'platform/sources.yaml', revision, receipt['nonce'], ''])).encode()).hexdigest()
    public['privateSources']['acceptanceCommitment'] = commitment
    return {'acceptanceCommitment': commitment, 'acceptedRevision': revision, 'acceptanceReceipt': receipt}


def private_policies(evidence):
    return {('validatingpolicy.policies.kyverno.io', name): {
        'metadata': {'uid': name + '-uid', 'generation': 2, 'annotations': {
            'argocd.argoproj.io/tracking-id': 'cloudlab-workload-policy:policies.kyverno.io/ValidatingPolicy:cloudlab-policy/' + name}},
        'spec': copy.deepcopy(spec), 'status': {'conditionStatus': {'ready': True, 'conditions': [
            {'type': 'WebhookConfigured', 'status': 'True'}, {'type': 'RBACPermissionsGranted', 'status': 'True'}]}}}
        for name, spec in evidence['policies'].items()}


def private_probe(evidence, document):
    rejected = (document['metadata']['labels']['cloudlab.io/owner'] == 'foreign' or
                (document['kind'] == 'Secret' and 'ownerReferences' not in document['metadata']))
    if not rejected: return 0, ''
    name = 'cloudlab-private-source-credentials' if document['kind'] == 'Secret' else 'cloudlab-private-source-ownership'
    message = evidence['policies'][name]['validations'][0]['message']
    return 1, 'admission webhook denied the request: ' + name + ': ' + message


def binding_fixture(required=True):
    repository = 'https://github.com/example/platform.git'
    target = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}
    public = {'repository': repository, 'services': {'enabled': required, 'revision': 'c' * 40}}
    evidence = prepare(public, target['valuesRepository'], target['valuesRevision'],
                       {'catalog': [], 'dataApprovals': {}} if required else None)
    objects = {
        ('application.argoproj.io', 'cloudlab-public-root'): {
            'metadata': {'uid': 'root', 'resourceVersion': '1'},
            'spec': {'project': 'cloudlab-root', 'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}, 'source': {'repoURL': repository,
                'targetRevision': 'main', 'path': 'gitops/roots/public',
                'helm': {'valuesObject': {'services': {'enabled': required}}}}}},
        ('statefulset', 'argocd-application-controller'): {'metadata': {'uid': 'controller'}, 'spec': {'replicas': 1}},
        ('appproject.argoproj.io', 'cloudlab-root'): {
            'metadata': {'uid': 'project', 'resourceVersion': '1'}, 'spec': {
                'sourceRepos': [repository],
                'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
                'clusterResourceWhitelist': [{'group': '', 'kind': 'Namespace'}],
                'namespaceResourceWhitelist': [{'group': 'argoproj.io', 'kind': kind}
                                               for kind in ('Application', 'AppProject', 'ApplicationSet')]}}}
    payload = {'repository': repository, 'branch': 'main', 'revision': 'a' * 40,
               'private_repository': target['valuesRepository'], 'argo': {'serviceActivation': evidence,
                   'accessActivation': access_evidence(repository, target),
                   'dataActivation': data_evidence(repository, target),
                   'privateActivation': prepare_private(public, target['valuesRepository'], target['valuesRevision'])}}
    original = copy.deepcopy(objects['application.argoproj.io', 'cloudlab-public-root']['spec']['source'])
    patched = copy.deepcopy(original)
    patched['helm']['valuesObject']['identity'] = {'enabled': True, 'argo': target}
    checkpoint = {'phase': 'source-updated', 'target': target, 'root_uid': 'root', 'controller_uid': 'controller',
                  'project_uid': 'project', 'originalSource': original, 'patchedSource': patched,
                  'serviceActivation': evidence, 'privateActivation': payload['argo']['privateActivation'],
                  'accessActivation': payload['argo']['accessActivation'],
                  'dataActivation': payload['argo']['dataActivation']}
    return objects, payload, target, checkpoint


def access_evidence(repository, target, administrator=None):
    import hashlib
    from access_activation import validate
    return validate({'required': False, 'enabled': True, 'repository': repository, 'revision': 'e' * 40,
        'private_repository': target['valuesRepository'], 'private_revision': target['valuesRevision'],
        'administratorHash': hashlib.sha256(administrator.encode()).hexdigest() if administrator is not None else None}, target)


def access_authority(repository):
    import hashlib
    import access_activation
    administrator = 'admin@example.invalid'
    receipt = {'phase': 'configured', 'application_uid': 'access-app',
               'administrator': hashlib.sha256(administrator.encode()).hexdigest()}
    objects = {('application.argoproj.io', access_activation.APP): {
        'metadata': {'uid': 'access-app', 'labels': {'cloudlab.io/owner': 'cloudlab-access-bootstrap'}},
        'spec': {'source': {'repoURL': repository, 'targetRevision': 'main', 'path': 'platform/connectivity/access'}}},
        ('clusterrolebinding.rbac.authorization.k8s.io', access_activation.BINDING): {
            'metadata': {'uid': 'access-binding', 'annotations': {'argocd.argoproj.io/tracking-id':
                access_activation.APP + ':rbac.authorization.k8s.io/ClusterRoleBinding:tailscale/' + access_activation.BINDING}},
            'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'cluster-admin'},
            'subjects': [{'kind': 'User', 'apiGroup': 'rbac.authorization.k8s.io', 'name': administrator}]}}
    return administrator, receipt, objects


def data_evidence(repository, target):
    from data_activation import validate
    return validate({'required': False, 'enabled': False, 'repository': repository,
        'revision': None, 'seaweedfsRevision': None, 'private_repository': target['valuesRepository'],
        'private_revision': target['valuesRevision'], 'settings': None,
        'absence': {'path': 'platform/data.yaml', 'revision': target['valuesRevision'], 'authenticated404': True}}, target)
