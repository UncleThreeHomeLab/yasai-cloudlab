"""Synthetic root and service activation inputs without credentials."""
import copy

from service_activation import prepare


def binding_fixture(required=True):
    repository = 'https://github.com/example/platform.git'
    target = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}
    public = {'repository': repository, 'services': {'enabled': required, 'revision': 'c' * 40}}
    evidence = prepare(public, target['valuesRepository'], target['valuesRevision'],
                       {'catalog': [], 'dataApprovals': {}} if required else None)
    objects = {
        ('application.argoproj.io', 'cloudlab-public-root'): {
            'metadata': {'uid': 'root', 'resourceVersion': '1'},
            'spec': {'project': 'cloudlab-root', 'source': {'repoURL': repository,
                'targetRevision': 'main', 'path': 'gitops/roots/public',
                'helm': {'valuesObject': {'services': {'enabled': required}}}}}},
        ('statefulset', 'argocd-application-controller'): {'metadata': {'uid': 'controller'}, 'spec': {'replicas': 1}},
        ('appproject.argoproj.io', 'cloudlab-root'): {
            'metadata': {'uid': 'project', 'resourceVersion': '1'}, 'spec': {
                'sourceRepos': [repository],
                'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
                'clusterResourceWhitelist': [{'group': '', 'kind': 'Namespace'}],
                'namespaceResourceWhitelist': [{'group': 'argoproj.io', 'kind': kind}
                                               for kind in ('Application', 'AppProject')]}}}
    payload = {'repository': repository, 'branch': 'main', 'revision': 'a' * 40,
               'private_repository': target['valuesRepository'], 'argo': {'serviceActivation': evidence}}
    original = copy.deepcopy(objects['application.argoproj.io', 'cloudlab-public-root']['spec']['source'])
    patched = copy.deepcopy(original)
    patched['helm']['valuesObject']['identity'] = {'enabled': True, 'argo': target}
    checkpoint = {'phase': 'source-updated', 'target': target, 'root_uid': 'root', 'controller_uid': 'controller',
                  'project_uid': 'project', 'originalSource': original, 'patchedSource': patched,
                  'serviceActivation': evidence}
    return objects, payload, target, checkpoint
