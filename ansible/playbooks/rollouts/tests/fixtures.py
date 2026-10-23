"""Credential-free release definitions and bounded live fixture scope."""
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[4]
NS = 'cloudlab-app-rollouts-proof'
APP = 'cloudlab-rollouts-proof'


def definition(host='release.internal.example.invalid', artifact=None):
    value = yaml.safe_load((ROOT / 'charts/service/values.yaml').read_text())
    value.update(name='release-proof', owner='platform')
    value['rollouts']['enabled'] = True
    value['ports'].append({'name': 'http-metrics', 'port': 9091})
    value['exposure'] = {'class': 'private', 'hostname': host, 'access': 'tailnet', 'path': '/canary-proof', 'port': 8080}
    value['health'] = {kind: {'path': '/ready', 'port': 'http'} for kind in ('readiness', 'liveness')}
    value['command'] = ['python', '-c', (Path(__file__).with_name('server.py')).read_text()]
    value['environment'] = {'RELEASE_MODE': 'healthy', 'RELEASE_SEQUENCE': 'baseline'}
    if artifact:
        value['image'] = artifact['image']
        value['imagePullSecrets'] = [{'name': 'harbor-application-pull'}]
        value['artifactPolicyHash'] = artifact['policy_hash']
    return value


def objects(repository, revision, host, artifact=None):
    namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': NS, 'labels': {
        'cloudlab.io/owner': 'service-platform', 'cloudlab.io/gateway': 'private',
        'cloudlab.io/release-analysis': 'approved', 'istio.io/dataplane-mode': 'ambient',
        'cloudlab.io/service-secrets': 'approved',
        'pod-security.kubernetes.io/enforce': 'restricted', 'pod-security.kubernetes.io/enforce-version': 'v1.36'}}}
    quota = {'apiVersion': 'v1', 'kind': 'ResourceQuota', 'metadata': {'name': 'budget', 'namespace': NS},
             'spec': {'hard': {'requests.cpu': '500m', 'requests.memory': '512Mi', 'limits.cpu': '1',
                               'limits.memory': '1Gi', 'pods': '4', 'persistentvolumeclaims': '0'}}}
    network = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
               'metadata': {'name': 'fixture-ingress', 'namespace': NS}, 'spec': {'podSelector': {}, 'policyTypes': ['Ingress'],
               'ingress': [{'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': namespace}}}],
                            'ports': [{'protocol': 'TCP', 'port': port} for port in ports]}
                           for namespace, ports in [('cloudlab-gateway-private', [8080, 15008]),
                                                    ('cloudlab-observability', [9091, 15008])]]}}
    authorization = {'apiVersion': 'security.istio.io/v1', 'kind': 'AuthorizationPolicy',
                     'metadata': {'name': 'fixture-identities', 'namespace': NS},
                     'spec': {'action': 'ALLOW', 'rules': [
                         {'from': [{'source': {'principals': [principal]}}],
                          'to': [{'operation': {'ports': [str(port)]}}]}
                         for principal, port in [('cluster.local/ns/cloudlab-gateway-private/sa/cloudlab-istio', 8080),
                                                 ('cluster.local/ns/cloudlab-observability/sa/cloudlab-prometheus', 9091)]]}}
    project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject', 'metadata': {'name': APP, 'namespace': 'argocd'},
               'spec': {'sourceRepos': [repository], 'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': NS}],
                        'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [
                            {'group': group, 'kind': kind} for group, kind in [('', 'Service'), ('', 'ServiceAccount'),
                            ('argoproj.io', 'Rollout'), ('argoproj.io', 'AnalysisTemplate'),
                            ('gateway.networking.k8s.io', 'HTTPRoute')]]}}
    app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': {'name': APP, 'namespace': 'argocd'},
           'spec': {'project': APP, 'source': {'repoURL': repository, 'targetRevision': revision, 'path': 'charts/service',
                    'helm': {'valuesObject': definition(host, artifact)}},
                    'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NS},
                    'ignoreDifferences': [
                        {'group': 'gateway.networking.k8s.io', 'kind': 'HTTPRoute', 'name': 'release-proof',
                         'jsonPointers': ['/spec/rules/0/backendRefs/0/weight', '/spec/rules/0/backendRefs/1/weight']},
                        *[{'group': '', 'kind': 'Service', 'name': name,
                           'jsonPointers': ['/spec/selector/rollouts-pod-template-hash']}
                          for name in ('release-proof', 'release-proof-canary')]],
                    'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True},
                                   'syncOptions': ['RespectIgnoreDifferences=true', 'FailOnSharedResource=true',
                                                   'DisableClientSideApplyMigration=true']}}}
    registry = [] if not artifact else [
        {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret',
         'metadata': {'name': 'harbor-application-pull', 'namespace': NS}, 'spec': artifact['delivery']},
        {'apiVersion': 'kyverno.io/v1', 'kind': 'Policy',
         'metadata': {'name': 'application-artifacts', 'namespace': NS,
                      'annotations': {'pod-policies.kyverno.io/autogen-controllers': 'none'}}, 'spec': artifact['policy']}]
    return [namespace, quota, network, authorization, *registry, project, app]
