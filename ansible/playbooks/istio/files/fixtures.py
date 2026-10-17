"""Disposable ambient fixtures; production namespaces and secrets are untouched."""
import json


def namespace(name, exposure=None, ambient=False):
    labels = {'app.kubernetes.io/managed-by': 'cloudlab-mesh-verify',
              'pod-security.kubernetes.io/enforce': 'restricted',
              'pod-security.kubernetes.io/enforce-version': 'v1.36', 'istio-injection': 'disabled'}
    if exposure:
        labels['cloudlab.io/gateway'] = exposure
    if ambient:
        labels['istio.io/dataplane-mode'] = 'ambient'
    return {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': name, 'labels': labels}}


def account(ns, name):
    return {'apiVersion': 'v1', 'kind': 'ServiceAccount',
            'metadata': {'name': name, 'namespace': ns}, 'automountServiceAccountToken': False}


def pod(ns, name, image, service_account, network=True, server=False):
    command = ['sh', '-ec', 'mkdir -p /www; printf mesh-ok > /www/index.html; exec httpd -f -p 8080 -h /www'] if server else ['sh', '-c', 'sleep 1800']
    container = {'name': 'workload', 'image': image, 'command': command,
                 'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                     'capabilities': {'drop': ['ALL']}},
                 'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                               'limits': {'cpu': '100m', 'memory': '64Mi'}}}
    spec = {'serviceAccountName': service_account, 'automountServiceAccountToken': False,
            'restartPolicy': 'Never', 'activeDeadlineSeconds': 1800,
            'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'runAsGroup': 1000, 'fsGroup': 1000,
                                'seccompProfile': {'type': 'RuntimeDefault'}}, 'containers': [container]}
    if server:
        container.update(ports=[{'containerPort': 8080}],
                         volumeMounts=[{'name': 'www', 'mountPath': '/www'}],
                         readinessProbe={'exec': {'command': ['sh', '-c', 'wget -qO- -T 2 http://127.0.0.1:8080/']},
                                         'periodSeconds': 3, 'timeoutSeconds': 3})
        spec['volumes'] = [{'name': 'www', 'emptyDir': {'sizeLimit': '1Mi'}}]
    return {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': name, 'namespace': ns,
                         'labels': {'app': 'backend' if server else 'client',
                                    'cloudlab.io/network-access': 'allowed' if network else 'denied'}}, 'spec': spec}


def service(ns):
    return {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'backend', 'namespace': ns},
            'spec': {'selector': {'app': 'backend'}, 'ports': [{'name': 'http', 'port': 8080, 'targetPort': 8080}]}}


def identity_policy(ns, principals):
    return [
        {'apiVersion': 'security.istio.io/v1', 'kind': 'PeerAuthentication',
         'metadata': {'name': 'strict', 'namespace': ns}, 'spec': {'mtls': {'mode': 'STRICT'}}},
        {'apiVersion': 'security.istio.io/v1', 'kind': 'AuthorizationPolicy',
         'metadata': {'name': 'backend', 'namespace': ns},
         'spec': {'selector': {'matchLabels': {'app': 'backend'}}, 'action': 'ALLOW',
                  'rules': [{'from': [{'source': {'principals': principals}}], 'to': [{'operation': {'ports': ['8080']}}]}]}}
    ]


def network_policy(ns, allow_hbone=True):
    return {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
            'metadata': {'name': 'backend', 'namespace': ns},
            'spec': {'podSelector': {'matchLabels': {'app': 'backend'}}, 'policyTypes': ['Ingress'],
                     'ingress': [{'ports': [{'protocol': 'TCP', 'port': 15008}]}] if allow_hbone else []}}


def route(ns, name, exposure, hostname):
    return {'apiVersion': 'gateway.networking.k8s.io/v1', 'kind': 'HTTPRoute',
            'metadata': {'name': name, 'namespace': ns},
            'spec': {'parentRefs': [{'name': 'cloudlab', 'namespace': 'cloudlab-gateway-' + exposure,
                                    'sectionName': 'https'}], 'hostnames': [hostname],
                     'rules': [{'matches': [{'path': {'type': 'PathPrefix', 'value': '/'}}],
                                'backendRefs': [{'name': 'backend', 'port': 8080}]}]}}


def document(objects):
    return {'apiVersion': 'v1', 'kind': 'List', 'items': objects}
