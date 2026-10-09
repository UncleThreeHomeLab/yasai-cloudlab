"""Exercise pinned official Operator and patched server without preview CRDs."""
import base64
import copy
import json
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import time
import traceback
import urllib.error
import urllib.request

import yaml

ROOT = Path('/workspace')
NAMESPACE = 'cloudlab-identity'
PLURALS = {'Namespace': ('v1', 'namespaces'), 'ServiceAccount': ('v1', 'serviceaccounts'),
           'Secret': ('v1', 'secrets'), 'Service': ('v1', 'services'),
           'Deployment': ('apps/v1', 'deployments'), 'Role': ('rbac.authorization.k8s.io/v1', 'roles'),
           'RoleBinding': ('rbac.authorization.k8s.io/v1', 'rolebindings'),
           'ClusterRole': ('rbac.authorization.k8s.io/v1', 'clusterroles'),
           'ClusterRoleBinding': ('rbac.authorization.k8s.io/v1', 'clusterrolebindings'),
           'CustomResourceDefinition': ('apiextensions.k8s.io/v1', 'customresourcedefinitions'),
           'MutatingAdmissionPolicy': ('admissionregistration.k8s.io/v1', 'mutatingadmissionpolicies'),
           'MutatingAdmissionPolicyBinding': ('admissionregistration.k8s.io/v1', 'mutatingadmissionpolicybindings'),
           'Keycloak': ('k8s.keycloak.org/v2beta1', 'keycloaks')}
CLUSTER_KINDS = {'Namespace', 'CustomResourceDefinition', 'ClusterRole', 'ClusterRoleBinding',
                 'MutatingAdmissionPolicy', 'MutatingAdmissionPolicyBinding'}


def wait(predicate, label, timeout=420):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(3)
    raise RuntimeError('Operator fixture timed out: ' + label)


def main():
    document = wait(lambda: yaml.safe_load(Path('/fixture/kubeconfig').read_text()), 'cluster credentials')
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        authority = document['clusters'][0]['cluster']
        user = document['users'][0]['user']
        for label, value in [('ca', authority['certificate-authority-data']),
                             ('cert', user['client-certificate-data']), ('key', user['client-key-data'])]:
            target = directory / label
            target.write_bytes(base64.b64decode(value))
            target.chmod(0o600)
        context = ssl.create_default_context(cafile=str(directory / 'ca'))
        context.load_cert_chain(str(directory / 'cert'), str(directory / 'key'))

        def api(path, method='GET', value=None):
            req = urllib.request.Request('https://cluster:6443' + path, method=method,
                data=json.dumps(value).encode() if value is not None else None,
                headers={'Content-Type': 'application/apply-patch+yaml'})
            try:
                with urllib.request.urlopen(req, context=context, timeout=20) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                raise RuntimeError('Operator fixture API rejected operation: HTTP ' + str(error.code)) from None

        wait(lambda: api('/api/v1/nodes')['items'], 'cluster ready')

        def apply(obj):
            version, plural = PLURALS[obj['kind']]
            prefix = '/api/v1' if version == 'v1' else '/apis/' + version
            if obj['kind'] not in CLUSTER_KINDS:
                obj['metadata'].setdefault('namespace', NAMESPACE)
                prefix += '/namespaces/' + obj['metadata']['namespace']
            return api(prefix + '/' + plural + '/' + obj['metadata']['name'] +
                       '?fieldManager=identity-operator-fixture', 'PATCH', obj)

        # Render the exact candidate chart in an isolated copy; never bypass its
        # installation gate in the working repository or on a real cluster.
        chart = directory / 'chart'
        shutil.copytree(ROOT / 'platform/identity/keycloak', chart)
        lock = json.loads((chart / 'artifact.lock.json').read_text())
        lock['operator_install_verified'] = True
        (chart / 'artifact.lock.json').write_text(json.dumps(lock))
        command = ['helm', 'template', 'fixture', str(chart), '--namespace', NAMESPACE,
                   '--set', 'enabled=true', '--set', 'serverEnabled=false']
        rendered = subprocess.run(command, capture_output=True, text=True, check=True)
        objects = [o for o in yaml.safe_load_all(rendered.stdout) if o]
        for obj in objects:
            apply(obj)
        crds = api('/apis/apiextensions.k8s.io/v1/customresourcedefinitions')['items']
        assert not any('client' in c['metadata']['name'] and c['spec']['group'] == 'k8s.keycloak.org' for c in crds)
        wait(lambda: api('/apis/apps/v1/namespaces/' + NAMESPACE + '/deployments/keycloak-operator')
             .get('status', {}).get('availableReplicas') == 1, 'official Operator startup without preview CRDs')
        apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'keycloak-bootstrap-admin'},
               'stringData': {'username': 'fixture-admin', 'password': secrets.token_urlsafe(32)}})
        image = json.loads((ROOT / 'platform/data/cnpg/artifact.lock.json').read_text())['postgres_image']
        apply({'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'identity-proof-db'},
               'spec': {'replicas': 1, 'selector': {'matchLabels': {'app': 'identity-proof-db'}},
                        'template': {'metadata': {'labels': {'app': 'identity-proof-db'}}, 'spec': {
                            'securityContext': {'runAsUser': 26, 'runAsGroup': 26, 'runAsNonRoot': True,
                                                'seccompProfile': {'type': 'RuntimeDefault'}},
                            'containers': [{'name': 'database', 'image': image, 'command': ['/bin/sh', '-ec'],
                              'args': ["test -d /tmp/db || initdb -D /tmp/db --auth=trust --encoding=UTF8; printf '\\nhost all all 0.0.0.0/0 trust\\n' >> /tmp/db/pg_hba.conf; exec postgres -D /tmp/db -c listen_addresses='*' -c unix_socket_directories=/tmp"],
                              'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                              'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}, 'limits': {'cpu': '500m', 'memory': '512Mi'}}}]}}}})
        apply({'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'identity-proof-db'},
               'spec': {'selector': {'app': 'identity-proof-db'}, 'ports': [{'port': 5432}]}})
        wait(lambda: api('/apis/apps/v1/namespaces/' + NAMESPACE + '/deployments/identity-proof-db')
             .get('status', {}).get('availableReplicas') == 1, 'fixture database')
        server = {'apiVersion': 'k8s.keycloak.org/v2beta1', 'kind': 'Keycloak', 'metadata': {'name': 'fixture'},
          'spec': {'instances': 1, 'image': lock['images']['server'], 'startOptimized': False,
            'ingress': {'enabled': False}, 'http': {'httpEnabled': True},
            'hostname': {'hostname': 'http://fixture-service:8080', 'strict': True},
            'db': {'vendor': 'postgres', 'host': 'identity-proof-db', 'database': 'postgres',
                   'usernameSecret': {'name': 'fixture-db', 'key': 'username'},
                   'passwordSecret': {'name': 'fixture-db', 'key': 'password'}},
            'bootstrapAdmin': {'user': {'secret': 'keycloak-bootstrap-admin'}},
            'resources': {'requests': {'cpu': '200m', 'memory': '768Mi'}, 'limits': {'cpu': '1', 'memory': '1536Mi'}},
            'startupProbe': {'periodSeconds': 5, 'failureThreshold': 60},
            'readinessProbe': {'periodSeconds': 5, 'failureThreshold': 3},
            'livenessProbe': {'periodSeconds': 10, 'failureThreshold': 3},
            'networkPolicy': {'enabled': False}, 'additionalOptions': [{'name': 'log-level', 'value': 'WARN'}]}}
        apply({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'fixture-db'},
               'stringData': {'username': 'postgres', 'password': secrets.token_urlsafe(32)}})
        apply(server)
        def ready():
            obj = api('/apis/k8s.keycloak.org/v2beta1/namespaces/' + NAMESPACE + '/keycloaks/fixture')
            return any(c['type'] == 'Ready' and c['status'] == 'True' and
                       c.get('observedGeneration') == obj['metadata']['generation']
                       for c in obj.get('status', {}).get('conditions', []))
        wait(ready, 'patched server CR ready', 600)
        pod = api('/api/v1/namespaces/' + NAMESPACE + '/pods/fixture-0')['spec']
        assert pod['securityContext']['runAsNonRoot'] and pod['securityContext']['seccompProfile']['type'] == 'RuntimeDefault'
        security = pod['containers'][0]['securityContext']
        assert security['allowPrivilegeEscalation'] is False and security['capabilities']['drop'] == ['ALL']
        stateful = '/apis/apps/v1/namespaces/' + NAMESPACE + '/statefulsets/fixture'
        before = api(stateful)
        apply(copy.deepcopy(server))
        time.sleep(8)
        after = api(stateful)
        assert before['metadata']['uid'] == after['metadata']['uid'] and before['spec'] == after['spec']
        changed = copy.deepcopy(server)
        changed['spec']['resources']['limits']['cpu'] = '900m'
        apply(changed)
        wait(lambda: api(stateful)['spec']['template']['spec']['containers'][0]['resources']['limits']['cpu'] == '900m',
             'Operator CR change reconciled')
        wait(ready, 'server remains ready')
        changed['spec']['instances'] = 0
        apply(changed)
        wait(lambda: not [p for p in api('/api/v1/namespaces/' + NAMESPACE + '/pods')['items']
                         if p['metadata'].get('labels', {}).get('app.kubernetes.io/instance') == 'fixture'],
             'Operator quiesces server for coordinated physical capture')
        changed['spec']['instances'] = 1
        apply(changed)
        wait(ready, 'server resumes after physical capture boundary', 600)
        print(json.dumps({'operator': lock['operator_version'], 'server': lock['server_version'],
                          'preview_client_crds': False, 'operator_ready': True, 'server_ready': True,
                          'repeat_preserved_statefulset': True, 'cr_change_reconciled': True,
                          'operator_stop_resume': True,
                          'stable_security_admission': True,
                          'environment': 'isolated Compose Kubernetes; no production TLS/SSO claim'}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        line = traceback.extract_tb(error.__traceback__)[-1].lineno
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Isolated Operator proof failed: ' + type(error).__name__ + ' at line ' + str(line)) from None
