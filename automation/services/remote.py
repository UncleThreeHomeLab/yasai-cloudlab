"""Check actual owner convergence and retire only scoped workload children."""
import json
import sys

from playbooks.istio.files.kube import get, condition, application_ready, kube, wait
from automation.identity.health import direct_https


def inspect(request):
    definition, approval = request['definition'], request['approval']
    namespace = approval['namespace']
    action = request['action']
    name = definition['name']
    notes = approval.get('chartPath') == 'apps/notes'
    workload_names = ['notes-web', 'notes-api'] if notes else [name]
    if action.startswith('fixture-'):
        from playbooks.data.files.service_proof import fixture
        fixture({'definition': definition, 'approval': approval})
        if action == 'fixture-data':
            from playbooks.data.files.service_proof import run
            return run({'definition': definition, 'approval': approval})
        if action == 'fixture-snapshot':
            import hashlib
            retained = [('namespace', namespace, None), ('resourcequota', 'budget', namespace),
                        ('networkpolicy', 'platform-ingress', namespace),
                        ('authorizationpolicy.security.istio.io', 'platform-workloads', namespace),
                        ('pvc', name, namespace), ('cluster.postgresql.cnpg.io', 'cloudlab-postgres', 'cloudlab-data')]
            retained += [('gateway.gateway.networking.k8s.io', 'cloudlab', 'cloudlab-gateway-' + exposure)
                         for exposure in ('public', 'private')]
            result = {}
            for kind, identifier, ns in retained:
                obj = get(kind, identifier, ns)
                if not obj: raise RuntimeError('A retained fixture or shared owner is missing')
                result[kind + ':' + identifier + ':' + str(ns)] = obj['metadata']['uid']
            for value in definition['data'].values():
                obj = get('secret', value['credentialReference'], namespace)
                result[value['credentialReference']] = [obj['metadata']['uid'], hashlib.sha256(
                    json.dumps(obj['data'], sort_keys=True).encode()).hexdigest()]
            return {'retained': result}
        if action == 'fixture-volume':
            import hashlib
            import uuid
            if get('deployment', name, namespace):
                raise RuntimeError('Retained volume proof requires the retired fixture workload')
            claim = get('pvc', name, namespace)
            if (not claim or claim.get('status', {}).get('phase') != 'Bound' or
                    not claim['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(
                        approval['name'] + '-' + name + ':')):
                raise RuntimeError('Retained fixture volume has a conflicting owner')
            nonce = uuid.uuid4().hex[:12]
            pod_name = 'retained-proof-' + nonce
            pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': pod_name, 'namespace': namespace,
                   'labels': {'cloudlab.io/fixture': nonce}}, 'spec': {'restartPolicy': 'Never',
                   'automountServiceAccountToken': False, 'securityContext': {'runAsNonRoot': True,
                   'runAsUser': 10001, 'runAsGroup': 10001, 'fsGroup': 10001, 'seccompProfile': {'type': 'RuntimeDefault'}},
                   'containers': [{'name': 'proof', 'image': definition['image'],
                   'command': ['python', '-c', "import hashlib;print(hashlib.sha256(open('/data/sentinel','rb').read()).hexdigest())"],
                   'resources': {'requests': {'cpu': '25m', 'memory': '32Mi'}, 'limits': {'cpu': '100m', 'memory': '64Mi'}},
                   'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                       'capabilities': {'drop': ['ALL']}},
                   'volumeMounts': [{'name': 'data', 'mountPath': '/data', 'readOnly': True}]}],
                   'volumes': [{'name': 'data', 'persistentVolumeClaim': {'claimName': name, 'readOnly': True}}]}}
            kube('create', '-f', '-', document=pod)
            uid = get('pod', pod_name, namespace)['metadata']['uid']
            try:
                wait(lambda: get('pod', pod_name, namespace).get('status', {}).get('phase') in ('Succeeded', 'Failed'),
                     'retained fixture volume read', timeout=300)
                actual = get('pod', pod_name, namespace)
                digest = kube('logs', pod_name, '-n', namespace).strip()
                if actual['status']['phase'] != 'Succeeded' or digest != hashlib.sha256(b'cloudlab retained service fixture\n').hexdigest():
                    raise RuntimeError('Retained fixture volume content differs')
            finally:
                actual = get('pod', pod_name, namespace)
                if actual and (actual['metadata']['uid'] != uid or actual['metadata'].get('labels', {}).get('cloudlab.io/fixture') != nonce):
                    raise RuntimeError('Retained-volume proof ownership changed; cleanup refused')
                if actual: kube('delete', 'pod', pod_name, '-n', namespace, '--wait=true')
            return {'retained_volume_read': True}
        raise ValueError('Unsupported disposable fixture check')
    elif action == 'backend':
        application = get('application.argoproj.io', approval['name'] + '-' + name, 'argocd')
        if not application or application['spec']['project'] != approval['name'] or application['spec']['destination'] != {
                'server': 'https://kubernetes.default.svc', 'namespace': namespace}:
            raise RuntimeError('Backend lacks its approved GitOps destination')
        source = application['spec'].get('sources') or [application['spec'].get('source', {})]
        catalog = get('application.argoproj.io', 'cloudlab-services', 'argocd')
        platform = catalog['spec']['source'] if catalog else {}
        same_repository = approval['repository'] == platform.get('repoURL')
        if (len(source) != (1 if same_repository else 2) or
                source[0].get('repoURL') != platform.get('repoURL') or
                source[0].get('targetRevision') != platform.get('targetRevision') or
                source[0].get('path') != approval.get('chartPath', 'charts/service') or
                (not same_repository and (source[1].get('repoURL') != approval['repository'] or
                                         source[1].get('targetRevision') != approval['revision'])) or
                application.get('status', {}).get('health', {}).get('status') != 'Healthy' or
                application.get('status', {}).get('sync', {}).get('status') != 'Synced' or application.get('operation')):
            raise RuntimeError('Backend is not converged at its approved source')
        for workload_name in workload_names:
            deployed = get('deployment', workload_name, namespace)
            if (not deployed or deployed.get('status', {}).get('observedGeneration') != deployed['metadata']['generation'] or
                    deployed.get('status', {}).get('availableReplicas') != definition['replicas'] or
                    deployed['spec']['template']['spec']['containers'][0]['image'] != definition['image']):
                raise RuntimeError('Backend is not ready at its pinned image')
        quota = get('resourcequota', 'budget', namespace)
        if not quota or quota['spec']['hard'].get('requests.cpu') != '1':
            raise RuntimeError('Backend lacks its platform resource budget')
    elif action == 'identity':
        oidc = definition['oidc']
        if not oidc['enabled']: return
        from automation.services.contract import identity_request
        desired = identity_request(definition, {oidc.get('secretReference'): 'x' * 48})
        source = get('configmap', 'identity-private-state', 'cloudlab-identity')
        if not source: raise RuntimeError('Private identity input is unavailable')
        configuration = json.loads(source['data']['desired_state'])
        revocations = json.loads(source['data']['revocations'])
        clients = configuration['realms'].get(oidc['realm'], {}).get('clients', [])
        if [c for c in clients if c['id'] == oidc['client']] != [desired['client']] or oidc['client'] in revocations['realms'].get(oidc['realm'], {}).get('clients', []):
            raise RuntimeError('Identity client is not the exact approved contract')
        private = get('application.argoproj.io', 'cloudlab-identity-private', 'argocd')
        revision = private.get('status', {}).get('sync', {}).get('revision') if private else None
        if not revision or not application_ready('cloudlab-identity-private', revision):
            raise RuntimeError('Private identity source is not converged')
        from automation.identity.bootstrap import APP, BASE, reconciled
        state = json.loads((BASE / 'ownership.json').read_text())
        root = get('application.argoproj.io', 'cloudlab-public-root', 'argocd') or {}
        identity = get('application.argoproj.io', APP, 'argocd') or {}
        public_source = root.get('spec', {}).get('source', {})
        identity_source = identity.get('spec', {}).get('source', {})
        revision = root.get('status', {}).get('sync', {}).get('revision')
        # A branch advances after bootstrap; its saved revision is historical.
        if (state.get('phase') != 'scoped' or not revision or not application_ready('cloudlab-public-root', revision) or
                identity_source.get('repoURL') != public_source.get('repoURL') or
                identity_source.get('targetRevision') != public_source.get('targetRevision') or
                identity_source.get('path') != 'platform/identity/keycloak' or not reconciled(revision, state['uid'])):
            raise RuntimeError('Identity writer is not converged')
    elif action == 'data':
        for kind, value in definition['data'].items():
            external = get('externalsecret.external-secrets.io', value['credentialReference'], namespace)
            secret = get('secret', value['credentialReference'], namespace)
            if not condition(external, 'Ready') or not secret or not any(
                    owner.get('uid') == external['metadata']['uid'] for owner in secret['metadata'].get('ownerReferences', [])):
                raise RuntimeError('Service data credentials are not ready and ESO-owned')
            fields = set(secret.get('data', {}))
            expected = {'username', 'password'} if kind == 'database' else {'BUCKET', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY', 'ENDPOINT', 'REGION'}
            if fields != expected:
                raise RuntimeError('Service received unexpected or privileged credential fields')
        for mounted in definition['secrets']:
            secret = get('secret', mounted['name'], namespace)
            external = get('externalsecret.external-secrets.io', mounted['name'], namespace)
            if not condition(external, 'Ready') or not secret or not any(
                    owner.get('uid') == external['metadata']['uid'] for owner in secret['metadata'].get('ownerReferences', [])):
                raise RuntimeError('An approved service credential is not owned by ready ESO')
            if definition['oidc'].get('secretReference') == mounted['name'] and set(secret['data']) != {'client_secret'}:
                raise RuntimeError('Service OIDC credential contains values outside its client scope')
    elif action == 'tls':
        for index, exposure in enumerate([definition['exposure']] + definition.get('additionalExposures', [])):
            if exposure['class'] == 'none': continue
            gateway_namespace = 'cloudlab-gateway-' + exposure['class']
            gateway = get('gateway.gateway.networking.k8s.io', 'cloudlab', gateway_namespace)
            route_name = workload_names[0] + ('-extra-' + str(index-1) if index else '')
            route = get('httproute.gateway.networking.k8s.io', route_name, namespace)
            if not condition(gateway, 'Programmed') or not route or route['spec']['hostnames'] != [exposure['hostname']]:
                raise RuntimeError('Exact service route or gateway is unavailable')
            parents = route.get('status', {}).get('parents', [])
            if not any(all(any(c.get('type') == kind and c.get('status') == 'True' and c.get('observedGeneration') == route['metadata']['generation']
                               for c in parent.get('conditions', [])) for kind in ('Accepted', 'ResolvedRefs')) for parent in parents):
                raise RuntimeError('Service route is not accepted at its current generation')
            address = get('service', 'cloudlab-istio', gateway_namespace)['spec']['clusterIP']
            status, _ = direct_https('https://' + exposure['hostname'] + exposure['path'], address,
                                     {'Host': exposure['hostname'], 'User-Agent': 'CloudLab-Service-Proof/1.0'})
            if status not in (200, 401, 403):
                raise RuntimeError('TLS origin did not reach the ready backend')
    elif action == 'api-protection':
        if not notes: raise ValueError('Reference API check requires the approved notes adapter')
        exposure = definition['exposure']
        address = get('service', 'cloudlab-istio', 'cloudlab-gateway-' + exposure['class'])['spec']['clusterIP']
        for path, expected in (('/api/notes', 401), ('/api/operations', 404)):
            status, _ = direct_https('https://' + exposure['hostname'] + path, address,
                                     {'Host': exposure['hostname'], 'User-Agent': 'CloudLab-Service-Proof/1.0'})
            if status != expected: raise RuntimeError('Anonymous reference API protection failed')
    elif action == 'private-boundary':
        public = get('service', 'cloudlab-istio', 'cloudlab-gateway-public')['spec']['clusterIP']
        public_route = get('httproute.gateway.networking.k8s.io', 'argocd', 'cloudlab-gateway-public')
        public_hosts = public_route.get('spec', {}).get('hostnames', []) if public_route else []
        if len(public_hosts) != 1 or '*' in public_hosts[0]:
            raise RuntimeError('Public gateway has no exact platform TLS hostname')
        private_exposures = [e for e in [definition['exposure']] + definition.get('additionalExposures', []) if e['class'] == 'private']
        for exposure in private_exposures:
            # Authenticate public TLS, then test routing of the private HTTP Host.
            status, _ = direct_https('https://' + public_hosts[0] + exposure['path'], public,
                                     {'Host': exposure['hostname'], 'User-Agent': 'CloudLab-Service-Proof/1.0'})
            if status != 404: raise RuntimeError('Private service is reachable through the public gateway')
        tailnet = get('service', 'cloudlab-tailnet', 'cloudlab-gateway-private')
        addresses = [row['ip'] for row in tailnet.get('status', {}).get('loadBalancer', {}).get('ingress', []) if row.get('ip') and ':' not in row['ip']]
        if len(addresses) != 1: raise RuntimeError('Private gateway has no exact tailnet peer')
        import ipaddress
        if ipaddress.ip_address(addresses[0]) not in ipaddress.ip_network('100.64.0.0/10'):
            raise RuntimeError('Private gateway peer is outside the tailnet')
        return {'privatePeer': addresses[0]}
    elif action in ('retire-route', 'route-absent', 'retire-workload'):
        application_name = approval['name'] + '-' + name
        if action == 'route-absent':
            routes = get('httproutes.gateway.networking.k8s.io', namespace=namespace) or {'items': []}
            if any(route['metadata']['name'].startswith(tuple(workload_names)) for route in routes['items']):
                raise RuntimeError('A route still exposes the retired service')
            return
        appset = get('applicationset.argoproj.io', approval['name'], 'argocd')
        if (not appset or appset['spec']['generators'] != [{'list': {'elements': []}}] or
                not appset['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-services:')):
            raise RuntimeError('Retirement requires the converged administrator-owned retired intent')
        application = get('application.argoproj.io', application_name, 'argocd')
        if not application: return
        if application['spec']['project'] != approval['name'] or application['spec']['destination'] != {
                'server': 'https://kubernetes.default.svc', 'namespace': namespace}:
            raise RuntimeError('Retirement application has a conflicting scope')
        kube('patch', 'application.argoproj.io', application_name, '-n', 'argocd', '--type=merge',
             '-p', json.dumps({'spec': {'syncPolicy': {'automated': {'enabled': False}}}}))
        children = application.get('status', {}).get('resources', [])
        allowed = {'HTTPRoute'} if action == 'retire-route' else {'Deployment', 'Service', 'ServiceAccount', 'HTTPRoute', 'ConfigMap'}
        planned = []
        groups = {'Deployment': 'apps', 'Service': '', 'ServiceAccount': '', 'HTTPRoute': 'gateway.networking.k8s.io', 'ConfigMap': ''}
        for child in children:
            if child['kind'] not in allowed: continue
            if child.get('group', '') != groups[child['kind']]:
                raise RuntimeError('Retirement resource API is outside its approved scope')
            if child.get('namespace') != namespace:
                raise RuntimeError('Retirement cannot delete shared resources or a foreign namespace')
            kind = child['kind'] + ('.' + child['group'] if child.get('group') else '')
            obj = get(kind, child['name'], namespace)
            if not obj: continue
            if not obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith(application_name + ':'):
                raise RuntimeError('Retirement workload has a conflicting tracking owner')
            planned.append((kind, child['name']))
        for kind, child_name in planned:
            kube('delete', kind, child_name, '-n', namespace, '--wait=true', '--timeout=60s')
        if action == 'retire-workload':
            if application['metadata'].get('finalizers'):
                raise RuntimeError('Retirement refuses an unexpected cascading application finalizer')
            kube('delete', 'application.argoproj.io', application_name, '-n', 'argocd', '--cascade=orphan', '--wait=true')
    else:
        raise ValueError('Unsupported read-only service check')


if __name__ == '__main__':
    try:
        result = inspect(json.load(sys.stdin)) or {}
        print(json.dumps(dict(result, ready=True)))
    except Exception:
        raise SystemExit('Service owner readiness check failed; values withheld') from None
