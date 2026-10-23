"""Bounded disposable acceptance; Argo owns desired workloads, Rollouts owns execution."""
import json
import time
import urllib.parse
import urllib.request

from playbooks.istio.files.kube import application_ready, condition, get, kube, wait
from playbooks.keycloak.files.health import direct_https

NS = 'cloudlab-app-rollouts-proof'
APP = 'cloudlab-rollouts-proof'
NAME = 'release-proof'
OWNER = 'cloudlab.io/rollouts-proof'


def owned(obj, nonce):
    if obj and obj['metadata'].get('labels', {}).get(OWNER) != nonce:
        raise RuntimeError('Disposable release owner differs; mutation refused')
    return obj


def write(obj, nonce):
    metadata = obj['metadata']
    namespace = metadata.get('namespace')
    kind = obj['kind'] + ('.' + obj['apiVersion'].split('/')[0] if '/' in obj['apiVersion'] else '')
    owned(get(kind, metadata['name'], namespace), nonce)
    metadata.setdefault('labels', {})[OWNER] = nonce
    kube('apply', '--server-side', '--field-manager=cloudlab-rollouts-fixture', '-f', '-', document=obj)


def snapshot():
    rollout = get('rollout.argoproj.io', NAME, NS) or {}
    route = get('httproute', NAME, NS) or {}
    app = get('application.argoproj.io', APP, 'argocd') or {}
    status = rollout.get('status', {})
    containers = rollout.get('spec', {}).get('template', {}).get('spec', {}).get('containers', [])
    environment = {o['name']: o.get('value') for o in containers[0].get('env', [])} if containers else {}
    analysis = status.get('canary', {}).get('currentStepAnalysisRunStatus', {}).get('name')
    if not analysis and rollout:
        candidates = [o for o in (get('analysisruns.argoproj.io', namespace=NS) or {'items': []})['items']
                      if any(ref.get('uid') == rollout['metadata']['uid'] for ref in o['metadata'].get('ownerReferences', []))
                      and any(arg.get('name') == 'revision' and arg.get('value') == status.get('currentPodHash')
                              for arg in o['spec'].get('args', []))]
        if candidates:
            analysis = max(candidates, key=lambda o: o['metadata']['creationTimestamp'])['metadata']['name']
    run = get('analysisrun.argoproj.io', analysis, NS) if analysis else None
    metrics = []
    for metric in (run or {}).get('status', {}).get('metricResults', []):
        metrics.append({key: metric.get(key) for key in ('name', 'phase', 'count', 'successful', 'failed', 'error')})
        metrics[-1]['values'] = [m.get('value') for m in metric.get('measurements', [])]
    return {'phase': status.get('phase'), 'stable': status.get('stableRS'), 'current': status.get('currentPodHash'),
            'sequence': environment.get('RELEASE_SEQUENCE'), 'mode': environment.get('RELEASE_MODE'),
            'observed': str(status.get('observedGeneration')) == str(rollout.get('metadata', {}).get('generation', -1)),
            'abort': status.get('abort', False), 'analysis': analysis,
            'analysis_phase': (run or {}).get('status', {}).get('phase'), 'metrics': metrics,
            'weights': [b.get('weight') for r in route.get('spec', {}).get('rules', []) for b in r.get('backendRefs', [])],
            'sync': app.get('status', {}).get('sync', {}).get('status'),
            'operation': app.get('status', {}).get('operationState', {}).get('phase')}


def run(request):
    nonce = request['nonce']
    import re
    if not re.fullmatch('[a-f0-9]{32}', nonce):
        raise ValueError('Invalid disposable release nonce')
    action = request['action']
    if action == 'prerequisites':
        if not application_ready('cloudlab-rollouts', request['revision']):
            return {'ready': False}
        from datetime import datetime, timezone
        lease = get('lease.coordination.k8s.io', 'argo-rollouts-controller-lock', 'argo-rollouts') or {}
        renewed = lease.get('spec', {}).get('renewTime')
        if (not lease.get('spec', {}).get('holderIdentity') or not renewed or
                (datetime.now(timezone.utc) - datetime.fromisoformat(renewed.replace('Z', '+00:00'))).total_seconds() > 30):
            return {'ready': False}
        controller = get('deployment', 'argo-rollouts', 'argo-rollouts')
        if controller['spec']['template']['spec']['containers'][0]['image'] != request['controller_image']:
            raise RuntimeError('Rollouts controller image differs from reviewed pin')
        config = get('configmap', 'argo-rollouts-config', 'argo-rollouts')
        if request['plugin_sha256'] not in config['data']['trafficRouterPlugins']:
            raise RuntimeError('Gateway plugin checksum is not enforced')
        denial = kube('auth', 'can-i', 'get', 'secrets', '--all-namespaces',
                      '--as=system:serviceaccount:argo-rollouts:argo-rollouts', allow_failure=True)
        if denial.returncode != 1 or denial.stdout.strip() != 'no':
            raise RuntimeError('Rollouts Secret access denial could not be established')
        routes = get('httproute', namespace='cloudlab-app-notes')['items']
        private = [o for o in routes if o['spec']['parentRefs'][0].get('namespace') == 'cloudlab-gateway-private']
        if not private:
            raise RuntimeError('Accepted private gateway topology is unavailable')
        host = private[0]['spec']['hostnames'][0]
        gateway = get('service', 'cloudlab-istio', 'cloudlab-gateway-private')['spec']['clusterIP']
        # The measured fixture never changes Notes or its retained admission policy.
        workloads = get('deployments', namespace='cloudlab-app-notes')['items']
        retained = {o['metadata']['name']: [o['metadata']['uid'], o['spec']['template']['spec']['containers'][0]['image']]
                    for o in workloads}
        policy = get('policy.kyverno.io', 'application-artifacts', 'cloudlab-app-notes')
        delivery = get('externalsecret.external-secrets.io', 'harbor-application-pull', 'cloudlab-app-notes')
        pull_sources = delivery.get('spec', {}).get('dataFrom', []) if delivery else []
        images = {row[1] for row in retained.values()}
        if (len(images) != 1 or not policy or policy['spec'].get('validationFailureAction') != 'Enforce' or
                not condition(policy, 'Ready') or not condition(delivery, 'Ready') or
                any(not o['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-services:')
                    for o in (policy, delivery)) or
                len(pull_sources) != 1 or set(pull_sources[0]) != {'extract'} or
                pull_sources[0]['extract'].get('key') != 'harbor-cloudlab-public-pull'):
            raise RuntimeError('Accepted signed public release and ESO pull delivery are required')
        image = next(iter(images))
        if not any(image.startswith(reference.removesuffix('*')) for rule in policy['spec']['rules']
                   for verification in rule.get('verifyImages', []) for reference in verification.get('imageReferences', [])):
            raise RuntimeError('Fixture image is not covered by the retained signature verifier')
        import hashlib
        artifact = {'image': image, 'policy': policy['spec'], 'delivery': delivery['spec'],
                    'policy_hash': hashlib.sha256(json.dumps(policy['spec'], sort_keys=True).encode()).hexdigest()}
        return {'host': host, 'gateway': gateway, 'retained': retained, 'artifact': artifact}
    owned(get('namespace', NS), nonce)
    owned(get('appproject.argoproj.io', APP, 'argocd'), nonce)
    owned(get('application.argoproj.io', APP, 'argocd'), nonce)
    if action == 'prepare':
        for obj in request['objects']:
            if ((obj['kind'] == 'Namespace' and obj['metadata']['name'] == NS) or
                (obj['metadata'].get('namespace') == NS and obj['kind'] in ('ResourceQuota', 'NetworkPolicy', 'AuthorizationPolicy', 'Policy', 'ExternalSecret')) or
                (obj['metadata'].get('namespace') == 'argocd' and obj['metadata']['name'] == APP and obj['kind'] in ('AppProject', 'Application'))):
                if obj['kind'] in ('Policy', 'ExternalSecret'):
                    kind, name = ('policy.kyverno.io', 'application-artifacts') if obj['kind'] == 'Policy' else (
                        'externalsecret.external-secrets.io', 'harbor-application-pull')
                    if obj['metadata']['name'] != name or obj['spec'] != get(kind, name, 'cloudlab-app-notes')['spec']:
                        raise RuntimeError('Disposable signature or registry declaration differs from its accepted owner')
                if obj['kind'] == 'Application':
                    wait(lambda: condition(get('externalsecret.external-secrets.io', 'harbor-application-pull', NS), 'Ready') and
                         condition(get('policy.kyverno.io', 'application-artifacts', NS), 'Ready'),
                         'disposable signed admission and ESO pull readiness', timeout=180)
                write(obj, nonce)
            else:
                raise ValueError('Fixture resource is outside the disposable scope')
    elif action == 'release':
        app = get('application.argoproj.io', APP, 'argocd')
        if not app or app['spec']['source']['path'] != 'charts/service' or app['spec']['destination']['namespace'] != NS:
            raise RuntimeError('Disposable application scope changed')
        app['spec']['source']['helm']['valuesObject']['environment'].update(request['environment'])
        app['metadata']['annotations'] = {'argocd.argoproj.io/refresh': 'hard'}
        kube('replace', '--field-manager=cloudlab-rollouts-fixture', '-f', '-', document=app)
    elif action == 'refresh':
        kube('annotate', 'application.argoproj.io', APP, '-n', 'argocd', 'argocd.argoproj.io/refresh=hard', '--overwrite')
    elif action == 'query-failure':
        state = snapshot()
        if not state['analysis']:
            return {'injected': False}
        obj = get('analysisrun.argoproj.io', state['analysis'], NS)
        rollout = get('rollout.argoproj.io', NAME, NS)
        if not any(o.get('uid') == rollout['metadata']['uid'] and o.get('controller') is True
                   for o in obj['metadata'].get('ownerReferences', [])):
            raise RuntimeError('Query fixture is not owned by the disposable Rollout')
        # Deliberately corrupt one pending generated query, never a Git-owned template.
        patch = [{'op': 'test', 'path': '/metadata/uid', 'value': obj['metadata']['uid']},
                 {'op': 'replace', 'path': '/spec/metrics/0/provider/prometheus/query', 'value': '('}]
        kube('patch', 'analysisrun.argoproj.io', state['analysis'], '-n', NS, '--type=json', '-p', json.dumps(patch))
        return {'injected': True}
    elif action == 'rollback-requests':
        gateway = get('service', 'cloudlab-istio', 'cloudlab-gateway-private')['spec']['clusterIP']
        for _ in range(30):
            status, body = direct_https('https://' + request['host'] + '/canary-proof', gateway,
                                        {'User-Agent': 'CloudLab-Release-Proof/1.0'})
            if status != 200 or json.loads(body).get('revision') != request['stable']:
                raise RuntimeError('New fixture request did not reach the healthy stable revision')
            time.sleep(0.2)
        return {'new_stable_requests': 30}
    elif action == 'cleanup':
        if get('namespace', NS):
            delivery = owned(get('externalsecret.external-secrets.io', 'harbor-application-pull', NS), nonce)
            secret_objects = (get('secrets', namespace=NS) or {'items': []})['items']
            if ((get('pvc', namespace=NS) or {'items': []})['items'] or any(
                    secret['metadata']['name'] != 'harbor-application-pull' or not delivery or
                    not any(ref.get('uid') == delivery['metadata']['uid'] and ref.get('controller') is True
                            for ref in secret['metadata'].get('ownerReferences', [])) for secret in secret_objects)):
                raise RuntimeError('Disposable namespace contains unexpected data or credentials')
        app = get('application.argoproj.io', APP, 'argocd')
        if app:
            if app['metadata'].get('finalizers'):
                raise RuntimeError('Unexpected application finalizer; cleanup refused')
            kube('delete', 'application.argoproj.io', APP, '-n', 'argocd', '--cascade=orphan', '--wait=true')
        if get('namespace', NS):
            # Only the owned ESO pull copy can accompany this data-free fixture.
            kube('delete', 'namespace', NS, '--wait=true', '--timeout=180s')
        if get('appproject.argoproj.io', APP, 'argocd'):
            kube('delete', 'appproject.argoproj.io', APP, '-n', 'argocd', '--wait=true')
        return {'fixture_removed': True}
    elif action != 'snapshot':
        raise ValueError('Unsupported progressive delivery operation')
    return snapshot()


if __name__ == '__main__':
    import sys
    try:
        print(json.dumps(run(json.load(sys.stdin))))
    except (ValueError, RuntimeError) as error:
        raise SystemExit(str(error)) from None
    except Exception:
        raise SystemExit('Progressive delivery check failed; private diagnostics withheld') from None
