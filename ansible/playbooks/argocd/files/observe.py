"""Observe the reviewed Argo boundary without applying or repairing it."""
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import time


ROOT_APP = 'cloudlab-public-root'
ARGO_APP = 'cloudlab-argocd'
PROJECTS = ('default', 'cloudlab-root', 'cloudlab-platform', 'cloudlab-public')
NAMESPACE = 'argocd'
REVISION = r'[a-f0-9]{40}'
REPOSITORY = r'https://github[.]com/([A-Za-z0-9][A-Za-z0-9-]*)/[A-Za-z0-9][A-Za-z0-9_.-]*[.]git'
EMPTY_PROJECT_FIELDS = ('sourceRepos', 'destinations', 'clusterResourceWhitelist',
                        'clusterResourceBlacklist', 'namespaceResourceWhitelist',
                        'namespaceResourceBlacklist', 'sourceNamespaces', 'signatureKeys', 'syncWindows', 'roles')


def spec_index(documents, kind, names):
    selected = [obj for obj in documents if obj['kind'] == kind and obj['metadata']['name'] in names]
    if len(selected) != len(names) or {obj['metadata']['name'] for obj in selected} != set(names):
        raise RuntimeError('Reviewed Argo declarations are incomplete')
    return {obj['metadata']['name']: obj['spec'] for obj in selected}


def template(chart, release, files, values):
    import yaml

    root = Path(__file__).resolve().parents[4]
    lock = json.loads((root / 'platform/delivery/argocd/artifact.lock.json').read_text())
    command = ['helm', 'template', release, str(root / chart), '--namespace', NAMESPACE,
               '--kube-version', lock['kube_version'], '-f', '-']
    for name in files:
        command.extend(('--show-only', 'templates/' + name))
    result = subprocess.run(command, input=json.dumps(values), capture_output=True,
                            text=True, check=True, timeout=90)
    return [obj for obj in yaml.safe_load_all(result.stdout) if obj]


def prepare(payload):
    from dotenv import dotenv_values

    private = dotenv_values(Path(__file__).resolve().parents[4] / '.env', interpolate=False)
    roots, operator = payload['roots'], payload['operator']
    references = {
        'applications': spec_index(roots, 'Application', (ROOT_APP, ARGO_APP)),
        'projects': spec_index(roots, 'AppProject', PROJECTS),
        'policies': {obj['metadata']['name']: obj['spec'] for obj in operator if obj['kind'] == 'NetworkPolicy'},
        'service': spec_index(operator, 'Service', ('argocd-server',))['argocd-server'],
        'revision': payload['revision'], 'repository': payload['repository'],
        'private_repository': private.get('PRIVATE_CONFIG_REPOSITORY'), 'image_refs': payload['image_refs'],
    }
    if references['applications'][ARGO_APP]['source']['helm']['valuesObject']['identitySyncObserver']:
        # The reviewed templates use these values only to select the bound variant.
        roots = template('gitops/roots/public', ROOT_APP, ('applications.yaml', 'projects.yaml'),
                         {'identity': {'argo': {'valuesRepository': 'https://github.com/example/private.git',
                                                'valuesRevision': '1' * 40}}})
        operator = template('platform/delivery/argocd', 'argocd', ('identity.yaml',), {'argo-cd': {'configs': {
            'cm': {'url': 'https://argocd.example.com', 'additionalUrls': '[https://argocd-private.example.com]',
                   'oidc.config': 'synthetic'}}}})
        references['bound'] = {
            'applications': spec_index(roots, 'Application', (ROOT_APP, ARGO_APP)),
            'projects': spec_index(roots, 'AppProject', PROJECTS),
            'policies': spec_index(operator, 'NetworkPolicy', ('argocd-native-identity',)),
        }
    return references


def read(resource, *names):
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--request-timeout=20s', 'get', resource, *names,
                             '-n', NAMESPACE, '-o', 'json', '--ignore-not-found'],
                            capture_output=True, check=True, timeout=25)
    document = json.loads(result.stdout) if result.stdout.strip() else {'items': []}
    objects = document['items'] if 'items' in document else [document]
    if any(obj['metadata']['namespace'] != NAMESPACE or not obj['metadata'].get('uid') or
           obj['metadata'].get('deletionTimestamp') for obj in objects):
        raise RuntimeError('An Argo resource identity differs or is being deleted')
    return objects


def declared_binding(root, repository, private_repository):
    source = root['spec'].get('source') or {}
    values = (source.get('helm') or {}).get('valuesObject', {})
    identity = values.get('identity', {}) if isinstance(values, dict) else None
    if not isinstance(identity, dict):
        raise RuntimeError('Argo root identity configuration is invalid')
    if 'argo' not in identity:
        return None

    target = identity['argo']
    public = re.fullmatch(REPOSITORY, repository)
    private = re.fullmatch(REPOSITORY, private_repository or '')
    if (not isinstance(target, dict) or set(target) != {'valuesRepository', 'valuesRevision'} or
            not public or not private or private[1].lower() != public[1].lower() or
            private_repository.lower() == repository.lower() or target['valuesRepository'] != private_repository or
            not isinstance(target['valuesRevision'], str) or not re.fullmatch(REVISION, target['valuesRevision'])):
        raise RuntimeError('Argo root does not declare an immutable values pin for the designated private repository')
    return target


def expected_boundary(payload, target):
    if target is None:
        return payload['applications'], payload['projects'], payload['policies']
    if 'bound' not in payload:
        raise RuntimeError('Argo root identity binding has no reviewed bound declaration')
    bound = copy.deepcopy(payload['bound'])
    bound['applications'][ROOT_APP]['source']['helm']['valuesObject']['identity']['argo'] = target
    bound['applications'][ARGO_APP]['sources'][1].update(
        repoURL=target['valuesRepository'], targetRevision=target['valuesRevision'])
    bound['projects']['cloudlab-platform']['sourceRepos'][1] = target['valuesRepository']
    return bound['applications'], bound['projects'], payload['policies'] | bound['policies']


def root_source(source):
    # The reviewed root delegates only these two data flags to their owning handoff.
    source = copy.deepcopy(source)
    values = source.get('helm', {}).get('valuesObject', {})
    data = values.get('data')
    if (isinstance(data, dict) and set(data) == {'configuration'} and isinstance(data['configuration'], dict) and
            data['configuration'] and set(data['configuration']) <= {'maintenance', 'hibernated'} and
            all(type(value) is bool for value in data['configuration'].values())):
        values.pop('data')
    return source


def converged(application, expected, revision):
    spec, status = application['spec'], application.get('status', {})
    metadata = application['metadata']
    if (any(spec.get(field) != expected.get(field)
            for field in ('project', 'destination', 'syncPolicy', 'sourceHydrator')) or
            spec.get('ignoreDifferences', []) != expected.get('ignoreDifferences', []) or
            metadata.get('finalizers') not in (None, [])):
        raise RuntimeError('Argo Application security policy differs from reviewed declarations')

    if 'sources' in expected:
        if spec.get('source') or spec.get('sources') != expected['sources']:
            raise RuntimeError('Argo operator sources differ from the reviewed public source and root identity pin')
    else:
        source = spec.get('source', {})
        expected_source = expected['source']
        if metadata['name'] == ROOT_APP and expected.get('ignoreDifferences'):
            source, expected_source = root_source(source), root_source(expected_source)
        if spec.get('sources') or source != expected_source:
            raise RuntimeError('Argo root source differs from the reviewed source declaration')

    sync = status.get('sync', {})
    compared = sync.get('comparedTo', {})
    phase = status.get('operationState', {}).get('phase')
    if phase in ('Failed', 'Error') or any(condition['type'].endswith('Error')
                                           for condition in status.get('conditions', [])):
        raise RuntimeError('Argo reported an Application comparison or operation error')
    if (application.get('operation') is not None or
            str(metadata.get('annotations', {}).get('argocd.argoproj.io/skip-reconcile')).lower() == 'true' or
            phase != 'Succeeded' or
            status.get('health', {}).get('status') != 'Healthy' or sync.get('status') != 'Synced' or
            compared.get('destination') != expected['destination']):
        return False
    if 'sources' in expected:
        # Argo can serialize the unused single-source field as an empty repoURL.
        return (compared.get('source') in (None, {}, {'repoURL': ''}) and
                compared.get('sources') == expected['sources'] and
                sync.get('revisions') == [revision, expected['sources'][1]['targetRevision']])
    return (not compared.get('sources') and compared.get('source') == spec['source'] and
            sync.get('revision') == revision)


def normalized_project(spec):
    return {key: value for key, value in spec.items() if not (
        (key in EMPTY_PROJECT_FIELDS and value in ([], None)) or
        (key == 'permitOnlyProjectScopedClusters' and value is False))}


def selector_matches(selector, labels):
    if not isinstance(labels, dict) or any(not isinstance(value, str) for value in labels.values()):
        raise RuntimeError('An Argo server label set is invalid')
    if not isinstance(selector, dict) or selector.keys() - {'matchLabels', 'matchExpressions'}:
        raise RuntimeError('An Argo NetworkPolicy pod selector is invalid')
    exact = selector.get('matchLabels', {})
    expressions = selector.get('matchExpressions', [])
    if (not isinstance(exact, dict) or
            any(not isinstance(key, str) or not key or not isinstance(value, str) for key, value in exact.items()) or
            not isinstance(expressions, list)):
        raise RuntimeError('An Argo NetworkPolicy pod selector is invalid')
    matches = all(labels.get(key) == value for key, value in exact.items())
    for expression in expressions:
        if not isinstance(expression, dict) or expression.keys() - {'key', 'operator', 'values'}:
            raise RuntimeError('An Argo NetworkPolicy selector expression is invalid')
        key, operator, values = expression.get('key'), expression.get('operator'), expression.get('values', [])
        if (not isinstance(key, str) or not key or operator not in ('In', 'NotIn', 'Exists', 'DoesNotExist') or
                not isinstance(values, list) or any(not isinstance(value, str) for value in values) or
                bool(values) != (operator in ('In', 'NotIn'))):
            raise RuntimeError('An Argo NetworkPolicy selector expression is invalid')
        result = {'In': labels.get(key) in values, 'NotIn': labels.get(key) not in values,
                  'Exists': key in labels, 'DoesNotExist': key not in labels}
        matches = matches and result[operator]
    return matches


def network_boundary(policies, service_selector, workloads):
    deployments = [obj for obj in workloads if obj['kind'] == 'Deployment' and
                   obj['metadata']['name'] == 'argocd-server']
    if len(deployments) != 1 or not service_selector:
        raise RuntimeError('Argo server Deployment selector is unavailable')
    template_labels = deployments[0]['spec']['template']['metadata'].get('labels', {})
    selector = {'matchLabels': service_selector}
    if not selector_matches(selector, template_labels):
        raise RuntimeError('Argo server pod template differs from the reviewed Service selector')
    server_labels = [template_labels]
    for obj in workloads:
        labels = obj['metadata'].get('labels', {})
        if obj['kind'] == 'Pod' and selector_matches(selector, labels):
            server_labels.append(labels)

    live_policies = read('networkpolicies.networking.k8s.io')
    actual = {obj['metadata']['name']: obj['spec'] for obj in live_policies}
    if len(actual) != len(live_policies) or any(actual.get(name) != spec for name, spec in policies.items()):
        raise RuntimeError('Reviewed Argo NetworkPolicy declarations differ')
    for name in actual.keys() - policies.keys():
        spec = actual[name]
        policy_types = spec.get('policyTypes', [])
        if not isinstance(policy_types, list) or any(value not in ('Ingress', 'Egress') for value in policy_types):
            raise RuntimeError('An Argo NetworkPolicy has unknown policy types')
        selected = any(selector_matches(spec.get('podSelector'), labels) for labels in server_labels)
        # Kubernetes defaults an unspecified policy type to include Ingress.
        if selected and (not policy_types or 'Ingress' in policy_types):
            raise RuntimeError('An unreviewed NetworkPolicy selects Argo server ingress')


def api_boundary(projects, policies, service, workloads):
    live_projects = read('appprojects.argoproj.io', *PROJECTS)
    if (len(live_projects) != len(projects) or
            {obj['metadata']['name']: normalized_project(obj['spec']) for obj in live_projects} !=
            {name: normalized_project(spec) for name, spec in projects.items()}):
        raise RuntimeError('Argo project privileges differ from reviewed declarations')
    configs = {obj['metadata']['name']: obj.get('data', {})
               for obj in read('configmaps', 'argocd-cm', 'argocd-rbac-cm')}
    if (configs.get('argocd-cm', {}).get('users.anonymous.enabled') != 'false' or
            configs.get('argocd-rbac-cm', {}).get('policy.default') != 'role:no-access'):
        raise RuntimeError('Argo anonymous access or default role differs from the reviewed restriction')

    live_service, = read('services', 'argocd-server')
    spec = live_service['spec']
    if (spec.get('type') != 'ClusterIP' or not spec.get('clusterIP') or spec['clusterIP'] == 'None' or
            spec.get('selector') != service['selector'] or spec.get('ports') != service['ports'] or
            any(spec.get(field) for field in ('externalIPs', 'externalName', 'loadBalancerIP', 'loadBalancerClass')) or
            live_service.get('status', {}).get('loadBalancer', {}).get('ingress')):
        raise RuntimeError('Argo server service differs from its internal ClusterIP boundary')

    network_boundary(policies, service['selector'], workloads)


def controllers(items, image_refs, fingerprint):
    if not any(obj['kind'] == 'StatefulSet' and obj['metadata']['name'] == 'argocd-application-controller'
               and obj['spec'].get('replicas') == 1 for obj in items):
        raise RuntimeError('Argo application controller lacks its reviewed replica count')
    for obj in items:
        if (obj['kind'] != 'Pod' or obj.get('status', {}).get('phase') == 'Succeeded' or
                any(owner.get('kind') == 'Job' for owner in obj['metadata'].get('ownerReferences', []))):
            continue
        containers = obj['spec']['containers'] + obj['spec'].get('initContainers', [])
        if any(container['image'] not in image_refs for container in containers):
            raise RuntimeError('Argo runtime image differs from the reviewed digest lock')
    return fingerprint(items)


def observe(payload, fingerprint):
    if not re.fullmatch(REVISION, payload['revision']):
        raise RuntimeError('GitOps observation requires a reviewed public revision')
    def roots():
        observed = {obj['metadata']['name']: obj for obj in read('applications.argoproj.io', ROOT_APP, ARGO_APP)}
        if observed.keys() != {ROOT_APP, ARGO_APP}:
            return None
        target = declared_binding(observed[ROOT_APP], payload['repository'], payload['private_repository'])
        applications, _, _ = expected_boundary(payload, target)
        if not all(converged(obj, applications[name], payload['revision']) for name, obj in observed.items()):
            return None
        identities = {name: obj['metadata']['uid'] for name, obj in observed.items()}
        return identities, target.copy() if target is not None else None

    deadline = time.monotonic() + 600
    while not (baseline_roots := roots()):
        if time.monotonic() >= deadline:
            raise RuntimeError('Public GitOps did not converge at the reviewed sources')
        time.sleep(5)
    workload_types = 'deployments,daemonsets,statefulsets,pods'
    workloads = read(workload_types)
    _, projects, policies = expected_boundary(payload, baseline_roots[1])
    api_boundary(projects, policies, payload['service'], workloads)
    baseline_controllers = controllers(workloads, payload['image_refs'], fingerprint)
    started = time.monotonic()
    while time.monotonic() - started < 60:
        time.sleep(10)
        if (roots() != baseline_roots or
                controllers(read(workload_types), payload['image_refs'], fingerprint) != baseline_controllers):
            raise RuntimeError('Public GitOps roots or controllers changed during stability observation')
    return {'public_roots_converged': True, 'project_boundary_observed': True,
            'api_configuration_observed': True, 'network_policy_configuration_observed': True,
            'controllers_stable': True, 'stability_seconds': round(time.monotonic() - started, 1),
            'dynamic_denial_tested': False, 'private_sources_tested': False}


if __name__ == '__main__':
    try:
        payload = json.load(sys.stdin)
        report = prepare(payload) if sys.argv[1:] == ['prepare'] else observe(payload, fingerprint)
        print(json.dumps(report))
    except RuntimeError as error:
        raise SystemExit(str(error)) from None
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        raise SystemExit('GitOps observation could not read its required inputs; diagnostics withheld') from None
