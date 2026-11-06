"""Protected finite handoff execution; never authorize from source receipts alone.

The production preflight and backend transition remain closed until their native
integration is implemented and qualified. Source preparation is not execution.
"""
import copy
from contextlib import contextmanager
import json
import math
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import parse_qs, urlsplit

from playbooks.observability.files import handoff as h, native_transport as transport, writer_guard

VERSION = 'cloudlab-observability-execution/v1'
TARGET = 'cloudlab.io/observability-handoff-target-cluster-uid'
HOLD = {'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False}
RESOURCES = {
    ('v1', 'namespaces'): 'namespaces', ('v1', 'pods'): 'pods',
    ('v1', 'configmaps'): 'configmaps', ('v1', 'serviceaccounts'): 'serviceaccounts',
    ('v1', 'secrets'): 'secrets', ('v1', 'services'): 'services',
    ('v1', 'endpoints'): 'endpoints', ('v1', 'events'): 'events',
    ('v1', 'persistentvolumeclaims'): 'persistentvolumeclaims',
    ('v1', 'persistentvolumes'): 'persistentvolumes',
    ('argoproj.io/v1alpha1', 'applications'): 'applications.argoproj.io',
    ('argoproj.io/v1alpha1', 'applicationsets'): 'applicationsets.argoproj.io',
    ('rbac.authorization.k8s.io/v1', 'roles'): 'roles.rbac.authorization.k8s.io',
    ('rbac.authorization.k8s.io/v1', 'rolebindings'): 'rolebindings.rbac.authorization.k8s.io',
    ('batch/v1', 'jobs'): 'jobs.batch',
    ('networking.k8s.io/v1', 'networkpolicies'): 'networkpolicies.networking.k8s.io',
    ('apps/v1', 'deployments'): 'deployments.apps', ('apps/v1', 'statefulsets'): 'statefulsets.apps',
    ('apps/v1', 'replicasets'): 'replicasets.apps',
    ('monitoring.coreos.com/v1', 'alertmanagers'): 'alertmanagers.monitoring.coreos.com',
    ('monitoring.coreos.com/v1alpha1', 'alertmanagerconfigs'): 'alertmanagerconfigs.monitoring.coreos.com',
    ('monitoring.coreos.com/v1', 'podmonitors'): 'podmonitors.monitoring.coreos.com',
    ('monitoring.coreos.com/v1', 'servicemonitors'): 'servicemonitors.monitoring.coreos.com',
    ('monitoring.coreos.com/v1', 'prometheusrules'): 'prometheusrules.monitoring.coreos.com',
    ('gateway.networking.k8s.io/v1', 'httproutes'): 'httproutes.gateway.networking.k8s.io',
    ('security.istio.io/v1', 'authorizationpolicies'): 'authorizationpolicies.security.istio.io',
    ('storage.k8s.io/v1', 'storageclasses'): 'storageclasses.storage.k8s.io',
    ('longhorn.io/v1beta2', 'volumes'): 'volumes.longhorn.io',
}
NAME = re.compile(r'[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?')


def document_path(obj):
    metadata = obj['metadata']
    candidates = [resource for (version, resource), kind in RESOURCES.items()
        if version == obj.get('apiVersion') and resource.rstrip('s').lower() == obj.get('kind', '').lower()]
    # Kubernetes plurals which cannot be recovered by removing a final s.
    plurals = {'NetworkPolicy': 'networkpolicies', 'AuthorizationPolicy': 'authorizationpolicies',
        'Endpoints': 'endpoints', 'Ingress': 'ingresses'}
    resource = plurals.get(obj.get('kind'), candidates[0] if len(candidates) == 1 else None)
    h.require(resource and (obj['apiVersion'], resource) in RESOURCES, 'Unsupported execution resource')
    prefix = '/api/v1' if obj['apiVersion'] == 'v1' else '/apis/' + obj['apiVersion']
    return prefix + ('/namespaces/' + metadata['namespace'] if metadata.get('namespace') else '') + '/' + resource + '/' + metadata['name']


def idle(obj):
    h.require(obj is not None and not obj.get('operation')
        and obj.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating')
        and not any(obj.get('metadata', {}).get(key) for key in ('deletionTimestamp', 'ownerReferences', 'finalizers'))
        and obj.get('kind') == 'Application' and obj.get('apiVersion') == 'argoproj.io/v1alpha1'
        and obj.get('metadata', {}).get('namespace') == 'argocd', 'Application is busy, deleting or has foreign ownership')
    transport.identity(obj)
    return obj


class NativeIO:
    """Captured fixed-argument kubectl I/O; never execute caller command strings."""
    def __init__(self, operation):
        self.operation = operation
        self.namespace = transport.namespace(operation)
        self.deadline = None

    @contextmanager
    def bounded(self, deadline):
        h.require(type(deadline) in (int, float) and math.isfinite(deadline) and deadline > time.monotonic(),
            'Native operation deadline expired')
        previous = self.deadline
        self.deadline = deadline if previous is None else min(previous, deadline)
        try:
            yield
        finally:
            self.deadline = previous

    def command(self, args, *, body=None, limit=h.PRIVATE_LIMIT, timeout=30):
        remaining = timeout if self.deadline is None else min(timeout, self.deadline - time.monotonic())
        h.require(remaining > 0, 'Native operation deadline expired')
        api_timeout = min(10, remaining)
        result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', '--request-timeout=' + str(api_timeout) + 's', *args],
            input=body, capture_output=True, timeout=remaining)
        h.require(result.returncode == 0 and not result.stderr.strip() and len(result.stdout) <= limit,
            'Bounded handoff Kubernetes operation failed; diagnostics withheld')
        return result.stdout

    def target(self, path):
        parsed = urlsplit(path)
        h.require(not parsed.scheme and not parsed.netloc and not parsed.fragment
            and '%' not in parsed.path and '..' not in parsed.path and '\\' not in path,
            'Execution path escaped the native API')
        match = re.fullmatch(r'/(?:api/(v1)|apis/([a-z0-9.]+/v[0-9]+(?:alpha[0-9]+|beta[0-9]+)?))'
            r'(?:/namespaces/([a-z0-9-]+))?/([a-z]+)(?:/([a-z0-9.-]+))?', parsed.path)
        h.require(match is not None, 'Unsupported execution API path')
        core, group, namespace, resource, name = match.groups()
        h.require((core or group, resource) in RESOURCES and (name is None or NAME.fullmatch(name))
            and namespace in (None, 'argocd', 'cloudlab-observability', 'longhorn-system', 'default', self.namespace),
            'Execution resource escaped its accepted scope')
        if resource == 'namespaces':
            h.require(namespace is None and name in (None, 'cloudlab-observability', self.namespace, 'kube-system'),
                'Execution namespace observation escaped its fixed discovery scope')
        query = parse_qs(parsed.query, strict_parsing=True) if parsed.query else {}
        h.require(set(query) <= {'labelSelector'} and all(len(values) == 1 for values in query.values()),
            'Unsupported execution list query')
        if query:
            selector = query['labelSelector'][0]
            h.require((namespace == 'argocd' and resource == 'pods' and selector in
                ('app.kubernetes.io/component=repo-server', 'app.kubernetes.io/component=redis'))
                or (namespace == self.namespace and resource == 'pods' and selector == 'job-name=' + transport.JOB),
                'Execution selector escaped its fixed discovery scope')
        return RESOURCES[(core or group, resource)], namespace, name, query

    def request(self, path, method='GET', body=None, content_type=None):
        resource, namespace, name, query = self.target(path)
        scope = ['-n', namespace] if namespace else []
        if method == 'GET':
            h.require(body is None and content_type is None, 'Unexpected GET payload')
            args = ['get', resource, *([name] if name else []), *scope, '--ignore-not-found',
                '--show-managed-fields=true', '-o', 'json']
            if query: args += ['-l', query['labelSelector'][0]]
            raw = self.command(args)
            if not raw.strip():
                h.require(name is not None, 'Native list returned no complete document')
                return None  # Successful --ignore-not-found is the only absence case.
            value = h.strict_json(raw, h.PRIVATE_LIMIT)
            if name is None:
                h.require(isinstance(value, dict) and isinstance(value.get('items'), list)
                    and len(value['items']) <= 512 and not value.get('metadata', {}).get('continue'),
                    'Native discovery is incomplete or excessive')
            return value
        h.require(not query and isinstance(body, (dict, list)), 'Invalid native mutation payload')
        target_name = body.get('metadata', {}).get('name') if method == 'POST' and isinstance(body, dict) else name
        if method == 'POST':
            h.require(isinstance(body, dict) and body.get('metadata', {}).get('namespace') == namespace,
                'Native creation namespace differs')
        if resource == 'applications.argoproj.io':
            h.require(method == 'PATCH' and target_name in transport.CHILDREN and namespace == 'argocd',
                'Execution cannot mutate root, parent or unrelated Applications')
        elif resource in ('roles.rbac.authorization.k8s.io', 'rolebindings.rbac.authorization.k8s.io'):
            h.require(namespace == 'argocd' and target_name == self.namespace, 'Execution RBAC escaped its collector realm')
        elif resource == 'namespaces':
            h.require(namespace is None and target_name == self.namespace, 'Execution namespace mutation escaped its collector realm')
        elif namespace == self.namespace:
            h.require(resource in ('jobs.batch', 'networkpolicies.networking.k8s.io', 'configmaps', 'serviceaccounts')
                and target_name == transport.JOB, 'Execution mutation escaped exact collector resources')
        elif namespace == 'cloudlab-observability':
            transfer = resource in ('podmonitors.monitoring.coreos.com', 'servicemonitors.monitoring.coreos.com',
                'prometheusrules.monitoring.coreos.com', 'httproutes.gateway.networking.k8s.io')
            if transfer:
                h.require(method == 'PATCH' and isinstance(body, list)
                    and len([row for row in body if row.get('op') == 'replace']) == 1
                    and all((row.get('op') == 'test' and row.get('path') in ('/metadata/uid', '/metadata/resourceVersion', '/spec',
                        '/metadata/annotations/argocd.argoproj.io~1tracking-id'))
                        or (row.get('op') == 'replace' and row.get('path') == '/metadata/annotations/argocd.argoproj.io~1tracking-id')
                        for row in body), 'Only exact tracking ownership CAS is allowed')
            else:
                h.require((resource == 'persistentvolumeclaims' and target_name == 'alertmanager-cloudlab-db-alertmanager-cloudlab-0')
                or (resource in ('pods', 'configmaps') and isinstance(target_name, str)
                    and re.fullmatch(r'cloudlab-(?:checkpoint|checkpoint-writer|handoff-probe)-' + self.operation, target_name)),
                'Execution backend mutation escaped its exact operation scope')
                h.require(method in ('POST', 'DELETE'), 'Backend workloads remain owned by Argo')
        else:
            raise RuntimeError('Execution mutation escaped accepted field ownership')
        raw = h.canonical(body)
        h.require(len(raw) <= h.LIMIT, 'Native mutation exceeds bound')
        if method == 'POST':
            h.require(name is None and content_type is None, 'Invalid native creation target')
            return h.strict_json(self.command(['create', '--raw', path, '-f', '-'], body=raw), h.PRIVATE_LIMIT)
        if method == 'DELETE':
            h.require(name is not None and content_type is None and body.get('kind') == 'DeleteOptions'
                and set(body.get('preconditions', {})) == {'uid', 'resourceVersion'}, 'Deletion requires exact native identity')
            return h.strict_json(self.command(['delete', '--raw', path, '-f', '-'], body=raw), h.PRIVATE_LIMIT)
        h.require(method == 'PATCH' and name is not None and content_type == 'application/json-patch+json'
            and isinstance(body, list), 'Only exact JSON-patch mutation is supported')
        return h.strict_json(self.command(['patch', resource, name, *scope, '--type=json', '--patch-file=/dev/stdin',
            '-o', 'json'], body=raw), h.PRIVATE_LIMIT)

    def collect_bytes(self, namespace, pod, container, arguments):
        h.require(namespace == self.namespace and re.fullmatch(transport.JOB + '-[a-z0-9]+', pod)
            and container == 'transport' and arguments == transport.COLLECT, 'Exec escaped the exact collector command')
        return self.command(['exec', '-n', namespace, pod, '-c', container, '--', *arguments], timeout=30)

    def collector(self, value, record):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            rows = self.request('/api/v1/namespaces/' + self.namespace + '/pods?labelSelector=job-name=' + transport.JOB)['items']
            h.require(len(rows) <= 1, 'Collector Pod discovery is ambiguous')
            if rows:
                pod = rows[0]
                h.require(pod.get('status', {}).get('phase') not in ('Failed', 'Succeeded'), 'Collector exited before collection')
                statuses = pod.get('status', {}).get('containerStatuses', [])
                if any(row.get('name') == 'transport' and row.get('state', {}).get('running') for row in statuses):
                    transport.transport_pod(pod, value, record['objects']['job']['identity']['uid'])
                    raw = self.command(['logs', '-n', self.namespace, pod['metadata']['name'], '-c', 'transport', '--tail=1'], limit=4096)
                    if raw.strip():
                        status = h.strict_json(raw, 4096)
                        h.require(status.get('status') in ('ready', 'failed'), 'Unexpected collector status')
                        h.require(status['status'] == 'ready', 'Native collector failed')
                        return pod, status
            time.sleep(2)
        raise RuntimeError('Native collector readiness exceeded its bound')


def production_preflight(io, directory, intent):
    from playbooks.observability.files import handoff_backend
    return handoff_backend.production_preflight(io, directory, intent)


def backend_phase(io, directory, phase, journal):
    from playbooks.observability.files import handoff_backend
    return handoff_backend.backend_phase(io, directory, phase, journal, persist, sync_resources)


def pending_result(error, *, changed=False):
    from playbooks.observability.files import handoff_backend
    h.require(isinstance(error, handoff_backend.NativeConfigPending)
        and error.purpose in ('original', 'muted', 'restored'), 'Unexpected native classification state')
    return {'stage': 'native-config-pending', 'purpose': error.purpose, 'changed': changed, 'ready': False}


def state(directory):
    value = h.strict_json(h.read_private(Path(directory) / 'execution.json'))
    h.require(isinstance(value, dict) and set(value) == {'authorization', 'steps', 'phases'}
        and isinstance(value['steps'], dict) and isinstance(value['phases'], dict), 'Invalid protected execution journal')
    return value


def check_continuation(directory):
    """An unrelated or ambiguous fence never authorizes a handoff continuation."""
    if h.private_path(writer_guard.RETIREMENT_FENCE, missing=True) is None:
        writer_guard.check_fence()
        return None
    journal = state(directory)
    authorization = journal['authorization']
    fence = h.strict_json(h.read_private(writer_guard.RETIREMENT_FENCE))
    h.require(authorization.get('version') == VERSION and fence == authorization
        and authorization.get('operationId') == Path(directory).name.removeprefix('handoff-')
        and type(authorization.get('expires')) is int and int(time.time()) <= authorization['expires'],
        'Execution fence differs or approved maintenance window expired')
    manifest = h.verify_bundle(Path(directory) / 'runtime', Path(directory) / 'bundle.json')
    h.require(authorization['bundleSHA256'] == h.digest(h.canonical(manifest))
        and authorization['sourceSHA256'] == h.digest(h.read_private(Path(directory) / 'source.json'))
        and authorization['baselineSHA256'] == h.digest(h.read_private(Path(directory) / 'baseline.json')),
        'Execution authority code, source or baseline changed')
    intent = h.phase_json(h.phase_file(directory, 'baseline', 'intent'))
    h.qualification_files(directory, intent)
    actual = scope_gate(NativeIO(manifest['operationId']), directory, intent)
    h.require(all(authorization.get(key) == value for key, value in actual.items()),
        'Execution qualification scope or live cluster identity changed')
    return journal


def require_execution(directory):
    journal = check_continuation(directory)
    h.require(journal is not None, 'Source preparation grants no execution authority')
    return journal


def scoped_evidence(directory, intent):
    reference = intent['prepared']['profiles']['acceptedArtifacts']['handoff']
    expected = reference.get('artifactDigests', {}).get(h.HANDOFF_EVIDENCE)
    h.require(isinstance(expected, str) and re.fullmatch('[a-f0-9]{64}', expected), 'Typed handoff evidence is required')
    raw = h.read_private(Path(directory) / 'qualifications' / 'handoff' / h.HANDOFF_EVIDENCE)
    h.require(h.digest(raw) == expected, 'Typed handoff evidence bytes changed')
    evidence = h.strict_json(raw)
    return h.handoff_scope(intent, evidence), evidence


def live_cluster_uid(io):
    obj = io.request('/api/v1/namespaces/kube-system')
    h.require(obj is not None and obj.get('apiVersion') == 'v1' and obj.get('kind') == 'Namespace'
        and obj.get('metadata', {}).get('name') == 'kube-system'
        and obj['metadata'].get('namespace') is None and not obj['metadata'].get('deletionTimestamp')
        and h.valid_cluster_uid(obj['metadata'].get('uid')), 'Live cluster identity is unavailable')
    return obj['metadata']['uid']


def target_from_draft(directory):
    """The first native six-Application output supplies private target authority."""
    intent = h.phase_json(h.phase_file(directory, 'baseline', 'intent'))
    value = h.phase_json(h.phase_file(directory, 'baseline', 'input'))
    draft = h.phase_json(h.phase_file(directory, 'baseline', 'draft'))
    payload = h.phase_json(h.phase_file(directory, 'baseline', 'draft-payload'))
    collector = h.phase_json(h.phase_file(directory, 'baseline', 'transport'))
    h.require(draft['intentSHA256'] == h.digest(h.canonical(intent))
        and draft['payloadSHA256'] == h.digest(h.canonical(payload))
        and draft['custody'] == h.collection_binding(collector)
        and collector['context'] == {'operation': intent['operationId'], 'codeSHA256': value['codeSHA256'],
            'inputSHA256': h.digest(h.canonical(value))}, 'Native private target custody changed')
    applications = [payload['phaseApplications'][name] for name in payload['applicationOrder']]
    transport.phase_applications(value['source'], applications)
    actual = {'parent': applications, 'baseline': payload['baseline']}
    h.require(h.digest(h.canonical(actual)) == collector['sourcePayloadSHA256'], 'Native private target output changed')
    targets = {obj['metadata']['annotations'].get(TARGET) for obj in applications}
    h.require(len(targets) == 1 and h.valid_cluster_uid(next(iter(targets))), 'Native private target annotation differs')
    return {'version': 'cloudlab-observability-target/v1', 'operationId': intent['operationId'],
        'targetClusterUID': targets.pop(), 'intentSHA256': h.digest(h.canonical(intent)),
        'draftSHA256': h.digest(h.canonical(draft)), 'collector': h.collection_binding(collector)}


def scope_gate(io, directory, intent):
    """Every grant after initial discovery requires the sealed private target."""
    scope, evidence = scoped_evidence(directory, intent)
    binding = h.phase_json(Path(directory) / 'target-cluster.json')
    discovery = h.phase_json(Path(directory) / 'initial-discovery.json')
    h.require(binding == target_from_draft(directory) and binding['operationId'] == intent['operationId']
        and discovery.get('stage') == 'bound' and discovery.get('operationId') == binding['operationId']
        and discovery.get('intentSHA256') == binding['intentSHA256']
        and discovery.get('targetClusterUID') == binding['targetClusterUID'] and discovery.get('qualificationScope') == scope
        and (intent.get('targetClusterUID') is None or intent['targetClusterUID'] == binding['targetClusterUID']),
        'Protected private target binding changed')
    actual = live_cluster_uid(io)
    h.require(actual == binding['targetClusterUID']
        and (scope['kind'] != 'mechanism-rehearsal' or actual == evidence['observedClusterUID']),
        'Live target cluster identity differs from private intent or qualification')
    return {'targetClusterUID': actual, 'qualificationScope': scope}


def initial_discovery(io, directory, intent, record):
    """One protected baseline read; never a caller-selectable authority bypass."""
    h.require(intent['phase'] == 'baseline' and intent['previousPhaseSHA256'] is None
        and h.phase_head(directory) is None
        and h.private_path(Path(directory) / 'target-cluster.json', missing=True) is None,
        'Initial discovery is not available')
    scope, evidence = scoped_evidence(directory, intent)
    actual = live_cluster_uid(io)
    h.require(scope['kind'] != 'mechanism-rehearsal' or actual == evidence['observedClusterUID'],
        'Mechanism qualification cannot grant discovery on this cluster')
    path = Path(directory) / 'initial-discovery.json'
    expected = {'version': 'cloudlab-observability-discovery/v1', 'operationId': intent['operationId'],
        'intentSHA256': h.digest(h.canonical(intent)), 'targetClusterUID': actual, 'qualificationScope': scope}
    if h.private_path(path, missing=True) is None:
        h.write_once(path, expected | {'stage': 'started'})
    else:
        saved = h.phase_json(path)
        h.require(saved == expected | {'stage': 'started'}, 'Initial discovery is terminal or changed')
    h.require(not record.get('cleanupStarted') and not record.get('namespaceAbsent'),
        'Completed or failed initial discovery cannot grant credentials again')


def bind_discovered_target(io, directory, intent):
    binding = target_from_draft(directory)
    scope, evidence = scoped_evidence(directory, intent)
    live = live_cluster_uid(io)
    h.require(binding['targetClusterUID'] == live
        and (scope['kind'] != 'mechanism-rehearsal' or live == evidence['observedClusterUID']),
        'Native private target differs from the discovery cluster')
    discovery = h.phase_json(Path(directory) / 'initial-discovery.json')
    h.require(discovery['targetClusterUID'] == live and discovery['qualificationScope'] == scope
        and discovery['intentSHA256'] == binding['intentSHA256']
        and discovery['stage'] == 'started', 'Initial discovery binding changed')
    h.write_once(Path(directory) / 'target-cluster.json', binding)
    discovery['stage'] = 'bound'
    h.atomic_private(Path(directory) / 'initial-discovery.json', discovery)


def authorize(directory, *, window_seconds=7200):
    directory = Path(directory)
    h.require(type(window_seconds) is int and 3600 <= window_seconds <= 14400, 'Unsupported production maintenance window')
    with h.writer_locks():
        if h.private_path(writer_guard.RETIREMENT_FENCE, missing=True) is not None:
            require_execution(directory)
            return {'stage': 'execution-authorized', 'changed': False, 'ready': False}
        writer_guard.check_fence()
        h.require(h.phase_head(directory) is None, 'Execution must begin before baseline commit')
        manifest = h.verify_bundle(directory / 'runtime', directory / 'bundle.json')
        intent = h.phase_json(h.phase_file(directory, 'baseline', 'intent'))
        h.qualification_files(directory, intent)
        h.require(intent['prepared']['bundleSHA256'] == h.digest(h.canonical(manifest)), 'Execution bundle differs')
        io = NativeIO(manifest['operationId'])
        target = scope_gate(io, directory, intent)
        for name, expected in intent['applicationBindings'].items():
            current = idle(io.request(transport.APPS + name))
            h.require(transport.identity(current) == transport.identity(expected) and current['spec'] == expected['spec'],
                'Application changed before execution authorization')
        h.require(set(intent['applicationBindings']) == set(transport.CHILDREN), 'Execution requires exactly six Applications')
        original_baseline_export(directory)
        from playbooks.observability.files.handoff_backend import NativeConfigPending
        try:
            production_preflight(io, directory, intent)
        except NativeConfigPending as error:
            return pending_result(error)
        live_sources(io, directory, 'baseline')
        for name, expected in intent['applicationBindings'].items():
            current = idle(io.request(transport.APPS + name))
            h.require(transport.identity(current) == transport.identity(expected) and current['spec'] == expected['spec'],
                'Application changed during execution preflight')
        h.require(scope_gate(io, directory, intent) == target, 'Target cluster changed during execution preflight')
        authorization = {'version': VERSION, 'operationId': manifest['operationId'],
            'bundleSHA256': h.digest(h.canonical(manifest)), 'sourceSHA256': h.digest(h.read_private(directory / 'source.json')),
            'baselineSHA256': h.digest(h.read_private(directory / 'baseline.json')),
            'qualificationsSHA256': h.digest(h.canonical(intent['qualifications'])),
            **target,
            'expires': int(time.time()) + window_seconds}
        journal = {'authorization': authorization, 'steps': {}, 'phases': {}}
        # A crash here leaves a visible non-authorizing journal; no workload changed.
        h.write_once(directory / 'execution.json', journal)
        h.write_once(writer_guard.RETIREMENT_FENCE, authorization)
        return {'stage': 'execution-authorized', 'changed': True, 'ready': False}


def phase_authority(directory, phase):
    journal = require_execution(directory)
    intent = h.phase_json(h.phase_file(directory, phase, 'intent'))
    h.qualification_files(directory, intent)
    h.require(journal['authorization']['qualificationsSHA256'] == h.digest(h.canonical(intent['qualifications'])),
        'Execution qualifications changed')
    if phase != 'baseline':
        previous = h.PHASES[h.PHASES.index(phase) - 1]
        h.require(journal['phases'].get(previous, {}).get('stage') == 'backend-complete',
            'Previous workload phase is not complete')
    live_sources(NativeIO(intent['operationId']), directory, phase)
    return journal, intent


def live_sources(io, directory, phase):
    value = h.phase_json(h.phase_file(directory, phase, 'input'))
    source = value['source']
    identity = h.observe_identity()
    intent = h.phase_json(h.phase_file(directory, phase, 'intent'))
    h.require({key: obj['metadata']['uid'] for key, obj in identity['objects'].items()} == intent['prepared']['identityUIDs'],
        'Execution native identity owners changed')
    for path, expected in [(transport.SETS + transport.PARENT, source['set']),
            (transport.APPS + transport.PARENT, source['parent']),
            *(('/api/v1/namespaces/argocd/pods/' + obj['metadata']['name'], obj) for obj in source['pods'].values())]:
        current = io.request(path)
        h.require(current is not None and transport.identity(current) == transport.identity(expected)
            and current['spec'] == expected['spec'], 'Execution native source identity or intent changed')


def advance_allowed(directory, phase):
    """Called before new source phases are staged while an execution fence exists."""
    journal = check_continuation(directory)
    if journal is not None and phase != 'baseline':
        previous = h.PHASES[h.PHASES.index(phase) - 1]
        h.require(journal['phases'].get(previous, {}).get('stage') == 'backend-complete',
            'Previous workload phase is not complete')


def persist(directory, journal):
    h.atomic_private(Path(directory) / 'execution.json', journal)


def owned_metadata(obj):
    metadata = obj.get('metadata', {})
    return {'annotations': copy.deepcopy(metadata.get('annotations', {})),
        'labels': {key: value for key, value in metadata.get('labels', {}).items()
            if key.startswith(('cloudlab.io/', 'argocd.argoproj.io/')) or key == 'app.kubernetes.io/instance'},
        'ownerReferences': copy.deepcopy(metadata.get('ownerReferences', [])),
        'finalizers': copy.deepcopy(metadata.get('finalizers', [])), 'deletionTimestamp': metadata.get('deletionTimestamp')}


def mutation(directory, journal, key, io, path, before, after, patch):
    """A persisted CAS binds both metadata and spec; unknown intent never refreshes."""
    expected = {'path': path, 'uid': before['metadata']['uid'],
        'beforeSpecSHA256': h.digest(h.canonical(before['spec'])), 'afterSpecSHA256': h.digest(h.canonical(after['spec'])),
        'beforeMetadata': owned_metadata(before), 'afterMetadata': owned_metadata(after),
        'annotations': copy.deepcopy(after['metadata'].get('annotations', {}))}
    row = journal['steps'].get(key)
    current = io.request(path)
    h.require(current is not None and current['metadata']['uid'] == expected['uid'], 'Mutation target UID changed')
    idle(current)
    if row is None:
        h.require(current['spec'] == before['spec'] and owned_metadata(current) == expected['beforeMetadata']
            and isinstance(current['metadata'].get('resourceVersion'), str) and current['metadata']['resourceVersion'],
            'New mutation before-state changed')
        expected['beforeResourceVersion'] = current['metadata']['resourceVersion']
        row = {'intent': expected, 'acknowledged': False, 'patchRequested': False}
        journal['steps'][key] = row
        persist(directory, journal)
    else:
        expected['beforeResourceVersion'] = row['intent'].get('beforeResourceVersion')
        h.require(row['intent'] == expected and isinstance(expected['beforeResourceVersion'], str)
            and expected['beforeResourceVersion'], 'Mutation intent changed during resume')
    matches_before = current['spec'] == before['spec'] and owned_metadata(current) == expected['beforeMetadata']
    matches_after = current['spec'] == after['spec'] and owned_metadata(current) == expected['afterMetadata']
    no_op = before['spec'] == after['spec'] and expected['beforeMetadata'] == expected['afterMetadata']
    if row['acknowledged']:
        h.require(matches_after, 'Acknowledged Application metadata or specification drifted')
        return current
    if no_op:
        h.require(matches_before and row.get('patchRequested') is False, 'No-op intent does not match observed state')
        row['outcome'] = 'no-op'
    elif matches_after:
        h.require(row.get('patchRequested') is True, 'Unrequested mutation after-state cannot be adopted')
        row['outcome'] = 'observed-after'
    else:
        h.require(matches_before and current['metadata']['resourceVersion'] == expected['beforeResourceVersion'],
            'Mutation precondition changed')
        tests = [{'op': 'test', 'path': '/metadata/uid', 'value': expected['uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
            {'op': 'test', 'path': '/spec', 'value': before['spec']}]
        row['patchRequested'] = True
        persist(directory, journal)
        current = io.request(path, 'PATCH', tests + patch, 'application/json-patch+json')
        h.require(current['metadata']['uid'] == expected['uid'] and current['spec'] == after['spec']
            and owned_metadata(current) == expected['afterMetadata'],
            'Mutation acknowledgement differs')
        idle(current)
        row['outcome'] = 'patch-acknowledged'
    row['acknowledged'] = True
    row['resultSHA256'] = h.digest(h.canonical(current))
    persist(directory, journal)
    return current


def wait_absent(io, paths, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(io.request(path) is None for path in paths): return
        time.sleep(2)
    raise RuntimeError('Owned cleanup did not complete; namespace retained')


def namespace_inventory(io):
    raw = io.command(['api-resources', '--namespaced=true', '--verbs=list', '-o', 'name'], limit=65536)
    names = raw.decode().splitlines()
    h.require(names and len(names) <= 512 and len(set(names)) == len(names)
        and all(re.fullmatch('[a-z][a-z0-9]*(?:[.][a-z0-9-]+)*', name) for name in names),
        'Complete native namespace discovery is unavailable')
    objects = []
    native = {'serviceaccounts': ('/api/v1', 'v1', 'ServiceAccount'),
        'configmaps': ('/api/v1', 'v1', 'ConfigMap'), 'events': ('/api/v1', 'v1', 'Event'),
        'events.events.k8s.io': ('/apis/events.k8s.io/v1', 'events.k8s.io/v1', 'Event')}
    for name in names:
        descriptor = native.get(name)
        raw = io.command(['get', '--raw', descriptor[0] + '/namespaces/' + io.namespace + '/' + name.split('.')[0]]) if descriptor else \
            io.command(['get', name, '-n', io.namespace, '--ignore-not-found', '--show-managed-fields=true', '-o', 'json'])
        value = h.strict_json(raw, h.PRIVATE_LIMIT)
        h.require(isinstance(value, dict) and isinstance(value.get('items'), list)
            and len(value['items']) <= 128 and not value.get('metadata', {}).get('continue'),
            'Namespace discovery is incomplete')
        if descriptor is None:
            h.require(not value['items'], 'Foreign API group or kind remains in the transport namespace')
            continue
        h.require(value.get('apiVersion') == descriptor[1] and value.get('kind') == descriptor[2] + 'List',
            'Foreign API group or kind remains in the transport namespace')
        for obj in value['items']:
            h.require(isinstance(obj, dict), 'Invalid native namespace inventory item')
            item = dict(obj)
            # Typed Kubernetes lists may omit item TypeMeta. Only the verified
            # native collection supplies absent keys; explicit values must agree.
            if 'apiVersion' not in item: item['apiVersion'] = descriptor[1]
            if 'kind' not in item: item['kind'] = descriptor[2]
            h.require(item['apiVersion'] == descriptor[1] and item['kind'] == descriptor[2],
                'Foreign API group or kind remains in the transport namespace')
            objects.append(item)
    h.require(len(objects) <= 256, 'Namespace inventory exceeds accepted bound')
    return objects


def finish_transport(directory, path, io, record):
    """Revoke first, then remove only the recorded realm after complete discovery."""
    save = lambda: h.atomic_private(path, record)
    pending_unsuspend = record.get('unsuspendIntent')
    if pending_unsuspend and record['objects'].get('job'):
        job = io.request(record['objects']['job']['path'])
        h.require(job is not None and transport.identity(job) == record['objects']['job']['identity']
            and transport.fingerprint(job) in (pending_unsuspend['before'], pending_unsuspend['after']),
            'Ambiguous collector Job transition retained')
        record['objects']['job']['fingerprint'] = transport.fingerprint(job)
        record['unsuspended'] = transport.fingerprint(job) == pending_unsuspend['after']
        record.pop('unsuspendIntent'); save()
    if not record.get('cleanupStarted') and record['objects'].get('job'):
        rows = io.request('/api/v1/namespaces/' + io.namespace + '/pods?labelSelector=job-name=' + transport.JOB)['items']
        h.require(len(rows) <= 1, 'Transport cleanup Pod discovery is ambiguous')
        observed = []
        for pod in rows:
            transport.identity(pod)
            h.require(pod.get('metadata', {}).get('ownerReferences') == [{'apiVersion': 'batch/v1', 'kind': 'Job',
                'name': transport.JOB, 'uid': record['objects']['job']['identity']['uid'], 'controller': True,
                'blockOwnerDeletion': True}], 'Foreign cleanup Pod retained')
            observed.append(pod['metadata']['uid'])
        record['cleanupPodUIDs'] = observed; save()
    transport.cleanup(io.request, record, save)
    h.require(not record.get('pending'), 'Unacknowledged collector resource creation retained for exact recovery')
    targets = [record['objects'][key]['path'] for key in ('binding', 'role', 'job') if key in record['objects']]
    wait_absent(io, targets)
    ns = record['objects'].get('namespace')
    h.require(ns is not None and ns['path'] == '/api/v1/namespaces/' + io.namespace,
        'Transport namespace custody is missing')
    current = io.request(ns['path'])
    if current is None:
        record['namespaceAbsent'] = True; save(); return
    h.require(transport.identity(current) == ns['identity'] and transport.fingerprint(current) == ns['fingerprint'],
        'Transport namespace identity changed')
    labels = current['metadata'].get('labels', {})
    h.require(labels.get('cloudlab.io/owner') == transport.OWNER and labels.get(transport.LABEL) == io.operation
        and labels.get('pod-security.kubernetes.io/enforce') == 'restricted'
        and labels.get('pod-security.kubernetes.io/enforce-version') == 'v1.36'
        and labels.get('istio-injection') == 'disabled'
        and labels.get('istio.io/dataplane-mode') != 'ambient' and 'cloudlab.io/service-secrets' not in labels,
        'Transport namespace authority or enrollment changed')
    # Job GC must remove its Pod, immutable assets and account before namespace deletion.
    owned_paths = [record['objects'][key]['path'] for key in ('assets', 'account') if key in record['objects']]
    wait_absent(io, owned_paths)
    network = record['objects'].get('network')
    if network:
        actual = io.request(network['path'])
        if actual is not None:
            h.require(transport.identity(actual) == network['identity']
                and transport.fingerprint(actual) == network['fingerprint']
                and actual['metadata'].get('labels', {}).get('cloudlab.io/owner') == transport.OWNER
                and actual['metadata']['labels'].get(transport.LABEL) == io.operation
                and not actual['metadata'].get('finalizers'), 'Foreign transport network policy retained')
            record['networkDeletion'] = {key: actual['metadata'][key] for key in ('uid', 'resourceVersion')}; save()
            io.request(network['path'], 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                'preconditions': record['networkDeletion'], 'propagationPolicy': 'Foreground'})
            wait_absent(io, [network['path']])
    known_uids = {entry['identity']['uid'] for entry in record['objects'].values()}
    known_uids.update(record.get('cleanupPodUIDs', []))
    if record.get('collected'): known_uids.add(record['collected']['podUID'])
    roots = io.request('/api/v1/namespaces/argocd/configmaps/kube-root-ca.crt')
    h.require(roots is not None and (roots.get('apiVersion'), roots.get('kind')) == ('v1', 'ConfigMap')
        and roots.get('metadata', {}).get('namespace') == 'argocd'
        and roots['metadata'].get('name') == 'kube-root-ca.crt'
        and set(roots.get('data', {})) == {'ca.crt'}, 'Cluster trust root unavailable')
    inventory = namespace_inventory(io)
    housekeeping = []
    for obj in inventory:
        metadata = obj.get('metadata', {})
        managers = {row.get('manager') for row in metadata.get('managedFields', [])}
        h.require(metadata.get('namespace') == io.namespace and metadata.get('uid')
            and not metadata.get('ownerReferences') and not metadata.get('finalizers'),
            'Unknown transport object retained')
        native_type = (obj.get('apiVersion'), obj.get('kind'))
        if native_type == ('v1', 'ServiceAccount') and metadata.get('name') == 'default':
            h.require(managers and managers <= {'kube-controller-manager', 'k3s'}
                and not obj.get('secrets') and not obj.get('imagePullSecrets')
                and not metadata.get('labels') and not metadata.get('annotations')
                and obj.get('automountServiceAccountToken') is None, 'Foreign default account retained')
        elif native_type == ('v1', 'ConfigMap') and metadata.get('name') == 'kube-root-ca.crt':
            h.require(managers and managers <= {'kube-controller-manager', 'k3s'}
                and obj.get('data') == roots['data'] and not obj.get('binaryData')
                and not metadata.get('labels') and set(metadata.get('annotations', {})) <= {'kubernetes.io/description'},
                'Foreign namespace trust object retained')
        elif native_type in (('v1', 'Event'), ('events.k8s.io/v1', 'Event')):
            reference = obj.get('involvedObject' if native_type[0] == 'v1' else 'regarding', {})
            h.require(reference.get('uid') in known_uids and reference.get('namespace', io.namespace) == io.namespace,
                'Foreign namespace event retained')
        else:
            raise RuntimeError('Unknown transport namespace object retained')
        housekeeping.append({'apiVersion': obj['apiVersion'], 'kind': obj['kind'], 'name': metadata['name'], 'uid': metadata['uid'],
            'sha256': h.digest(h.canonical(obj))})
    record['namespaceDeletion'] = {'uid': current['metadata']['uid'],
        'resourceVersion': current['metadata']['resourceVersion'], 'housekeeping': housekeeping, 'accepted': False}
    save()
    io.request(ns['path'], 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions',
        'preconditions': {key: current['metadata'][key] for key in ('uid', 'resourceVersion')}, 'propagationPolicy': 'Foreground'})
    record['namespaceDeletion']['accepted'] = True; save()
    wait_absent(io, [ns['path']])
    record['namespaceAbsent'] = True; save()


def collect_phase(directory, phase, *, downstream=False):
    with h.writer_locks():
        if h.private_path(writer_guard.RETIREMENT_FENCE, missing=True) is None:
            writer_guard.check_fence()
            h.require(phase == 'baseline' and not downstream and h.phase_head(directory) is None,
                'Only original read-only baseline discovery is allowed before execution authorization')
            intent = h.phase_json(h.phase_file(directory, phase, 'intent'))
            h.qualification_files(directory, intent)
            journal = None
        else:
            journal, intent = phase_authority(directory, phase)
        io = NativeIO(intent['operationId'])
        first_read = phase == 'baseline' and not downstream and h.private_path(Path(directory) / 'target-cluster.json', missing=True) is None
        if downstream:
            h.require(journal['phases'].get(phase, {}).get('stage') == 'applications-held',
                'Downstream discovery requires all six exact Application holds')
            # The same namespace cannot carry two concurrent credential lifecycles.
            parent = h.phase_json(h.phase_file(directory, phase, 'transport'))
            h.require(parent.get('namespaceAbsent') is True and io.request('/api/v1/namespaces/' + io.namespace) is None,
                'Previous collector realm remains active')
            observed = h.phase_observation(directory, phase)['native']
            h.downstream_input(directory, phase, observed)
        value = h.phase_json(h.phase_file(directory, phase, 'downstream-input' if downstream else 'input'))
        path = h.phase_file(directory, phase, 'downstream-transport' if downstream else 'transport')
        record = {} if h.private_path(path, missing=True) is None else h.phase_json(path)
        if first_read and record.get('collected') and record.get('sourcePayloadSHA256'):
            # A crash after the sealed output needs no second credential grant.
            discovery = h.phase_json(Path(directory) / 'initial-discovery.json')
            h.require(discovery['targetClusterUID'] == live_cluster_uid(io), 'Discovery recovery moved to a different cluster')
            try:
                bind_discovered_target(io, directory, intent)
            except BaseException:
                discovery['stage'] = 'failed'
                h.atomic_private(Path(directory) / 'initial-discovery.json', discovery)
                raise
            finally:
                finish_transport(directory, path, io, record)
            scope_gate(io, directory, intent)
            return {'stage': 'phase-draft', 'phase': phase, 'ready': False}
        if first_read:
            initial_discovery(io, directory, intent, record)
        else:
            scope_gate(io, directory, intent)
        if record.get('namespaceAbsent'):
            h.require(record.get('collected') and record.get('sourcePayloadSHA256'), 'Cleaned collector has no successful custody')
            return {'stage': 'phase-resources-collected' if downstream else 'phase-draft', 'phase': phase, 'ready': False}
        save = lambda: h.atomic_private(path, record)
        # Never silently recreate a partially cleaned transport scope.
        if record.get('cleanupStarted'):
            finish_transport(directory, path, io, record)
            h.require(record.get('collected') and record.get('sourcePayloadSHA256'),
                'Interrupted collection failed; recovered scope cannot fabricate source custody')
            return {'stage': 'phase-resources-collected' if downstream else 'phase-draft', 'phase': phase, 'ready': False}
        try:
            transport.prepare(io.request, record, save, value)
            pod, status = io.collector(value, record)
            result = h._collect_phase_locked(directory, phase, io.request, io.collect_bytes, pod, status, downstream=downstream)
            if first_read:
                bind_discovered_target(io, directory, intent)
        except BaseException:
            if first_read:
                discovery = h.phase_json(Path(directory) / 'initial-discovery.json')
                discovery['stage'] = 'failed'
                h.atomic_private(Path(directory) / 'initial-discovery.json', discovery)
            raise
        finally:
            # The source collector may have durably advanced before raising.
            if h.private_path(path, missing=True) is not None:
                current = h.phase_json(path)
                h.require(current.get('context') == record.get('context'), 'Collector journal changed during execution')
                record.clear(); record.update(current)
            if record.get('objects', {}).get('namespace'):
                finish_transport(directory, path, io, record)
        return result


def original_baseline_export(directory):
    """Authenticate original three native inventories without requiring later source phases."""
    intent = h.phase_json(h.phase_file(directory, 'baseline', 'intent'))
    draft = h.phase_json(h.phase_file(directory, 'baseline', 'draft'))
    payload = h.phase_json(h.phase_file(directory, 'baseline', 'draft-payload'))
    collector = h.phase_json(h.phase_file(directory, 'baseline', 'transport'))
    transport_input = h.phase_json(h.phase_file(directory, 'baseline', 'input'))
    bundle = h.verify_bundle(Path(directory) / 'runtime', Path(directory) / 'bundle.json')
    h.require(draft['intentSHA256'] == h.digest(h.canonical(intent))
        and draft['payloadSHA256'] == h.digest(h.canonical(payload))
        and draft['custody'] == h.collection_binding(collector)
        and collector.get('namespaceAbsent') is True
        and isinstance(payload.get('baseline'), dict)
        and set(payload['baseline']) == set(transport.DOWNSTREAM), 'Original native inventory custody is unavailable')
    h.require(intent['phase'] == 'baseline' and intent['previousPhaseSHA256'] is None
        and h.phase_head(directory) is None and transport.initial_baseline(transport_input)
        and intent['prepared']['bundleSHA256'] == h.digest(h.canonical(bundle))
        and transport_input['codeSHA256'] == bundle['moduleDigests']['playbooks/observability/files/native_transport.py']
        and collector['context'] == {'operation': bundle['operationId'], 'codeSHA256': transport_input['codeSHA256'],
            'inputSHA256': h.digest(h.canonical(transport_input))}, 'Original native source or code binding changed')
    actual = {'parent': [payload['phaseApplications'][name] for name in payload['applicationOrder']],
        'baseline': payload['baseline']}
    h.require(h.digest(h.canonical(actual)) == draft['custody']['objectsSHA256'], 'Original native inventory changed')
    return {'intent': intent, 'draft': draft, 'draftPayload': payload, 'collector': collector,
        'transportInput': transport_input, 'bundle': bundle, 'previous': None}


def classification_phase_export(directory, phase):
    """Preserve the source export schema while binding current and predecessor records."""
    head = h.phase_head(directory)
    h.require(head is not None and head['record']['phase'] == phase, 'Native classification has no current validated source phase')
    previous = None
    if phase != 'baseline':
        predecessor = h.PHASES[h.PHASES.index(phase) - 1]
        previous = {'record': h.phase_json(h.phase_file(directory, predecessor, 'record')),
            'intent': h.phase_json(h.phase_file(directory, predecessor, 'intent'))}
        h.require(head['record']['previousPhaseSHA256'] == h.digest(h.canonical(previous['record'])),
            'Native classification predecessor differs')
    return {'phase': h.phase_export(directory, phase), 'record': head['record'], 'previous': previous,
        'bundle': h.verify_bundle(Path(directory) / 'runtime', Path(directory) / 'bundle.json')}


def native_classification(directory, phase, *, expected_sha256=None):
    """Export and stage only the protected pending nonce; no caller path or receipt."""
    from playbooks.observability.files import handoff_backend
    directory = Path(directory)
    with h.writer_locks():
        pending = h.phase_json(directory / 'backend.json').get('pendingClassification')
        h.require(isinstance(pending, dict) and set(pending) == {'purpose', 'challenge'}, 'No native classification is pending')
        challenge = pending['challenge']
        h.require(challenge.get('phase') == phase and re.fullmatch('[a-f0-9]{32}', challenge.get('nonce', '')),
            'Native classification phase or nonce changed')
        if pending['purpose'] == 'original':
            h.require(phase == 'baseline', 'Original classification requires baseline')
            writer_guard.check_fence()
        else:
            require_execution(directory)
        path = directory / 'private' / ('native-' + challenge['nonce'] + '.proposal.json')
        h.staging_targets([path])
        if expected_sha256 is not None:
            return handoff_backend.stage_native_classification(directory, path, expected_sha256)
        return handoff_backend.native_config_export(directory, lambda purpose, selected:
            original_baseline_export(directory) if purpose == 'original' else classification_phase_export(directory, selected))


def sync_resources(io, directory, phase, journal, application, resources, *, prune=False, deadline=None):
    end = time.monotonic() + 600
    if deadline is not None:
        h.require(type(deadline) in (int, float) and math.isfinite(deadline) and deadline > time.monotonic(),
            'Approved Sync deadline expired')
        end = min(end, deadline)
    with io.bounded(end):
        return _sync_resources(io, directory, phase, journal, application, resources, prune=prune, deadline=end)


def _sync_resources(io, directory, phase, journal, application, resources, *, prune, deadline):
    """Only authenticated native inventory members may enter a bounded Argo Sync."""
    h.require(application in transport.DOWNSTREAM and isinstance(resources, list) and resources
        and type(prune) is bool, 'Unsupported bounded Sync target')
    intent = h.phase_json(h.phase_file(directory, phase, 'intent'))
    packet = h.phase_json(h.phase_file(directory, phase, 'resources'))
    record = h.phase_json(h.phase_file(directory, phase, 'record'))
    h.require(record['intentSHA256'] == h.digest(h.canonical(intent))
        and record['payloadSHA256'] == h.digest(h.canonical(packet)), 'Sync source validation changed')
    inventory = packet['objects'][application]
    indexed = {(obj['apiVersion'], obj['kind'], obj['metadata'].get('namespace', ''), obj['metadata']['name']): obj
        for obj in inventory}
    selectors = []
    deny_key = ('security.istio.io/v1', 'AuthorizationPolicy', 'cloudlab-observability',
        'cloudlab-observability-handoff-write-deny')
    if prune:
        h.require(phase == 'persistent-normal' and application == 'cloudlab-observability' and len(resources) == 1
            and deny_key not in indexed, 'Pruning is restricted to the removed handoff DENY')
        maintenance = h.phase_json(h.phase_file(directory, 'maintenance', 'resources'))['objects'][application]
        accepted = [obj for obj in maintenance if (obj['apiVersion'], obj['kind'],
            obj['metadata'].get('namespace', ''), obj['metadata']['name']) == deny_key]
        h.require(accepted == resources and journal['steps'].get('owned-deny'), 'Owned DENY removal lacks original authority')
        old = journal['steps']['owned-deny']
        actual = io.request(document_path(resources[0]))
        h.require(actual is None or (transport.identity(actual) == old['identity'] and actual.get('spec') == old['spec']
            and actual['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') == old['tracking']),
            'Owned DENY identity or source changed before prune')
    for obj in resources:
        key = (obj['apiVersion'], obj['kind'], obj['metadata'].get('namespace', ''), obj['metadata']['name'])
        h.require((prune and key == deny_key) or (key in indexed and indexed[key] == obj),
            'Sync resource is outside the exact accepted inventory')
        selector = {'kind': key[1], 'name': key[3]}
        if '/' in key[0]: selector['group'] = key[0].split('/')[0]
        if key[2]: selector['namespace'] = key[2]
        selectors.append(selector)
    h.require(len(selectors) == len({h.digest(h.canonical(row)) for row in selectors}), 'Duplicate Sync target')
    payload = h.phase_json(h.phase_file(directory, phase, 'draft-payload'))
    desired = payload['phaseApplications'][application]
    current = io.request(transport.APPS + application)
    h.require(current is not None and not current.get('metadata', {}).get('deletionTimestamp'), 'Sync Application is unavailable')
    h.require(current['metadata']['uid'] == intent['applicationBindings'][application]['metadata']['uid']
        and current['spec'] == desired['spec'] and current['spec']['syncPolicy']['automated'] == HOLD
        and current['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') == 'false',
        'Sync Application lost its exact paused source')
    revision = current['spec']['source']['targetRevision']
    operation = {'initiatedBy': {'username': 'cloudlab-observability-handoff-' + intent['operationId']}, 'retry': {},
        'sync': {'revision': revision, 'syncStrategy': {'apply': {}},
            'syncOptions': current['spec']['syncPolicy']['syncOptions'], 'resources': selectors}}
    if prune: operation['sync']['prune'] = True
    key = phase + ':sync:' + application + ':' + h.digest(h.canonical(selectors))
    expected = {'operation': operation, 'uid': current['metadata']['uid'], 'specSHA256': h.digest(h.canonical(current['spec']))}
    row = journal['steps'].get(key)
    if row is None:
        idle(current)
        row = {'intent': expected, 'requested': False, 'complete': False}
        journal['steps'][key] = row; persist(directory, journal)
    h.require(row['intent'] == expected, 'Sync intent changed')
    last = current.get('status', {}).get('operationState', {})
    if row['complete']:
        h.require(last.get('phase') == 'Succeeded' and last.get('operation') == operation,
            'Completed native Sync evidence changed')
        return current
    if not row['requested']:
        # Lost POST/PATCH acknowledgement must be resolved from this exact native operation.
        if last.get('operation') != operation:
            if current.get('operation') is not None:
                h.require(current['operation'] == operation, 'Foreign operation replaced the requested Sync')
                row['requested'] = True; persist(directory, journal)
            else:
                idle(current)
        if last.get('operation') != operation and not row['requested']:
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': current['metadata']['uid']},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                {'op': 'test', 'path': '/spec', 'value': current['spec']}, {'op': 'add', 'path': '/operation', 'value': operation}]
            result = io.request(transport.APPS + application, 'PATCH', patch, 'application/json-patch+json')
            h.require(result['metadata']['uid'] == expected['uid'] and result.get('operation') == operation,
                'Sync request acknowledgement differs')
        row['requested'] = True; persist(directory, journal)
    while time.monotonic() < deadline:
        now = io.request(transport.APPS + application)
        h.require(now is not None and now['metadata']['uid'] == expected['uid'] and now['spec'] == desired['spec'],
            'Sync Application identity or source changed')
        actual = now.get('status', {}).get('operationState', {})
        if actual.get('operation') == operation:
            h.require(actual.get('phase') not in ('Failed', 'Error', 'Terminating'), 'Bounded native Sync failed')
            if actual.get('phase') == 'Succeeded' and not now.get('operation'):
                if prune:
                    h.require(io.request(document_path(resources[0])) is None, 'Owned DENY remains after bounded prune')
                elif deny_key in [(obj['apiVersion'], obj['kind'], obj['metadata'].get('namespace', ''), obj['metadata']['name'])
                        for obj in resources]:
                    wanted = next(obj for obj in resources if obj['kind'] == 'AuthorizationPolicy')
                    observed = io.request(document_path(wanted))
                    tracking = 'cloudlab-observability:security.istio.io/AuthorizationPolicy:cloudlab-observability/' + deny_key[3]
                    h.require(observed is not None and observed.get('spec') == wanted['spec']
                        and observed['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') == tracking,
                        'Argo-owned DENY acknowledgement differs')
                    binding = {'identity': transport.identity(observed), 'spec': observed['spec'], 'tracking': tracking}
                    h.require(journal['steps'].get('owned-deny', binding) == binding, 'Owned DENY binding changed')
                    journal['steps']['owned-deny'] = binding
                row['complete'] = True; row['resultSHA256'] = h.digest(h.canonical(actual))
                persist(directory, journal); return now
        elif now.get('operation') is not None:
            h.require(now['operation'] == operation, 'Foreign operation replaced the bounded Sync')
        time.sleep(max(0, min(2, deadline - time.monotonic())))
    raise RuntimeError('Bounded native Sync timed out; fence and evidence retained')


def apply_applications(directory, phase):
    with h.writer_locks():
        journal, intent = phase_authority(directory, phase)
        before_journal = h.canonical(journal)
        payload = h.phase_json(h.phase_file(directory, phase, 'draft-payload'))
        draft = h.phase_json(h.phase_file(directory, phase, 'draft'))
        h.require(draft['intentSHA256'] == h.digest(h.canonical(intent))
            and draft['payloadSHA256'] == h.digest(h.canonical(payload)), 'Application draft custody changed')
        collector = h.phase_json(h.phase_file(directory, phase, 'transport'))
        h.require(draft['custody'] == h.collection_binding(collector), 'Application draft has no native collector custody')
        applications = payload['phaseApplications']
        h.require(set(applications) == set(intent['applicationBindings']) == set(transport.CHILDREN), 'Application closure differs')
        io = NativeIO(intent['operationId'])
        current = {name: idle(io.request(transport.APPS + name)) for name in transport.CHILDREN}
        held = {}
        staged = {}
        for name, old in intent['applicationBindings'].items():
            held[name] = copy.deepcopy(old)
            held[name]['spec']['syncPolicy']['automated'] = copy.deepcopy(HOLD)
            held[name]['metadata'].setdefault('annotations', {})['argocd.argoproj.io/skip-reconcile'] = 'true'
            staged[name] = copy.deepcopy(applications[name])
            annotations = {key: value for key, value in held[name]['metadata'].get('annotations', {}).items()
                if not key.startswith(('cloudlab.io/', 'argocd.argoproj.io/'))}
            annotations.update(staged[name]['metadata'].get('annotations', {}))
            staged[name]['metadata']['annotations'] = annotations
        # Validate the entire closure before the first hold or source mutation.
        for name in transport.CHILDREN:
            expected, desired, now = intent['applicationBindings'][name], applications[name], current[name]
            h.require(transport.identity(now) == transport.identity(expected)
                and desired['spec']['syncPolicy']['automated'] == HOLD
                and desired['metadata']['name'] == name and desired['metadata']['namespace'] == 'argocd',
                'Application source escaped the fixed held closure')
            source_row = journal['steps'].get(phase + ':app:' + name)
            hold_row = journal['steps'].get(phase + ':hold:' + name)
            if source_row:
                allowed = [staged[name]] + ([] if source_row['acknowledged'] else [held[name]])
            elif hold_row:
                allowed = [held[name]] + ([] if hold_row['acknowledged'] else [expected])
            else:
                allowed = [expected]
            h.require(any(now['spec'] == candidate['spec'] and owned_metadata(now) == owned_metadata(candidate)
                for candidate in allowed), 'Application metadata or specification changed before holds')
        # Stop every child before changing any source. A paused parent does not hold children.
        for name in transport.CHILDREN:
            if phase + ':app:' + name in journal['steps']:
                continue
            after = held[name]
            before = current[name] if phase + ':hold:' + name not in journal['steps'] else intent['applicationBindings'][name]
            mutation(directory, journal, phase + ':hold:' + name, io, transport.APPS + name,
                before, after,
                [{'op': 'add', 'path': '/metadata/annotations', 'value': after['metadata']['annotations']},
                 {'op': 'replace', 'path': '/spec', 'value': after['spec']}])
        for name in transport.CHILDREN:
            now = idle(io.request(transport.APPS + name))
            h.require(now['metadata']['uid'] == intent['applicationBindings'][name]['metadata']['uid']
                and (now['spec'] == held[name]['spec'] or (phase + ':app:' + name in journal['steps']
                    and now['spec'] == applications[name]['spec'])) and now['spec']['syncPolicy']['automated'] == HOLD,
                'Application hold changed before source staging')
        for name in transport.CHILDREN:
            after = staged[name]
            mutation(directory, journal, phase + ':app:' + name, io, transport.APPS + name, held[name], after,
                [{'op': 'add', 'path': '/metadata/annotations', 'value': after['metadata']['annotations']},
                 {'op': 'replace', 'path': '/spec', 'value': after['spec']}])
        for name in transport.CHILDREN:
            now = idle(io.request(transport.APPS + name))
            h.require(now['metadata']['uid'] == intent['applicationBindings'][name]['metadata']['uid']
                and now['spec'] == applications[name]['spec'] and now['spec']['syncPolicy']['automated'] == HOLD,
                'Application hold or exact source changed')
        journal['phases'].setdefault(phase, {})['stage'] = 'applications-held'
        persist(directory, journal)
        return {'stage': 'applications-held', 'phase': phase, 'changed': h.canonical(journal) != before_journal, 'ready': False}


def held_applications(io, directory, phase, intent, journal):
    payload = h.phase_json(h.phase_file(directory, phase, 'draft-payload'))
    h.require(set(payload['phaseApplications']) == set(transport.CHILDREN), 'Held Application closure differs')
    for name, desired in payload['phaseApplications'].items():
        current = io.request(transport.APPS + name)
        h.require(current is not None, 'Held Application is unavailable')
        h.require(not any(current['metadata'].get(key) for key in ('deletionTimestamp', 'ownerReferences', 'finalizers')),
            'Held Application ownership changed')
        pending = [row['intent']['operation'] for key, row in journal['steps'].items()
            if key.startswith(phase + ':sync:' + name + ':') and isinstance(row, dict)
            and row.get('intent', {}).get('uid') == current['metadata'].get('uid')
            and 'operation' in row.get('intent', {}) and not row.get('complete')]
        live_operation = current.get('operation') or (current.get('status', {}).get('operationState', {}).get('operation')
            if current.get('status', {}).get('operationState', {}).get('phase') == 'Running' else None)
        if live_operation not in pending: idle(current)
        h.require(current['metadata']['uid'] == intent['applicationBindings'][name]['metadata']['uid']
            and current['spec'] == desired['spec'] and current['spec']['syncPolicy']['automated'] == HOLD
            and current['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') ==
                ('true' if phase == 'native-paused' else 'false'), 'Application hold or accepted source changed')


def execute_phase(directory, phase):
    with h.writer_locks():
        journal, intent = phase_authority(directory, phase)
        head = h.phase_head(directory)
        h.require(head is not None and head['record']['phase'] == phase
            and head['record']['intentSHA256'] == h.digest(h.canonical(intent)), 'Actual source validation must precede backend execution')
        h.require(journal['phases'].get(phase, {}).get('stage') in ('applications-held', 'backend-complete'),
            'All six Application holds must precede backend execution')
        io = NativeIO(intent['operationId'])
        held_applications(io, directory, phase, intent, journal)
        from playbooks.observability.files.handoff_backend import NativeConfigPending
        before_journal = h.canonical(journal)
        try:
            backend_phase(io, directory, phase, journal)
        except NativeConfigPending as error:
            return pending_result(error, changed=h.canonical(journal) != before_journal)
        if phase == 'native-paused':
            transfer_tracking(io, directory, phase, journal, head['record'])
        held_applications(io, directory, phase, intent, journal)
        journal['phases'][phase] = {'stage': 'backend-complete', 'recordSHA256': h.digest(h.canonical(head['record']))}
        persist(directory, journal)
        return {'stage': 'backend-complete', 'phase': phase, 'changed': h.canonical(journal) != before_journal, 'ready': False}


def transfer_tracking(io, directory, phase, journal, record):
    h.require(phase == 'native-paused' and isinstance(record.get('transferIntents'), dict),
        'Tracking transfer requires actual canonical source validation')
    original = h.phase_json(Path(directory) / 'transfer-baseline.json')
    h.require(set(record['transferIntents']) == set(original), 'Tracking transfer closure differs')
    for encoded, approved in record['transferIntents'].items():
        version, kind, namespace, name = encoded.split('|')
        h.require((version, kind) in h.TRANSFER_KINDS and namespace == 'cloudlab-observability',
            'Tracking transfer escaped supported owned resources')
        path = '/apis/' + version + '/namespaces/' + namespace + '/' + h.TRANSFER_KINDS[(version, kind)] + '/' + name
        current = io.request(path)
        old = original[encoded]
        h.require(current is not None and current['metadata']['uid'] == approved['uid'] == old['metadata']['uid']
            and current.get('spec') == old.get('spec') and not current['metadata'].get('deletionTimestamp')
            and not current['metadata'].get('annotations', {}).get('argocd.argoproj.io/installation-id'),
            'Tracking transfer backing identity or specification changed')
        key = 'tracking:' + encoded
        intent = {'path': path, 'uid': approved['uid'], 'specSHA256': h.digest(h.canonical(old.get('spec'))),
            'from': approved['fromTracking'], 'to': approved['toTracking']}
        row = journal['steps'].get(key)
        if row is None:
            h.require(current['metadata']['resourceVersion'] == approved['resourceVersion'],
                'Tracking transfer resource version changed before intent')
            row = {'intent': intent, 'acknowledged': False}
            journal['steps'][key] = row; persist(directory, journal)
        h.require(row['intent'] == intent, 'Tracking transfer intent changed')
        tracking = current['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id')
        h.require(tracking in (intent['from'], intent['to']), 'Tracking transfer current owner differs')
        if not row['acknowledged'] and tracking != intent['to']:
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': approved['uid']},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                {'op': 'test', 'path': '/spec', 'value': old['spec']},
                {'op': 'test', 'path': '/metadata/annotations/argocd.argoproj.io~1tracking-id', 'value': intent['from']},
                {'op': 'replace', 'path': '/metadata/annotations/argocd.argoproj.io~1tracking-id', 'value': intent['to']}]
            current = io.request(path, 'PATCH', patch, 'application/json-patch+json')
        h.require(current['metadata']['uid'] == approved['uid'] and current.get('spec') == old.get('spec')
            and current['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') == intent['to'],
            'Tracking transfer acknowledgement differs')
        row['acknowledged'] = True; persist(directory, journal)


def execution_evidence(directory):
    """Export actual protected results only after all five native phases complete."""
    import base64
    with h.writer_locks():
        directory = Path(directory)
        journal, intent = phase_authority(directory, 'native-paused')
        head = h.phase_head(directory)
        h.require(head is not None and head['record']['phase'] == 'native-paused'
            and set(journal['phases']) == set(h.PHASES), 'Full entrypoint execution is incomplete')
        manifest = h.verify_bundle(directory / 'runtime', directory / 'bundle.json')
        backend = h.phase_json(directory / 'backend.json')
        h.require(all(backend.get(name) is True for name in ('denied', 'checkpointWritten', 'nativeDiskValidated',
            'checkpointValidated', 'storageSyncComplete', 'restored'))
            and backend['operationId'] == intent['operationId']
            and backend['bundleSHA256'] == h.digest(h.canonical(manifest)), 'Native backend integration is incomplete')
        h.require(set(backend.get('checkpoint', {})) == {'nflog', 'silences'}
            and all(re.fullmatch('[a-f0-9]{64}', value) for value in backend['checkpoint'].values())
            and backend.get('replacementSource', {}).get('uid') != backend.get('source', {}).get('uid')
            and all(backend.get('mutations', {}).get(name, {}).get('deleted') is True
                for name in ('writer', 'validator', 'validation-config', 'probe'))
            and backend.get('mutations', {}).get('claim', {}).get('deleted') is False,
            'Native checkpoint replacement or retained cleanup is incomplete')
        io = NativeIO(intent['operationId'])
        held_applications(io, directory, 'native-paused', intent, journal)
        h.require(all(io.request(path) is None for path in ('/api/v1/namespaces/' + io.namespace,
            '/apis/rbac.authorization.k8s.io/v1/namespaces/argocd/roles/' + io.namespace,
            '/apis/rbac.authorization.k8s.io/v1/namespaces/argocd/rolebindings/' + io.namespace)),
            'Native collection credentials or namespace remain active')
        # The completed branch rechecks native storage, watch scope and restored
        # configuration; its acknowledged deleted probe cannot be recreated.
        backend_phase(io, directory, 'native-paused', journal)
        backend = h.phase_json(directory / 'backend.json')
        phases = {}
        baseline = h.phase_json(h.phase_file(directory, 'baseline', 'draft-payload'))['baseline']
        for phase in h.PHASES:
            record = h.phase_json(h.phase_file(directory, phase, 'record'))
            current_intent = h.phase_json(h.phase_file(directory, phase, 'intent'))
            draft = h.phase_json(h.phase_file(directory, phase, 'draft'))
            payload = h.phase_json(h.phase_file(directory, phase, 'draft-payload'))
            resources = h.phase_json(h.phase_file(directory, phase, 'resources'))
            parent = h.phase_json(h.phase_file(directory, phase, 'transport'))
            downstream = h.phase_json(h.phase_file(directory, phase, 'downstream-transport'))
            parent_input = h.phase_json(h.phase_file(directory, phase, 'input'))
            downstream_input = h.phase_json(h.phase_file(directory, phase, 'downstream-input'))
            h.require(record.get('ready') is False and record.get('execution') == 'not-authorized'
                and journal['phases'][phase] == {'stage': 'backend-complete', 'recordSHA256': h.digest(h.canonical(record))}
                and record['intentSHA256'] == h.digest(h.canonical(current_intent))
                and record['draftSHA256'] == h.digest(h.canonical(draft))
                and record['payloadSHA256'] == h.digest(h.canonical(resources))
                and record['baselineSHA256'] == h.digest(h.canonical(baseline))
                and draft['payloadSHA256'] == h.digest(h.canonical(payload)), 'Protected phase payload or execution changed')
            for collector, value, custody in ((parent, parent_input, draft['custody']),
                    (downstream, downstream_input, resources['custody'])):
                h.require(collector.get('namespaceAbsent') is True and collector.get('cleanupStarted') is True
                    and collector['context'] == {'operation': intent['operationId'],
                        'codeSHA256': manifest['moduleDigests']['playbooks/observability/files/native_transport.py'],
                        'inputSHA256': h.digest(h.canonical(value))}
                    and custody == h.collection_binding(collector), 'Actual phase collector custody or cleanup changed')
            parents = [payload['phaseApplications'][name] for name in payload['applicationOrder']]
            original = {'parent': parents, 'baseline': payload['baseline']} if phase == 'baseline' else parents
            transport.phase_applications(parent_input['source'], parents)
            h.require(parent['sourcePayloadSHA256'] == h.digest(h.canonical(original))
                and downstream['sourcePayloadSHA256'] == h.digest(h.canonical(resources['objects']))
                and {obj['metadata']['name']: obj for obj in resources['objects']['parent']} == payload['phaseApplications'],
                'Actual phase native objects changed')
            indexed = {}
            h.require(set(resources['objects']) == {'parent', *transport.DOWNSTREAM}, 'Actual downstream closure changed')
            for name in transport.DOWNSTREAM:
                objects = resources['objects'][name]
                transport.resource_manifests(h.canonical({'manifests': [h.canonical(obj).decode() for obj in objects]}))
                for obj in objects:
                    key = (obj['apiVersion'], obj['kind'], obj['metadata'].get('namespace', ''), obj['metadata']['name'])
                    h.require(key not in indexed, 'Actual native phase resource is duplicated')
                    indexed[key] = obj
            inventory = [{'apiVersion': key[0], 'kind': key[1], 'namespace': key[2], 'name': key[3],
                'sha256': h.digest(h.canonical(obj))} for key, obj in sorted(indexed.items())]
            h.require(inventory == record['inventory'], 'Native phase resource inventory hash changed')
            h.require(all(journal['steps'].get(phase + ':' + step + ':' + name, {}).get('acknowledged') is True
                for name in transport.CHILDREN for step in ('hold', 'app')), 'Actual six-Application phase execution is incomplete')
            phases[phase] = {'intent': current_intent, 'record': record, 'draft': draft,
                'parentCollector': parent, 'downstreamCollector': downstream}
        for encoded, approved in head['record']['transferIntents'].items():
            row = journal['steps'].get('tracking:' + encoded)
            old = h.phase_json(directory / 'transfer-baseline.json')[encoded]
            current = io.request(row['intent']['path']) if row else None
            h.require(row is not None and row.get('acknowledged') is True and current is not None
                and current['metadata']['uid'] == approved['uid'] and current.get('spec') == old.get('spec')
                and current['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') == approved['toTracking'],
                'Actual tracking transfer backing identity or specification changed')
        references = intent['qualifications']['references']
        modules = {'ansible/' + name: manifest['moduleDigests'][name] for name in h.HOST_FILES}
        modules.update({'ansible/' + name: value for name, value in manifest['runnerModuleDigests'].items()})
        return {'entrypoint': {'version': 'cloudlab-observability-entrypoint-evidence/v1',
            'codeRevision': references['handoff']['codeRevision'], 'operationId': intent['operationId'],
            'observedClusterUID': journal['authorization']['targetClusterUID'], 'bundle': manifest,
            'moduleDigests': modules, 'imagePins': {name: references[name]['imagePins'] for name in h.QUALIFICATIONS if name != 'handoff'},
            'source': base64.b64encode(h.read_private(directory / 'source.json')).decode(),
            'baseline': base64.b64encode(h.read_private(directory / 'baseline.json')).decode(),
            'execution': journal, 'backend': backend, 'phaseHead': h.phase_json(directory / 'phase-head.json')},
            'phases': phases}
