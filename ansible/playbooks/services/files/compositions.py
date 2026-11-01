"""Reviewed chart compositions share the service owners and retain exact pod authority."""
import copy
from decimal import Decimal, InvalidOperation
import json
import re


NAME = r'[a-z][a-z0-9-]{0,30}'
DIGEST = r'[a-z0-9][a-z0-9./:_-]+@sha256:[a-f0-9]{64}'
CAPABILITIES = {'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID', 'SYS_CHROOT',
                'SETPCAP', 'NET_ADMIN', 'KILL'}
DEFAULT_TOLERATIONS = [
    {'key': 'node.kubernetes.io/not-ready', 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 300},
    {'key': 'node.kubernetes.io/unreachable', 'operator': 'Exists', 'effect': 'NoExecute', 'tolerationSeconds': 300},
    {'key': 'node.kubernetes.io/memory-pressure', 'operator': 'Exists', 'effect': 'NoSchedule'},
]
POD_FIELDS = {'containers', 'initContainers', 'volumes', 'automountServiceAccountToken',
              'enableServiceLinks', 'terminationGracePeriodSeconds', 'securityContext',
              'dnsPolicy', 'dnsConfig', 'serviceAccountName', 'imagePullSecrets',
              'restartPolicy', 'schedulerName'}
CONTAINER_FIELDS = {'name', 'image', 'imagePullPolicy', 'command', 'args', 'workingDir',
                    'env', 'resources', 'securityContext', 'volumeMounts', 'ports',
                    'readinessProbe', 'livenessProbe', 'startupProbe', 'terminationMessagePath',
                    'terminationMessagePolicy'}


def _validate(approval):
    value = approval.get('composition')
    if value is None:
        return None
    required = {'chart', 'imageValues', 'images', 'workloads', 'claims', 'budget', 'backends', 'secrets'}
    if not isinstance(value, dict) or not required <= set(value) <= required | {'connections'}:
        raise ValueError('Composition requires its complete reviewed source and workload contract')
    chart = value['chart']
    if (not isinstance(chart, dict) or set(chart) != {'repository', 'revision', 'path'} or
            not re.fullmatch(r'https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[.]git', chart['repository']) or
            not re.fullmatch(r'[a-f0-9]{40}', chart['revision']) or
            not re.fullmatch(r'[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*', chart['path'])):
        raise ValueError('Composition chart requires an immutable confined Git source')
    images, paths = value['images'], value['imageValues']
    if (not isinstance(images, dict) or not 1 <= len(images) <= 12 or
            any(not re.fullmatch(NAME, name) or not re.fullmatch(DIGEST, image)
                for name, image in images.items()) or not isinstance(paths, dict) or set(paths) != set(images) or
            any(not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9]*(?:[.][a-zA-Z][a-zA-Z0-9]*){0,7}', path)
                for path in paths.values()) or len(set(paths.values())) != len(paths)):
        raise ValueError('Composition images require distinct reviewed Helm value paths and digests')
    if len(set(images.values())) != len(images):
        raise ValueError('Composition roles require distinct image digests')
    artifact = approval.get('artifact')
    if artifact and (not artifact.get('components') or not set(artifact['components']) <= set(images)):
        raise ValueError('Composition releases require their complete approved component bindings')
    if artifact and chart['repository'] != 'https://github.com/' + artifact['sourceRepository'] + '.git':
        raise ValueError('Composition chart must belong to its approved application source')
    if (not isinstance(value['workloads'], list) or not 1 <= len(value['workloads']) <= 12 or
            len({row['name'] for row in value['workloads']}) != len(value['workloads'])):
        raise ValueError('Composition requires distinct bounded workloads')
    claims = value['claims']
    if (not isinstance(claims, list) or len(claims) > 16 or
            any(set(row) != {'name', 'size'} or not re.fullmatch(NAME, row['name']) or
                not re.fullmatch(r'[1-9][0-9]?Gi', row['size']) for row in claims) or
            len({row['name'] for row in claims}) != len(claims)):
        raise ValueError('Composition claims require exact retained names and sizes')
    budget = value['budget']
    if (not isinstance(budget, dict) or set(budget) != {'requests.cpu', 'requests.memory', 'limits.cpu',
            'limits.memory', 'pods', 'persistentvolumeclaims', 'requests.storage'} or
            not all(re.fullmatch(r'[1-9][0-9]{0,4}m', budget[k]) for k in ('requests.cpu', 'limits.cpu')) or
            not all(re.fullmatch(r'[1-9][0-9]{0,5}Mi', budget[k]) for k in ('requests.memory', 'limits.memory')) or
            not re.fullmatch(r'[1-9][0-9]?Gi', budget['requests.storage']) or
            type(budget['pods']) is not int or not 1 <= budget['pods'] <= 32 or
            type(budget['persistentvolumeclaims']) is not int or not 0 <= budget['persistentvolumeclaims'] <= 16 or
            budget['persistentvolumeclaims'] < len(claims) or
            int(budget['requests.storage'][:-2]) < sum(int(row['size'][:-2]) for row in claims)):
        raise ValueError('Composition requires an explicit bounded namespace budget')
    backends = value['backends']
    if not isinstance(backends, dict) or not 0 <= len(backends) <= 8:
        raise ValueError('Composition requires bounded named route backends')
    for name, backend in backends.items():
        if (not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]', name) or not isinstance(backend, dict) or
                not {'service', 'port', 'selector'} <= set(backend) <= {'service', 'port', 'selector', 'readiness'} or
                not re.fullmatch(NAME, backend['service']) or type(backend['port']) is not int or
                not 1 <= backend['port'] <= 65535 or not isinstance(backend['selector'], dict) or
                not 1 <= len(backend['selector']) <= 8 or any(not re.fullmatch(r'[a-zA-Z0-9./_-]{1,100}', key) or
                not re.fullmatch(r'[a-zA-Z0-9._-]{1,63}', label) for key, label in backend['selector'].items())):
            raise ValueError('Composition routes require exact named backends and selectors')
        if 'readiness' in backend:
            probe = backend['readiness']
            if (set(probe) != {'path', 'statuses'} or not re.fullmatch(r'/[a-zA-Z0-9/_-]{0,127}', probe['path']) or
                    not isinstance(probe['statuses'], list) or not 1 <= len(probe['statuses']) <= 6 or
                    len(set(probe['statuses'])) != len(probe['statuses']) or
                    any(type(status) is not int or status not in (200, 204, 400, 401, 403)
                        for status in probe['statuses'])):
                raise ValueError('Composition listener readiness requires bounded paths and explicit statuses')
    secrets = value['secrets']
    if not isinstance(secrets, list) or len(secrets) > 8:
        raise ValueError('Composition secret bindings exceed their scope')
    for secret in secrets:
        if (set(secret) != {'name', 'item', 'fields'} or secret['name'] not in approval['secretReferences'] or
                not re.fullmatch(NAME, secret['name']) or not re.fullmatch(NAME, secret['item']) or
                not isinstance(secret['fields'], dict) or not 1 <= len(secret['fields']) <= 32 or
                any(not re.fullmatch(r'[a-zA-Z0-9_.-]{1,64}', key) or
                    not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', field) for key, field in secret['fields'].items())):
            raise ValueError('Composition secret fields require explicit administrator approval')
    if len({row['name'] for row in secrets}) != len(secrets):
        raise ValueError('Composition secrets must have distinct destinations')
    request = {'cpu': 0, 'memory': 0}
    limit = {'cpu': 0, 'memory': 0}
    for workload in value['workloads']:
        if (set(workload) != {'name', 'replicas', 'podSpec'} | ({'selector'} if 'connections' in value else set()) or not re.fullmatch(NAME, workload['name']) or
                type(workload['replicas']) is not int or not 1 <= workload['replicas'] <= 3):
            raise ValueError('Composition workloads require exact names and bounded replicas')
        spec = workload['podSpec']
        if (not isinstance(spec, dict) or set(spec) - POD_FIELDS or
                spec.get('automountServiceAccountToken') is not False or spec.get('enableServiceLinks') is not False):
            raise ValueError('Composition pods cannot acquire host or service account authority')
        security = spec.get('securityContext', {})
        if (set(security) - {'runAsUser', 'runAsGroup', 'runAsNonRoot', 'fsGroup', 'supplementalGroups',
                             'seccompProfile', 'sysctls'} or security.get('seccompProfile') != {'type': 'RuntimeDefault'} or
                any(type(security.get(key)) is not int or not 0 <= security[key] <= 65535
                    for key in ('runAsUser', 'runAsGroup')) or
                ('sysctls' in security and security['sysctls'] != [
                    {'name': 'net.ipv6.conf.all.disable_ipv6', 'value': '1'}])):
            raise ValueError('Composition pod security differs from its supported bounded profile')
        containers = spec.get('containers', [])
        initializers = spec.get('initContainers', [])
        if not 1 <= len(containers) <= 8 or len(initializers) > 4:
            raise ValueError('Composition container count is invalid')
        for group in (containers, initializers):
            if len({row['name'] for row in group}) != len(group):
                raise ValueError('Composition container names must be distinct')
            for container in group:
                if set(container) - CONTAINER_FIELDS or container.get('image') not in images.values():
                    raise ValueError('Composition container or image differs from its approved scope')
                if any(port.get('hostPort', 0) != 0 or port.get('hostIP', '') != '' for port in container.get('ports', [])):
                    raise ValueError('Composition containers cannot publish host ports')
                sc = container.get('securityContext', {})
                caps = sc.get('capabilities', {})
                if (set(sc) - {'runAsUser', 'runAsGroup', 'runAsNonRoot', 'readOnlyRootFilesystem',
                              'allowPrivilegeEscalation', 'capabilities'} or
                        sc.get('readOnlyRootFilesystem') is not True or sc.get('allowPrivilegeEscalation') is not False or
                        set(caps) - {'drop', 'add'} or caps.get('drop') != ['ALL'] or
                        not set(caps.get('add', [])) <= (CAPABILITIES if group is containers else {'CHOWN', 'FOWNER', 'DAC_OVERRIDE'})):
                    raise ValueError('Composition containers must preserve sandbox security')
                for kind, totals in (('requests', request), ('limits', limit)):
                    resources = container.get('resources', {}).get(kind, {})
                    if set(resources) != {'cpu', 'memory'} or set(container.get('resources', {})) != {'requests', 'limits'}:
                        raise ValueError('Composition resources cannot acquire device or unapproved resource authority')
                    for unit, suffix in (('cpu', 'm'), ('memory', 'Mi')):
                        raw = resources.get(unit, '')
                        # Accept whole CPU cores in upstream charts; compare as millicores.
                        if unit == 'cpu' and re.fullmatch(r'[1-9][0-9]?', str(raw)):
                            amount = int(raw) * 1000
                        elif re.fullmatch(r'[1-9][0-9]{0,5}' + suffix, str(raw)):
                            amount = int(str(raw)[:-len(suffix)])
                        else:
                            raise ValueError('Composition containers require explicit positive resource budgets')
                        totals[unit] += amount * workload['replicas']
                for env in container.get('env', []):
                    if 'valueFrom' in env:
                        ref = env['valueFrom'].get('secretKeyRef', {})
                        if set(env['valueFrom']) != {'secretKeyRef'} or ref.get('name') not in approval['secretReferences']:
                            raise ValueError('Composition environment selects an unapproved credential')
        for volume in spec.get('volumes', []):
            if len(set(volume) - {'name'}) != 1 or set(volume) - {
                    'name', 'emptyDir', 'persistentVolumeClaim', 'secret', 'configMap'}:
                raise ValueError('Composition volumes cannot acquire host or projected authority')
            if 'secret' in volume and volume['secret'].get('secretName') not in approval['secretReferences']:
                raise ValueError('Composition volume selects an unapproved credential')
            if 'configMap' in volume and volume['configMap'].get('name') not in approval['configMaps']:
                raise ValueError('Composition volume selects an unapproved configuration')
            if 'persistentVolumeClaim' in volume and volume['persistentVolumeClaim'].get('claimName') not in {
                    row['name'] for row in claims}:
                raise ValueError('Composition volume selects an unapproved claim')
    for kind, totals in (('requests', request), ('limits', limit)):
        for unit, suffix in (('cpu', 'm'), ('memory', 'Mi')):
            if totals[unit] > int(budget[kind + '.' + unit][:-len(suffix)]):
                raise ValueError('Composition container totals exceed its namespace budget')
    if 'connections' in value:
        connections(value)
    return copy.deepcopy(value)


def connections(value):
    """Bind approved ambient peers to distinct workload identities and TCP listeners."""
    workloads = {row['name']: row for row in value['workloads']}
    accounts, selectors = set(), []
    for row in workloads.values():
        selector, account = row['selector'], row['podSpec'].get('serviceAccountName', '')
        listeners = [port for container in row['podSpec']['containers'] for port in container.get('ports', [])]
        if (len(listeners) > 16 or any(type(port.get('containerPort')) is not int or
                not 1 <= port['containerPort'] <= 65535 or port.get('protocol', 'TCP') != 'TCP' for port in listeners)):
            raise ValueError('Composition connections require bounded TCP workload listeners')
        if (not isinstance(selector, dict) or not 1 <= len(selector) <= 8 or
                any(not re.fullmatch(r'[a-zA-Z0-9./_-]{1,100}', key) or
                    not re.fullmatch(r'[a-zA-Z0-9._-]{1,63}', label) for key, label in selector.items()) or
                not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', account) or account == 'default' or account in accounts):
            raise ValueError('Composition connections require exact selectors and distinct non-default service accounts')
        if any(not any(key in other and other[key] != label for key, label in selector.items()) for other in selectors):
            raise ValueError('Composition workload selectors must be mutually exclusive')
        accounts.add(account)
        selectors.append(selector)
    for backend in value['backends'].values():
        selected = [row for row in workloads.values() if row['selector'] == backend['selector']]
        if len(selected) != 1 or backend['port'] not in tcp_ports(selected[0]):
            raise ValueError('Composition backend must select one approved workload listener')
    graph = value['connections']
    if not isinstance(graph, list) or len(graph) > 144:
        raise ValueError('Composition connections exceed their bounded graph')
    pairs = set()
    for edge in graph:
        if (not isinstance(edge, dict) or set(edge) != {'source', 'destination', 'ports'} or
                edge['source'] not in workloads or edge['destination'] not in workloads or
                not isinstance(edge['ports'], list) or not 1 <= len(edge['ports']) <= 16 or
                any(type(port) is not int or not 1 <= port <= 65535 for port in edge['ports']) or
                len(set(edge['ports'])) != len(edge['ports']) or
                not set(edge['ports']) <= tcp_ports(workloads[edge['destination']])):
            raise ValueError('Composition connections require declared peers and exact TCP destination ports')
        pair = edge['source'], edge['destination']
        if pair in pairs:
            raise ValueError('Composition connections must have distinct peer pairs')
        pairs.add(pair)


def tcp_ports(workload):
    return {port['containerPort'] for container in workload['podSpec']['containers']
            for port in container.get('ports', []) if port.get('protocol', 'TCP') == 'TCP'}


def workload_labels(workload, metadata):
    labels, annotations = metadata.get('labels', {}), metadata.get('annotations', {})
    if (any(labels.get(key) != label for key, label in workload['selector'].items()) or
            labels.get('istio.io/dataplane-mode', 'ambient') != 'ambient' or
            any(key in labels for key in ('istio.io/use-waypoint', 'istio.io/use-waypoint-namespace', 'sidecar.istio.io/inject')) or
            any(key.startswith(('sidecar.istio.io/', 'traffic.sidecar.istio.io/')) or
                key == 'ambient.istio.io/bypass-inbound-capture' for key in annotations) or
            annotations.get('ambient.istio.io/redirection', 'enabled') != 'enabled'):
        raise RuntimeError('Composition labels or mesh capture differ from their approved workload identity')


def validate(approval):
    try:
        return _validate(approval)
    except (KeyError, TypeError, AttributeError, IndexError) as error:
        raise ValueError('Composition input has an invalid contract shape') from None


def image_values(value, images=None):
    """Image paths replace both the tag and repository atomically with a full digest."""
    result = {}
    for name, path in value['imageValues'].items():
        target = result
        parts = path.split('.')
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        repository, digest = (images or value['images'])[name].split('@')
        target[parts[-1]] = {'repository': repository, 'digest': digest}
    return result


def quantity(value, key):
    raw = str(value)
    if len(raw) > 64:
        raise ValueError('Resource quantity exceeds its bound')
    try:
        if key.endswith('cpu'):
            return Decimal(raw[:-1]) / 1000 if raw.endswith('m') else Decimal(raw)
        if key.endswith(('memory', 'storage')):
            for suffix, scale in (('Gi', 1024 ** 3), ('Mi', 1024 ** 2), ('Ki', 1024)):
                if raw.endswith(suffix):
                    return Decimal(raw[:-2]) * scale
        return Decimal(raw)
    except InvalidOperation:
        raise ValueError('Resource quantity is invalid') from None


def normalized_spec(value):
    """Compare declared templates with API defaulting without hiding extra pod authority."""
    value = copy.deepcopy(value)
    tolerations = value.pop('tolerations', [])
    if (not isinstance(tolerations, list) or any(row not in DEFAULT_TOLERATIONS for row in tolerations) or
            len({row['key'] for row in tolerations}) != len(tolerations)):
        raise ValueError('Composition tolerations differ from exact admission defaults')
    for key, default in {'restartPolicy': 'Always', 'dnsPolicy': 'ClusterFirst', 'schedulerName': 'default-scheduler',
                         'serviceAccountName': 'default', 'terminationGracePeriodSeconds': 30}.items():
        value.setdefault(key, default)
    for key, default in (('serviceAccount', value['serviceAccountName']), ('priority', 0),
                         ('preemptionPolicy', 'PreemptLowerPriority')):
        if value.get(key) == default:
            value.pop(key)
    for volume in value.get('volumes', []):
        for kind in ('secret', 'configMap'):
            if kind in volume:
                volume[kind].setdefault('defaultMode', 420)
    for row in value['containers'] + value.get('initContainers', []):
        for key, default in {'imagePullPolicy': 'IfNotPresent', 'terminationMessagePath': '/dev/termination-log',
                             'terminationMessagePolicy': 'File'}.items():
            row.setdefault(key, default)
        for kind in ('requests', 'limits'):
            row['resources'][kind] = {key: quantity(amount, key) for key, amount in row['resources'][kind].items()}
        for port in row.get('ports', []):
            port.setdefault('protocol', 'TCP')
        for key in ('readinessProbe', 'livenessProbe', 'startupProbe'):
            if key not in row:
                continue
            for field, default in {'periodSeconds': 10, 'timeoutSeconds': 1,
                                   'successThreshold': 1, 'failureThreshold': 3}.items():
                row[key].setdefault(field, default)
            if 'httpGet' in row[key]:
                row[key]['httpGet'].setdefault('path', '/')
                row[key]['httpGet'].setdefault('scheme', 'HTTP')
    return value


def backend(definition, approval, get, condition):
    value = validate(approval)
    namespace = approval['namespace']
    application = get('application.argoproj.io', approval['name'] + '-' + definition['name'], 'argocd')
    catalog = get('application.argoproj.io', 'cloudlab-services', 'argocd')
    platform = (catalog['spec'].get('sources') or [catalog['spec'].get('source', {})])[0] if catalog else {}
    if (not application or application['spec']['project'] != approval['name'] or
            application['spec']['destination'] != {'server': 'https://kubernetes.default.svc', 'namespace': namespace} or
            application.get('status', {}).get('health', {}).get('status') != 'Healthy' or
            application.get('status', {}).get('sync', {}).get('status') != 'Synced' or application.get('operation')):
        raise RuntimeError('Composition lacks its converged approved application')
    sources = application['spec'].get('sources', [])
    if (len(sources) != 3 or sources[0].get('repoURL') != platform.get('repoURL') or
            sources[0].get('targetRevision') != platform.get('targetRevision') or sources[0].get('path') != 'charts/service' or
            sources[1].get('repoURL') != value['chart']['repository'] or
            sources[1].get('targetRevision') != value['chart']['revision'] or sources[1].get('path') != value['chart']['path'] or
            sources[1].get('helm', {}).get('releaseName') != approval['name'] or
            sources[1].get('helm', {}).get('valueFiles') != ['$values/' + approval['valuesPath']] or
            sources[2] != {'repoURL': approval['repository'], 'targetRevision': approval['revision'], 'ref': 'values'}):
        raise RuntimeError('Composition chart, private values or platform source differs from approval')
    images = copy.deepcopy(value['images'])
    artifact = approval.get('artifact')
    annotations = application.get('metadata', {}).get('annotations', {})
    if artifact:
        components = json.loads(annotations.get('cloudlab.io/artifact-components', '{}'))
        if (set(components) != set(artifact.get('components', [])) or
                annotations.get('cloudlab.io/primary-component') != artifact.get('primaryComponent') or
                components.get(artifact['primaryComponent']) != annotations.get('cloudlab.io/artifact-digest') or
                any(not isinstance(digest, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest)
                    for digest in components.values()) or
                not re.fullmatch(r'[a-f0-9]{40}', annotations.get('cloudlab.io/source-revision', '')) or
                not re.fullmatch(r'[1-9][0-9]{0,19}', annotations.get('cloudlab.io/workflow-run', '')) or
                not any(owner.get('kind') == 'ApplicationSet' and owner.get('name') == approval['name'] and
                        owner.get('controller') is True for owner in application.get('metadata', {}).get('ownerReferences', []))):
            raise RuntimeError('Composition release bindings differ from the approved component record')
        images.update({name: artifact['repository'] + '@' + digest for name, digest in components.items()})
    expected_values = image_values(value, images)
    if artifact:
        expected_values['imagePullSecrets'] = [{'name': 'harbor-application-pull'}]
    if sources[1].get('helm', {}).get('valuesObject') != expected_values:
        raise RuntimeError('Composition image overrides differ from the approved release')
    route_values = sources[0].get('helm', {}).get('valuesObject', {})
    if (route_values.get('routeOnly') is not True or route_values.get('routeBackends') != value['backends'] or
            route_values.get('exposure') != definition['exposure'] or
            route_values.get('additionalExposures') != definition.get('additionalExposures', [])):
        raise RuntimeError('Composition route source differs from its approved backend and exposure')
    policy = get('validatingpolicy.policies.kyverno.io', 'cloudlab-composition-' + approval['name'])
    from playbooks.istio.files.kube import condition_status_ready as policy_ready
    state = get('configmap', 'composition-' + approval['name'], 'cloudlab-policy')
    state = json.loads(state.get('data', {}).get('release.json', '{}')) if state else {}
    if (not policy_ready(policy) or policy['spec']['validationActions'] != ['Deny'] or
            policy['spec']['failurePolicy'] != 'Fail' or state.get('images') != images or
            state.get('approval') != policy['metadata'].get('annotations', {}).get('cloudlab.io/composition-profile')):
        raise RuntimeError('Composition release admission is absent, stale or unenforced')
    profile_application = get('application.argoproj.io', approval['name'] + '-profile', 'argocd')
    profile_source = profile_application.get('spec', {}).get('source', {}) if profile_application else {}
    if (not profile_application or profile_application.get('status', {}).get('health', {}).get('status') != 'Healthy' or
            profile_application.get('status', {}).get('sync', {}).get('status') != 'Synced' or
            profile_application['spec'].get('project') != approval['name'] + '-profile' or
            profile_source.get('repoURL') != platform.get('repoURL') or
            profile_source.get('targetRevision') != platform.get('targetRevision') or
            profile_source.get('path') != 'platform/delivery/service-profile' or
            profile_source.get('helm', {}).get('valuesObject', {}).get('images') != images):
        raise RuntimeError('Composition release state lacks its converged protected source')
    for workload in value['workloads']:
        deployment = get('deployment', workload['name'], namespace)
        if (not deployment or str(deployment.get('status', {}).get('observedGeneration')) != str(deployment['metadata']['generation']) or
                deployment.get('spec', {}).get('replicas') != workload['replicas'] or
                any(deployment.get('status', {}).get(field) != workload['replicas'] for field in (
                    'replicas', 'updatedReplicas', 'readyReplicas', 'availableReplicas')) or
                any(deployment.get('status', {}).get(field, 0) != 0 for field in ('unavailableReplicas', 'terminatingReplicas'))):
            raise RuntimeError('Composition workload is not ready at its approved replica count')
        spec = deployment['spec']['template']['spec']
        if 'connections' in value:
            if deployment['spec'].get('selector') != {'matchLabels': workload['selector']}:
                raise RuntimeError('Composition Deployment selector differs from its approved workload identity')
            workload_labels(workload, deployment['spec']['template'].get('metadata', {}))
        expected_spec = copy.deepcopy(workload['podSpec'])
        for kind in ('containers', 'initContainers'):
            expected = workload['podSpec'].get(kind, [])
            actual = spec.get(kind, [])
            if len(actual) != len(expected):
                raise RuntimeError('Composition container set differs from approval')
            for row in expected:
                component = next(name for name, image in value['images'].items() if image == row['image'])
                next(container for container in expected_spec[kind] if container['name'] == row['name'])['image'] = images[component]
                if not any(container['name'] == row['name'] and container['image'] == images[component] for container in actual):
                    raise RuntimeError('Composition component image differs from its approved role')
        if normalized_spec(spec) != normalized_spec(expected_spec):
            raise RuntimeError('Composition workload template differs from its complete approved profile')
    quota = get('resourcequota', 'budget', namespace)
    if not quota or any(quantity(quota['spec']['hard'].get(key), key) != quantity(expected, key)
                        for key, expected in value['budget'].items()):
        raise RuntimeError('Composition lacks its approved resource budget')
    for claim in value['claims']:
        actual = get('pvc', claim['name'], namespace)
        if (not actual or actual.get('status', {}).get('phase') != 'Bound' or
                actual['spec']['resources']['requests']['storage'] != claim['size'] or
                actual['spec']['accessModes'] != ['ReadWriteOncePod']):
            raise RuntimeError('Composition claim is not bound at its approved single-writer capacity')
