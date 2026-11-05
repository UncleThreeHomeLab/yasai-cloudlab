"""Prepare inert, public storage fixtures; never apply them to a cluster."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

import yaml

from playbooks.observability.files.chart import BASE, render

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = Path(__file__).with_name('fixtures') / 'storage-lifecycle'
OPERATION = '@@OPERATION@@'
PREFIX = 'obs-storage-' + OPERATION
OWNER = 'observability-lifecycle-proof'
NAMESPACE = 'cloudlab-observability'
LIMIT = 2 * 1024 * 1024
SOURCE_LIMIT = 4 * 1024 * 1024
OVERLAYS = {
    'loki': {'loki': {'cloudlabNativeLifecycle': True, 'singleBinary': {'persistence': {
        'enableStatefulSetAutoDeletePVC': True, 'whenDeleted': 'Retain', 'whenScaled': 'Retain'}}}},
    'tempo': {'tempo': {'persistence': {'enableStatefulSetAutoDeletePVC': False}}},
    'prometheus': {'kube-prometheus-stack': {'grafana': {'persistence': {'annotations': {
        'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}}}}},
}
SELECTED = {
    ('ServiceAccount', 'cloudlab-loki'): 'loki',
    ('ConfigMap', 'loki'): 'loki-config',
    ('ConfigMap', 'loki-runtime'): 'loki-runtime',
    ('Service', 'cloudlab-loki-memberlist'): 'loki-memberlist',
    ('Service', 'cloudlab-loki-headless'): 'loki-headless',
    ('Service', 'cloudlab-loki'): 'loki',
    ('StatefulSet', 'cloudlab-loki'): 'loki',
    ('ServiceAccount', 'cloudlab-tempo'): 'tempo',
    ('ConfigMap', 'tempo'): 'tempo-config',
    ('Service', 'cloudlab-tempo-headless'): 'tempo-headless',
    ('Service', 'cloudlab-tempo'): 'tempo',
    ('StatefulSet', 'cloudlab-tempo'): 'tempo',
    ('ServiceAccount', 'cloudlab-grafana'): 'grafana',
    ('ConfigMap', 'cloudlab-grafana'): 'grafana-config',
    ('ConfigMap', 'cloudlab-dashboards'): 'grafana-dashboards',
    ('Service', 'cloudlab-grafana'): 'grafana',
    ('PersistentVolumeClaim', 'cloudlab-grafana'): 'grafana',
    ('Deployment', 'cloudlab-grafana'): 'grafana',
}
DUMMY_SECRETS = {
    'grafana-emergency': {'username': 'fixture-only', 'password': 'fixture-only-password',
                          'secret_key': 'fixture-only-signing-key'},
    'grafana-oidc': {'client_secret': 'fixture-only-client-secret'},
}
WORKLOADS = {('StatefulSet', 'cloudlab-loki'): 'loki', ('StatefulSet', 'cloudlab-tempo'): 'tempo',
             ('Deployment', 'cloudlab-grafana'): 'grafana'}
ALLOWED = {'ConfigMap', 'Secret', 'ServiceAccount', 'Service', 'PersistentVolumeClaim', 'StatefulSet', 'Deployment'}
EXCLUDED_KINDS = {'CustomResourceDefinition', 'ClusterRole', 'ClusterRoleBinding', 'PrometheusRule',
                  'ServiceMonitor', 'Prometheus', 'Alertmanager', 'DaemonSet'}
EXCLUDED_NAMES = {'cloudlab-prometheus-kube-state-metrics', 'cloudlab-prometheus-prometheus-node-exporter',
                  'cloudlab-alertmanager', 'cloudlab-prometheus-operator', 'cloudlab-prometheus',
                  'alertmanager-cloudlab', 'cloudlab-prometheus-kube-state-metrics-customresourcestate-config'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def key(obj):
    return obj['kind'], obj['metadata']['name']


def name_mapping():
    return {identity: PREFIX + '-' + suffix for identity, suffix in SELECTED.items()} | {
        ('Secret', name): PREFIX + '-' + name for name in DUMMY_SECRETS}


def source_objects():
    sources, pins = [], {}
    for component, overlay in OVERLAYS.items():
        directory = BASE / component
        lock = json.loads((directory / 'artifact.lock.json').read_bytes())
        archive = directory / lock['archive']
        require(digest(archive.read_bytes()) == lock['sha256'], 'Native chart archive differs from its lock')
        pins[component] = {'archive': lock['archive'], 'sha256': lock['sha256'],
                           'valuesSha256': digest((directory / 'values.json').read_bytes()),
                           'overlay': overlay}
        sources.extend(render(component, overlay))
    require(len(canonical(sources)) <= SOURCE_LIMIT, 'Native render exceeds fixture bound')
    require(len({key(obj) for obj in sources}) == len(sources), 'Duplicate native resource identity')
    image_lock = (BASE / 'images.lock.json').read_bytes()
    images = json.loads(image_lock)
    for obj in sources:
        if key(obj) in WORKLOADS:
            component = WORKLOADS[key(obj)]
            require(obj['spec']['template']['spec']['containers'][0]['image'].split('@')[-1] == images[component].split('@')[-1],
                    'Native storage image differs from its accepted pin')
    pins['imagesLockSha256'] = digest(image_lock)
    return sources, pins


def dependency_refs(pod):
    refs = [('ServiceAccount', pod.get('serviceAccountName', 'default'))]
    for volume in pod.get('volumes', []):
        for field, kind, reference in [('configMap', 'ConfigMap', 'name'), ('secret', 'Secret', 'secretName'),
                                       ('persistentVolumeClaim', 'PersistentVolumeClaim', 'claimName')]:
            if field in volume:
                refs.append((kind, volume[field][reference]))
        require(not set(volume) - {'name', 'emptyDir', 'configMap', 'secret', 'persistentVolumeClaim'},
                'Unsupported native volume source')
    for container in pod.get('containers', []) + pod.get('initContainers', []):
        for entry in container.get('env', []) or []:
            for field, kind in [('secretKeyRef', 'Secret'), ('configMapKeyRef', 'ConfigMap')]:
                if field in entry.get('valueFrom', {}):
                    refs.append((kind, entry['valueFrom'][field]['name']))
        for entry in container.get('envFrom', []) or []:
            for field, kind in [('secretRef', 'Secret'), ('configMapRef', 'ConfigMap')]:
                if field in entry:
                    refs.append((kind, entry[field]['name']))
    return refs


def validate_closure(objects, namespace=None):
    indexed = {key(obj): obj for obj in objects}
    require(len(indexed) == len(objects), 'Duplicate fixture identity')
    for obj in objects:
        require(obj['kind'] in ALLOWED, 'Forbidden fixture kind')
        require(obj['metadata'].get('namespace') in ((NAMESPACE, PREFIX) if namespace is None else (namespace,)),
                'Unexpected fixture namespace')
        finalizers = obj['metadata'].get('finalizers') or []
        require(not obj['metadata'].get('ownerReferences')
                and finalizers == (['kubernetes.io/pvc-protection'] if obj['kind'] == 'PersistentVolumeClaim' else [])
                and not any(field in (obj['metadata'].get('annotations') or {})
                            for field in ('helm.sh/hook', 'argocd.argoproj.io/hook')), 'Unexpected native ownership or hook')
        if obj['kind'] == 'Service':
            require(obj['spec'].get('type', 'ClusterIP') == 'ClusterIP'
                    and not any(obj['spec'].get(field) for field in ('externalIPs', 'externalName', 'loadBalancerIP'))
                    and all(not port.get('nodePort') for port in obj['spec']['ports']), 'Exposed fixture Service')
        if obj['kind'] == 'Secret':
            require(obj.get('type') == 'Opaque' and not obj.get('data')
                    and obj.get('stringData') and not obj['metadata'].get('annotations'), 'Token or unsupported Secret')
        if obj['kind'] == 'ServiceAccount':
            # Grafana's native account defaults true; its selected Pod explicitly disables mounts and has no RBAC.
            grafana = obj['metadata']['name'] in ('cloudlab-grafana', PREFIX + '-grafana',
                                                 str(namespace) + '-grafana')
            require(obj.get('automountServiceAccountToken') is grafana and not obj.get('secrets')
                    and not obj.get('imagePullSecrets'), 'Credential-bearing ServiceAccount')
        if obj['kind'] == 'PersistentVolumeClaim':
            require(obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/sync-options') == 'Prune=false,Delete=false',
                    'Unprotected Grafana claim')
        if obj['kind'] not in ('StatefulSet', 'Deployment'):
            continue
        spec = obj['spec']
        pod = spec['template']['spec']
        claims = {('PersistentVolumeClaim', item['metadata']['name']) for item in spec.get('volumeClaimTemplates', [])}
        if obj['kind'] == 'StatefulSet':
            require(('Service', spec['serviceName']) in indexed, 'Dangling native governing Service: ' + spec['serviceName'])
            retention = spec.get('persistentVolumeClaimRetentionPolicy', {})
            require(all(retention.get(field, 'Retain') == 'Retain' for field in ('whenDeleted', 'whenScaled')),
                    'Destructive StatefulSet claim retention')
        for reference in dependency_refs(pod):
            require(reference in indexed or reference in claims, 'Unresolved workload dependency: ' + str(reference))
        require(pod.get('automountServiceAccountToken') is False and not pod.get('initContainers')
                and len(pod['containers']) == 1 and not pod.get('hostNetwork') and not pod.get('hostPID')
                and not pod.get('hostIPC') and not pod.get('imagePullSecrets'), 'Unexpected workload or credential profile')
        require(pod.get('securityContext', {}).get('runAsNonRoot') is True, 'Native workload must remain non-root')
        volumes = {volume['name'] for volume in pod.get('volumes', [])} | {name for kind, name in claims}
        for container in pod['containers']:
            require(re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}', container['image'])
                    and not container.get('securityContext', {}).get('privileged'), 'Unpinned or privileged container')
            require(all(mount['name'] in volumes for mount in container.get('volumeMounts', [])), 'Dangling mount')


def selected_objects(sources):
    indexed = {key(obj): obj for obj in sources}
    require(set(SELECTED) <= set(indexed), 'Native storage dependency identity changed')
    for obj in sources:
        if key(obj) not in SELECTED:
            require(obj['kind'] in EXCLUDED_KINDS or obj['metadata']['name'] in EXCLUDED_NAMES,
                    'Unknown excluded native resource')
    selected = [copy.deepcopy(indexed[identity]) for identity in SELECTED]
    require(b'@@' not in canonical(selected), 'Native configuration collides with fixture markers')
    for name, data in DUMMY_SECRETS.items():
        selected.append({'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': name, 'namespace': NAMESPACE},
                         'type': 'Opaque', 'stringData': data})
    validate_closure(selected)
    return selected


def replace_reference(value, kind, names):
    require((kind, value) in names, 'Unresolved typed reference: ' + kind + '/' + value)
    return names[kind, value]


def project(sources):
    objects = selected_objects(sources)
    names = name_mapping()
    for obj in objects:
        identity = key(obj)
        obj['metadata']['name'] = names[identity]
        obj['metadata']['namespace'] = PREFIX
        obj['metadata'].setdefault('labels', {}).update({'cloudlab.io/owner': OWNER, 'cloudlab.io/storage-proof': OPERATION})
        if obj['kind'] == 'PersistentVolumeClaim':
            obj['spec']['resources']['requests']['storage'] = '1Gi'
        if obj['kind'] not in ('StatefulSet', 'Deployment'):
            continue
        spec, pod = obj['spec'], obj['spec']['template']['spec']
        require(spec['replicas'] == 1, 'Native replica policy changed')
        spec['replicas'] = '@@REPLICAS@@'
        spec['template']['metadata'].setdefault('labels', {}).update(
            {'cloudlab.io/owner': OWNER, 'cloudlab.io/storage-proof': OPERATION})
        pod['serviceAccountName'] = replace_reference(pod['serviceAccountName'], 'ServiceAccount', names)
        if obj['kind'] == 'StatefulSet':
            spec['serviceName'] = replace_reference(spec['serviceName'], 'Service', names)
        for claim in spec.get('volumeClaimTemplates', []):
            claim['spec']['resources']['requests']['storage'] = '1Gi'
            claim['metadata'].setdefault('labels', {}).update(
                {'cloudlab.io/owner': OWNER, 'cloudlab.io/storage-proof': OPERATION})
        annotations = spec['template']['metadata']['annotations']
        if 'storage/size' in annotations:
            annotations['storage/size'] = '1Gi'
        annotations['checksum/config'] = '@@CHECKSUM_' + WORKLOADS[identity].upper() + '@@'
        for volume in pod.get('volumes', []):
            for field, kind, reference in [('configMap', 'ConfigMap', 'name'), ('secret', 'Secret', 'secretName'),
                                           ('persistentVolumeClaim', 'PersistentVolumeClaim', 'claimName')]:
                if field in volume:
                    volume[field][reference] = replace_reference(volume[field][reference], kind, names)
        for container in pod['containers']:
            for entry in container.get('env', []) or []:
                for field, kind in [('secretKeyRef', 'Secret'), ('configMapKeyRef', 'ConfigMap')]:
                    if field in entry.get('valueFrom', {}):
                        entry['valueFrom'][field]['name'] = replace_reference(entry['valueFrom'][field]['name'], kind, names)
            for entry in container.get('envFrom', []) or []:
                for field, kind in [('secretRef', 'Secret'), ('configMapRef', 'ConfigMap')]:
                    if field in entry:
                        entry[field]['name'] = replace_reference(entry[field]['name'], kind, names)
    indexed = {key(obj): obj for obj in objects}
    loki = indexed['ConfigMap', names['ConfigMap', 'loki']]['data']
    config = yaml.safe_load(loki['config.yaml'])
    require(config['common']['compactor_grpc_address'] == 'cloudlab-loki.' + NAMESPACE + '.svc.cluster.local:9095'
            and config['memberlist']['join_members'] == ['cloudlab-loki-memberlist.' + NAMESPACE + '.svc.cluster.local'],
            'Native Loki service reference changed')
    config['common']['compactor_grpc_address'] = names['Service', 'cloudlab-loki'] + '.' + PREFIX + '.svc.cluster.local:9095'
    config['memberlist']['join_members'] = [names['Service', 'cloudlab-loki-memberlist'] + '.' + PREFIX + '.svc.cluster.local']
    loki['config.yaml'] = yaml.safe_dump(config, sort_keys=False)
    tempo = indexed['ConfigMap', names['ConfigMap', 'tempo']]['data']
    config = yaml.safe_load(tempo['tempo.yaml'])
    require(config['memberlist']['cluster_label'] == 'cloudlab-tempo.' + NAMESPACE, 'Native Tempo cluster label changed')
    config['memberlist']['cluster_label'] = names['StatefulSet', 'cloudlab-tempo'] + '.' + PREFIX
    tempo['tempo.yaml'] = yaml.safe_dump(config, sort_keys=False)
    grafana = indexed['ConfigMap', names['ConfigMap', 'cloudlab-grafana']]['data']
    config = yaml.safe_load(grafana['datasources.yaml'])
    expected = {'Prometheus': 'http://cloudlab-prometheus:9090', 'Loki': 'http://cloudlab-loki:3100',
                'Tempo': 'http://cloudlab-tempo:3200'}
    require({entry['name']: entry['url'] for entry in config['datasources']} == expected, 'Native datasource endpoints changed')
    urls = {'Prometheus': 'http://unused.fixture.invalid:9090',
            'Loki': 'http://' + names['Service', 'cloudlab-loki'] + ':3100',
            'Tempo': 'http://' + names['Service', 'cloudlab-tempo'] + ':3200'}
    for entry in config['datasources']:
        entry['url'] = urls[entry['name']]
    grafana['datasources.yaml'] = yaml.safe_dump(config, sort_keys=False)
    validate_closure(objects)
    return objects


def invariant_workload(obj, names=None):
    """Normalize only the enumerated reference/fixture metadata differences."""
    obj = copy.deepcopy(obj)
    spec = obj['spec']
    if names is not None:
        reverse = {(kind, target): source for (kind, source), target in names.items()}
        require(spec['replicas'] == '@@REPLICAS@@', 'Forbidden fixture replica transformation')
        spec['replicas'] = 1
        pod = spec['template']['spec']
        pod['serviceAccountName'] = replace_reference(pod['serviceAccountName'], 'ServiceAccount', reverse)
        if obj['kind'] == 'StatefulSet':
            spec['serviceName'] = replace_reference(spec['serviceName'], 'Service', reverse)
        for volume in pod.get('volumes', []):
            for field, kind, reference in [('configMap', 'ConfigMap', 'name'), ('secret', 'Secret', 'secretName'),
                                           ('persistentVolumeClaim', 'PersistentVolumeClaim', 'claimName')]:
                if field in volume:
                    volume[field][reference] = replace_reference(volume[field][reference], kind, reverse)
        for container in pod['containers']:
            for entry in container.get('env', []) or []:
                for field, kind in [('secretKeyRef', 'Secret'), ('configMapKeyRef', 'ConfigMap')]:
                    if field in entry.get('valueFrom', {}):
                        entry['valueFrom'][field]['name'] = replace_reference(entry['valueFrom'][field]['name'], kind, reverse)
            for entry in container.get('envFrom', []) or []:
                for field, kind in [('secretRef', 'Secret'), ('configMapRef', 'ConfigMap')]:
                    if field in entry:
                        entry[field]['name'] = replace_reference(entry[field]['name'], kind, reverse)
        for metadata in [spec['template']['metadata']] + [claim['metadata'] for claim in spec.get('volumeClaimTemplates', [])]:
            require(metadata.get('labels', {}).get('cloudlab.io/owner') == OWNER
                    and metadata['labels'].get('cloudlab.io/storage-proof') == OPERATION, 'Missing fixture ownership')
            metadata['labels'].pop('cloudlab.io/owner')
            metadata['labels'].pop('cloudlab.io/storage-proof')
            if not metadata['labels']:
                metadata.pop('labels')
    for claim in spec.get('volumeClaimTemplates', []):
        if names is not None:
            require(claim['spec']['resources']['requests']['storage'] == '1Gi', 'Fixture claim exceeds one GiB')
        claim['spec']['resources']['requests']['storage'] = 'normalized'
    annotations = spec['template']['metadata']['annotations']
    if names is not None:
        require(re.fullmatch('@@CHECKSUM_(LOKI|TEMPO|GRAFANA)@@', annotations['checksum/config']), 'Unexpected checksum transform')
        if 'storage/size' in annotations:
            require(annotations['storage/size'] == '1Gi', 'Inconsistent storage size annotation')
    annotations.pop('checksum/config')
    if 'storage/size' in annotations:
        annotations['storage/size'] = 'normalized'
    return spec


def validate_projection(sources, objects):
    original = {key(obj): obj for obj in selected_objects(sources)}
    actual = {key(obj): obj for obj in objects}
    names = name_mapping()
    require(set(actual) == {(kind, names[kind, name]) for kind, name in original}, 'Fixture projection identities changed')
    validate_closure(objects)
    for identity, source in original.items():
        projected = actual[identity[0], names[identity]]
        metadata = copy.deepcopy(source['metadata'])
        metadata.update(name=names[identity], namespace=PREFIX)
        metadata.setdefault('labels', {}).update({'cloudlab.io/owner': OWNER, 'cloudlab.io/storage-proof': OPERATION})
        require(projected['metadata'] == metadata, 'Forbidden resource metadata transformation')
        if identity in WORKLOADS:
            continue
        expected = copy.deepcopy(source)
        expected['metadata'] = metadata
        if source['kind'] == 'PersistentVolumeClaim':
            expected['spec']['resources']['requests']['storage'] = '1Gi'
        if source['kind'] == 'ConfigMap':
            data = copy.deepcopy(projected['data'])
            changed = {('ConfigMap', 'loki'): 'config.yaml', ('ConfigMap', 'tempo'): 'tempo.yaml',
                       ('ConfigMap', 'cloudlab-grafana'): 'datasources.yaml'}.get(identity)
            if changed:
                before, after = yaml.safe_load(source['data'][changed]), yaml.safe_load(data[changed])
                if identity[1] == 'loki':
                    require(after['common']['compactor_grpc_address'] == names['Service', 'cloudlab-loki'] + '.' + PREFIX + '.svc.cluster.local:9095'
                            and after['memberlist']['join_members'] == [names['Service', 'cloudlab-loki-memberlist'] + '.' + PREFIX + '.svc.cluster.local'],
                            'Unscoped Loki configuration')
                    after['common']['compactor_grpc_address'] = before['common']['compactor_grpc_address']
                    after['memberlist']['join_members'] = before['memberlist']['join_members']
                elif identity[1] == 'tempo':
                    require(after['memberlist']['cluster_label'] == names['StatefulSet', 'cloudlab-tempo'] + '.' + PREFIX,
                            'Unscoped Tempo configuration')
                    after['memberlist']['cluster_label'] = before['memberlist']['cluster_label']
                else:
                    require({entry['name']: entry['url'] for entry in after['datasources']} == {
                        'Prometheus': 'http://unused.fixture.invalid:9090', 'Loki': 'http://' + names['Service', 'cloudlab-loki'] + ':3100',
                        'Tempo': 'http://' + names['Service', 'cloudlab-tempo'] + ':3200'}, 'Unscoped datasource endpoint')
                    urls = {entry['name']: entry['url'] for entry in before['datasources']}
                    for entry in after['datasources']:
                        entry['url'] = urls[entry['name']]
                require(after == before, 'Forbidden configuration field transformation')
                data[changed] = source['data'][changed]
            require(data == source['data'], 'Forbidden ConfigMap data transformation')
            expected['data'] = projected['data']
        require(projected == expected, 'Forbidden dependency transformation')
    for identity in WORKLOADS:
        require(invariant_workload(original[identity]) == invariant_workload(actual[identity[0], names[identity]], names),
                'Forbidden workload field transformation')


def template(obj):
    # Expand only markers inserted at typed projection fields; source Helm text stays literal.
    raw = json.dumps(obj, indent=2, ensure_ascii=False).replace('{{', '{{ "{{" }}')
    raw = raw.replace(OPERATION, '{{ .Values.operationId }}')
    raw = raw.replace('"@@REPLICAS@@"', '{{ ternary 1 0 (eq .Values.phase "running") }}')
    for component in ('loki', 'tempo', 'grafana'):
        expression = '{{ get (include "storage.config.' + component + '" . | fromJson) "data" | toJson | sha256sum }}'
        raw = raw.replace('@@CHECKSUM_' + component.upper() + '@@', expression)
    require('@@' not in raw, 'Unresolved generated fixture marker')
    return raw + '\n'


def build(sources=None, pins=None):
    if sources is None:
        sources, pins = source_objects()
    objects = project(sources)
    validate_projection(sources, objects)
    names = name_mapping()
    configs = {names['ConfigMap', source]: component for component, source in
               [('loki', 'loki'), ('tempo', 'tempo'), ('grafana', 'cloudlab-grafana')]}
    partials, manifests = [], []
    for obj in objects:
        if obj['kind'] == 'ConfigMap' and obj['metadata']['name'] in configs:
            helper = 'storage.config.' + configs[obj['metadata']['name']]
            partials.append('{{- define "' + helper + '" -}}\n' + template(obj) + '{{- end -}}\n')
            manifests.append('{{ include "' + helper + '" . }}\n')
        else:
            manifests.append(template(obj))
    sentinel = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': PREFIX + '-sentinel', 'namespace': PREFIX,
                'labels': {'cloudlab.io/owner': OWNER, 'cloudlab.io/storage-proof': OPERATION}},
                'data': {'purpose': 'synthetic-storage-lifecycle'}}
    guard = '''{{- range $name, $_ := .Values -}}
{{- if not (has $name (list "operationId" "phase")) }}{{ fail "Unsupported fixture input" }}{{ end -}}
{{- end -}}
{{- if or (not (kindIs "string" .Values.operationId)) (not (regexMatch "^[a-f0-9]{16}$" .Values.operationId)) }}{{ fail "Invalid fixture operationId" }}{{ end -}}
{{- if or (not (kindIs "string" .Values.phase)) (not (has .Values.phase (list "running" "scaled-down" "removed"))) }}{{ fail "Invalid fixture phase" }}{{ end -}}
{{- if ne .Release.Namespace (printf "obs-storage-%s" .Values.operationId) }}{{ fail "Fixture namespace must match operationId" }}{{ end -}}
'''
    schema = {'$schema': 'http://json-schema.org/draft-07/schema#', 'type': 'object', 'additionalProperties': False,
              'required': ['operationId', 'phase'], 'properties': {'operationId': {'type': 'string', 'pattern': '^[a-f0-9]{16}$'},
              'phase': {'type': 'string', 'enum': ['running', 'scaled-down', 'removed']}}}
    files = {'Chart.yaml': b'apiVersion: v2\nname: cloudlab-storage-lifecycle-fixture\nversion: 0.1.0\ntype: application\n',
             'values.yaml': b"operationId: ''\nphase: running\n",
             'values.schema.json': json.dumps(schema, indent=2).encode() + b'\n',
             'templates/_configuration.tpl': '\n'.join(partials).encode(),
             'templates/resources.yaml': (guard + template(sentinel) + '\n{{ if ne .Values.phase "removed" }}\n---\n'
                  + '\n---\n'.join(manifests) + '{{ end }}\n').encode()}
    lock = {'version': 1, 'sources': pins, 'sourceObjects': {kind + '/' + name: digest(canonical(obj))
            for obj in selected_objects(sources) for kind, name in [key(obj)]},
            'transformations': ['operation-bound names, namespaces, references and ownership labels', 'claims and storage/size annotation: 1Gi',
                'replicas: phase-selected one or zero', 'enumerated dummy grafana-emergency/grafana-oidc credentials',
                'Loki compactor/memberlist and Tempo cluster label: fixture names',
                'Grafana datasource URLs: fixture Loki/Tempo, unused.fixture.invalid Prometheus'],
            'checksumBasis': {'annotation': 'checksum/config', 'owners': list(WORKLOADS.values()),
                'input': 'Helm toJson(projected ConfigMap.data)', 'algorithm': 'sha256',
                'semantics': 'Fixture rollout checksum; not the upstream helper byte representation'},
            'artifacts': {name: digest(raw) for name, raw in files.items()}}
    files['derivation.lock.json'] = json.dumps(lock, sort_keys=True, indent=2).encode() + b'\n'
    require(sum(map(len, files.values())) <= LIMIT, 'Generated fixture exceeds bound')
    return files


def validate_rendered(objects, operation, phase):
    require(re.fullmatch('[a-f0-9]{16}', operation) and phase in ('running', 'scaled-down', 'removed'), 'Invalid fixture profile')
    namespace = 'obs-storage-' + operation
    names = {identity: target.replace(OPERATION, operation) for identity, target in name_mapping().items()}
    sentinel = ('ConfigMap', namespace + '-sentinel')
    expected = {sentinel} if phase == 'removed' else {(kind, target) for (kind, source), target in names.items()} | {sentinel}
    require({key(obj) for obj in objects} == expected and len(objects) == len(expected), 'Unexpected fixture resources')
    for obj in objects:
        require(obj['metadata'].get('namespace') == namespace
                and obj['metadata'].get('labels', {}).get('cloudlab.io/owner') == OWNER
                and obj['metadata']['labels'].get('cloudlab.io/storage-proof') == operation, 'Unscoped fixture resource')
        if obj['kind'] in ('StatefulSet', 'Deployment'):
            require(obj['spec']['replicas'] == (1 if phase == 'running' else 0), 'Invalid fixture replicas')
            for claim in obj['spec'].get('volumeClaimTemplates', []):
                require(claim['spec']['resources']['requests']['storage'] == '1Gi'
                        and claim['spec'].get('storageClassName') == 'cloudlab-telemetry', 'Invalid fixture claim')
        if obj['kind'] == 'PersistentVolumeClaim':
            require(obj['spec']['resources']['requests']['storage'] == '1Gi'
                    and obj['spec'].get('storageClassName') == 'cloudlab-telemetry', 'Invalid fixture claim')
    validate_closure([obj for obj in objects if key(obj) != sentinel], namespace=namespace)


def render_fixture(directory, operation, phase, namespace=None, extra=None):
    values = {'operationId': operation, 'phase': phase} | (extra or {})
    result = subprocess.run(['helm', 'template', 'fixture', str(directory), '--namespace', namespace or 'obs-storage-' + operation,
        '--kube-version', '1.36.5', '--values', '-'], input=yaml.safe_dump(values), text=True, capture_output=True, timeout=30)
    require(result.returncode == 0 and len(result.stdout.encode()) <= LIMIT, 'Storage fixture render rejected')
    return [obj for obj in yaml.safe_load_all(result.stdout) if obj]


def validate_output_paths(names):
    for path in (FIXTURE, *FIXTURE.parents):
        require(not path.is_symlink(), 'Storage fixture output contains a symbolic link')
        require(not path.exists() or path.is_dir(), 'Storage fixture output has a non-directory parent')
        if path == ROOT:
            break
    for name in names:
        target = FIXTURE / name
        for parent in target.parents:
            require(not parent.is_symlink(), 'Storage fixture output contains a symbolic link')
            require(not parent.exists() or parent.is_dir(), 'Storage fixture output has a non-directory parent')
            if parent == FIXTURE:
                break
        require(not target.is_symlink() and (not target.exists() or target.is_file()), 'Unsafe storage fixture output')
        require(not target.exists() or target.lstat().st_nlink == 1,
                'Storage fixture output has multiple hard links')


def prepare(check=True):
    files = build()
    with tempfile.TemporaryDirectory() as temporary:
        candidate = Path(temporary)
        for name, raw in files.items():
            (candidate / name).parent.mkdir(parents=True, exist_ok=True)
            (candidate / name).write_bytes(raw)
        for operation in ('a1b2c3d4e5f60789', '0123456789abcdef'):
            for phase in ('running', 'scaled-down', 'removed'):
                validate_rendered(render_fixture(candidate, operation, phase), operation, phase)
        validate_output_paths(files)
        if check:
            require(all((FIXTURE / name).is_file() and (FIXTURE / name).read_bytes() == raw for name, raw in files.items()),
                    'Storage fixture differs from pinned native derivation')
            require({str(path.relative_to(FIXTURE)).replace('\\', '/') for path in FIXTURE.rglob('*') if path.is_file()} == set(files),
                    'Unexpected storage fixture artifact')
        else:
            if FIXTURE.exists():
                require({str(path.relative_to(FIXTURE)).replace('\\', '/') for path in FIXTURE.rglob('*') if path.is_file()} <= set(files),
                        'Unknown file blocks fixture preparation')
            # Git publication remains a separate reviewed operation; only fixed artifact paths are written.
            for name in files:
                target = FIXTURE / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((candidate / name).read_bytes())
    return {'artifacts': len(files), 'liveActions': 0}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--check', action='store_true')
    modes.add_argument('--write', action='store_true')
    args = parser.parse_args()
    print(json.dumps(prepare(check=args.check)))
