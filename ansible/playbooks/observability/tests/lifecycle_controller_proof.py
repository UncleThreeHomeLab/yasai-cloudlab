"""Disposable Argo controller proof; synthetic workloads, never a stack qualification."""
import argparse
import base64
from contextlib import contextmanager
import copy
import functools
import hashlib
import io
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import ssl
import urllib.parse
import subprocess
import tempfile
import threading
import time

import yaml

from playbooks.argocd.tests.fixtures import (
    GitServer, GitSource, NativeAPI, ReadOnlyGit, command, install_argocd, require)

ROOT = Path('/workspace')
SOURCE = 'http://10.245.237.3:8000/'
APPS = '/apis/argoproj.io/v1alpha1/namespaces/argocd/applications/'
HEALTH_KEY = 'resource.customizations.health.argoproj.io_Application'
IMAGE = 'quay.io/argoproj/argocd:v3.5.3@sha256:dd3f47d5a5e4da563a7a398506e892481b358a7cec50abdf320c71aa55904bfa'


def application(name, path, revision, repository='public', automated=True, namespace='fixture'):
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
            'metadata': {'name': name, 'namespace': 'argocd'},
            'spec': {'project': 'default', 'source': {'repoURL': SOURCE + repository + '.git',
                'path': path, 'targetRevision': revision},
                'destination': {'server': 'https://kubernetes.default.svc', 'namespace': namespace},
                'syncPolicy': {'automated': {'enabled': automated, 'prune': True, 'selfHeal': True},
                    'retry': {'limit': 2, 'backoff': {'duration': '2s', 'maxDuration': '5s', 'factor': 2}}}}}


def run():
    require(os.environ.get('FIXTURE_PROJECT', '').startswith('obs-lifecycle-'), 'Use an isolated lifecycle project')
    deadline = time.monotonic() + 1500

    def wait(predicate, label, seconds=150):
        print('Waiting: ' + label, flush=True)
        stop = min(deadline, time.monotonic() + seconds)
        while time.monotonic() < stop:
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, ValueError, RuntimeError):
                pass
            time.sleep(2)
        raise RuntimeError('Fixture timed out: ' + label)

    document = wait(lambda: yaml.safe_load(Path('/fixture/kubeconfig').read_text()), 'cluster credentials')
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        api = NativeAPI(directory, document)
        wait(lambda: api.request('/api/v1/nodes')['items'], 'cluster API')
        argo = ROOT / 'platform/delivery/argocd'
        diagnostic_values = yaml.safe_load((argo / 'values.yaml').read_text())
        # v3.5.3 stores resource health only in Redis by default. Persist it in
        # BOTH runs so Kubernetes API assertions can compare the parent badge.
        diagnostic_values['argo-cd']['controller'].setdefault('extraArgs', []).append('--persist-resource-health')
        values_path = directory / 'diagnostic-values.yaml'
        values_path.write_text(yaml.safe_dump(diagnostic_values))
        install_argocd(api, directory, argo / 'charts/argo-cd-10.9.6.tgz',
                       argo / 'artifact.lock.json', values_path, baseline_health=True)
        wait(lambda: all(api.request('/apis/apps/v1/namespaces/argocd/' + kind + '/' + name)
             .get('status', {}).get('readyReplicas') == 1 for kind, name in
             [('deployments', 'argocd-repo-server'), ('deployments', 'argocd-redis'),
              ('statefulsets', 'argocd-application-controller')]), 'pinned controller readiness', 420)
        # An actual evaluation error yields Unknown in Argo; source errors alone
        # can legitimately leave an empty application's health Healthy.
        settings = api.request('/api/v1/namespaces/argocd/configmaps/argocd-cm')
        settings['data']['resource.customizations.health.fixtures.cloudlab.invalid_LifecycleFixture'] = (
            'error("Synthetic evaluator failure")')
        api.request('/api/v1/namespaces/argocd/configmaps/argocd-cm', 'PUT', settings)
        api.apply({'apiVersion': 'apiextensions.k8s.io/v1', 'kind': 'CustomResourceDefinition',
            'metadata': {'name': 'lifecyclefixtures.fixtures.cloudlab.invalid'},
            'spec': {'group': 'fixtures.cloudlab.invalid', 'scope': 'Namespaced',
                'names': {'plural': 'lifecyclefixtures', 'singular': 'lifecyclefixture', 'kind': 'LifecycleFixture'},
                'versions': [{'name': 'v1alpha1', 'served': True, 'storage': True,
                    'schema': {'openAPIV3Schema': {'type': 'object', 'properties': {'spec': {'type': 'object'}}}}}]}})
        for namespace in ('fixture', 'cloudlab-observability'):
            api.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': namespace}})
        api.apply({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
            'metadata': {'name': 'default', 'namespace': 'argocd'},
            'spec': {'sourceRepos': [SOURCE + 'public.git', SOURCE + 'private.git'], 'destinations': [
                {'server': 'https://kubernetes.default.svc', 'namespace': 'fixture'},
                {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
                'namespaceResourceWhitelist': [{'group': '*', 'kind': '*'}]}})
        api.apply({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
            'metadata': {'name': 'cloudlab-observability', 'namespace': 'argocd'},
            'spec': {'sourceRepos': [SOURCE + 'public.git'], 'destinations': [
                {'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-observability'}],
                'namespaceResourceWhitelist': [{'group': '*', 'kind': '*'}]}})
        source_root = directory / 'sources'
        source_root.mkdir()
        deployment = {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': 'degraded'},
            'spec': {'replicas': 1, 'progressDeadlineSeconds': 5, 'selector': {'matchLabels': {'fixture': 'degraded'}},
                'template': {'metadata': {'labels': {'fixture': 'degraded'}}, 'spec': {'automountServiceAccountToken': False,
                    'containers': [{'name': 'fail', 'image': IMAGE, 'command': ['/bin/false'],
                        'readinessProbe': {'exec': {'command': ['/bin/false']}, 'periodSeconds': 1}}],
                    'terminationGracePeriodSeconds': 0}}}}
        public = GitSource(source_root, 'public', {
            'unknown/value.yaml': 'apiVersion: fixtures.cloudlab.invalid/v1alpha1\nkind: LifecycleFixture\nmetadata:\n  name: unknown-fixture\n',
            'degraded/deployment.yaml': yaml.safe_dump(deployment),
            'platform/observability/Chart.yaml': 'apiVersion: v2\nname: synthetic-readiness\nversion: 0.1.0\n',
            'platform/observability/templates/sentinel.yaml': 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: native-sentinel\n  annotations:\n    argocd.argoproj.io/sync-options: Prune=false,Delete=false\n',
            'platform/observability/templates/value.yaml': 'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: native-marker\ndata:\n  value: "{{ .Values.value | default "initial" }}"\n'})
        private = GitSource(source_root, 'private', {'placeholder': 'synthetic only'})
        server = GitServer(('0.0.0.0', 8000), functools.partial(ReadOnlyGit, directory=str(source_root)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            children = [application('parity-unknown', 'unknown', public.revision),
                        application('parity-degraded', 'degraded', public.revision)]
            for child in children:
                api.apply(child)
            for name, health in [('parity-unknown', 'Unknown'), ('parity-degraded', 'Degraded')]:
                wait(lambda: api.request(APPS + name).get('status', {}).get('health', {}).get('status') == health,
                     'natural child health ' + health, 240)
            original = {child['metadata']['name']: api.request(APPS + child['metadata']['name']) for child in children}

            def complete(name):
                obj = api.request(APPS + name)
                status = obj.get('status', {})
                operation = status.get('operationState', {})
                return (obj.get('operation') is None and operation.get('phase') not in ('Running', 'Terminating')
                        and not any(c.get('type') in {'ComparisonError', 'InvalidSpecError', 'SyncError', 'UnknownError', 'DeletionError'}
                                    for c in status.get('conditions', []))
                        and status.get('sync', {}).get('status') == 'Synced'
                        and status.get('sync', {}).get('revision') == private.revision
                        and status.get('sync', {}).get('comparedTo', {}).get('source') == obj['spec']['source']
                        and status.get('sync', {}).get('comparedTo', {}).get('destination') == obj['spec']['destination']
                        and status.get('health', {}).get('status') == 'Healthy' and obj)

            def parent_run(name, content, marker=None):
                files = {name + '/children.yaml': yaml.safe_dump_all(content),
                         name + '/marker.yaml': yaml.safe_dump({'apiVersion': 'v1', 'kind': 'ConfigMap',
                            'metadata': {'name': marker or name, 'annotations': {'argocd.argoproj.io/sync-wave': '1'}}})}
                private.commit(files)
                if api.absent(APPS + name):
                    api.apply(application(name, name, 'main', repository='private'))

            parent_run('parity-baseline', children)
            baseline = wait(lambda: complete('parity-baseline'), 'baseline next wave and parent readiness')
            require(not api.absent('/api/v1/namespaces/fixture/configmaps/parity-baseline'), 'Baseline next wave missing')
            # Release ownership without deleting children; parity exercises identical live children.
            api.request(APPS + 'parity-baseline', 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions'})
            wait(lambda: api.absent(APPS + 'parity-baseline'), 'baseline parent deletion')
            for child in children:
                current = api.request(APPS + child['metadata']['name'])
                annotations = current['metadata'].get('annotations', {})
                annotations.pop('argocd.argoproj.io/tracking-id', None)
                api.request(APPS + child['metadata']['name'], 'PUT', current)
            cm = api.request('/api/v1/namespaces/argocd/configmaps/argocd-cm')
            cm['data'][HEALTH_KEY] = yaml.safe_load((argo / 'values.yaml').read_text())['argo-cd']['configs']['cm'][HEALTH_KEY]
            api.request('/api/v1/namespaces/argocd/configmaps/argocd-cm', 'PUT', cm)
            controller = '/api/v1/namespaces/argocd/pods/argocd-application-controller-0'
            previous_uid = api.request(controller)['metadata']['uid']
            api.request(controller, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions',
                                              'preconditions': {'uid': previous_uid}})
            def restarted():
                pod = api.request(controller)
                return pod['metadata']['uid'] != previous_uid and any(
                    c['type'] == 'Ready' and c['status'] == 'True' for c in pod.get('status', {}).get('conditions', []))
            wait(restarted, 'controller consumes changed Application health settings')
            parent_run('parity-custom', children)
            custom = wait(lambda: complete('parity-custom'), 'fallback next wave and parent readiness')
            require(not api.absent('/api/v1/namespaces/fixture/configmaps/parity-custom'), 'Fallback next wave missing')
            for name, previous in original.items():
                current = api.request(APPS + name)
                require(current['metadata']['uid'] == previous['metadata']['uid'] and current['spec'] == previous['spec'],
                        'Parity changed child identity or source')
                require(current['status']['health']['status'] == previous['status']['health']['status'],
                        'Parity changed natural child health')
            badges = [resource.get('health', {}).get('status') for resource in custom['status']['resources']
                      if resource['kind'] == 'Application']
            require(badges == ['Healthy', 'Healthy'], 'Fallback parent badges missing')
            require(all('health' not in resource for resource in baseline['status']['resources']
                        if resource['kind'] == 'Application'), 'Baseline unexpectedly propagates Application health')
            print(json.dumps({'parity': 'passed', 'childHealth': ['Unknown', 'Degraded'],
                              'parentReadiness': 'Synced+Healthy', 'fallbackBadge': 'Healthy'}, sort_keys=True), flush=True)

            child = application('cloudlab-observability', 'platform/observability', public.revision,
                                namespace='cloudlab-observability')
            child['metadata']['labels'] = {'cloudlab.io/owner': 'observability-platform'}
            child['metadata']['annotations'] = {'cloudlab.io/observability-health': 'required',
                'cloudlab.io/observability-input-digest': 'a' * 64}
            child['spec']['project'] = 'cloudlab-observability'
            child['spec']['source']['helm'] = {'valuesObject': {'nativeInputDigest': 'a' * 64,
                                                               'nativeLifecycle': {'enabled': True}}}
            parent_run('native-current', [child])
            wait(lambda: complete('native-current'), 'current native child passes')
            marker_path = '/api/v1/namespaces/cloudlab-observability/configmaps/native-marker'
            marker_uid = api.request(marker_path)['metadata']['uid']
            sentinel_path = '/api/v1/namespaces/cloudlab-observability/configmaps/native-sentinel'
            sentinel_uid = api.request(sentinel_path)['metadata']['uid']
            sentinel_template = (public.work / 'platform/observability/templates/sentinel.yaml').read_text()

            def history(label):
                current = api.request(APPS + 'cloudlab-observability')
                status = current.get('status', {})
                operation = status.get('operationState', {})
                require(status.get('sync', {}).get('revision') == public.revision
                        and current.get('operation') is None and operation.get('phase') not in ('Running', 'Terminating')
                        and status['sync'].get('comparedTo', {}).get('source') == current['spec']['source']
                        and status['sync'].get('comparedTo', {}).get('destination') == current['spec']['destination']
                        and status['sync'].get('status') == 'Synced' and status.get('health', {}).get('status') == 'Healthy',
                        'Native child lacks current healthy comparison')
                require(api.request(marker_path)['metadata']['uid'] == marker_uid
                        and api.request(sentinel_path)['metadata']['uid'] == sentinel_uid, 'Git update replaced native resources')
                print(json.dumps({'nativeHistory': label, 'phase': operation.get('phase', 'absent'),
                    'finished': bool(operation.get('finishedAt')), 'currentRevision': public.revision,
                    'lastOperationRevision': operation.get('syncResult', {}).get('revision'),
                    'lastOperationCurrent': operation.get('syncResult', {}).get('revision') == public.revision,
                    'currentComparison': True, 'resourceUIDsUnchanged': True}, sort_keys=True), flush=True)

            def terminal_parent():
                current = api.request(APPS + 'native-current')
                status = current.get('status', {})
                operation = status.get('operationState', {})
                return (current.get('operation') is None and operation.get('phase') in ('Failed', 'Error')
                        and operation.get('finishedAt')
                        and operation.get('syncResult', {}).get('revision') == private.revision and current)

            public.commit({'irrelevant/value': 'synthetic source-only change\n'})
            child['spec']['source']['targetRevision'] = public.revision
            private.commit({'native-current/children.yaml': yaml.safe_dump(child)})
            wait(lambda: complete('native-current'), 'no-op Git advancement with current comparison', 240)
            history('source-only advancement')
            # A later Git update must replace finite failed inline operations without a manual refresh.
            child['spec']['source']['helm']['valuesObject']['value'] = '"invalid'
            parent_run('native-current', [child], marker='native-bad')
            wait(lambda: any(c['type'] == 'ComparisonError' for c in
                             api.request(APPS + 'cloudlab-observability').get('status', {}).get('conditions', [])),
                 'invalid Helm input comparison')
            require(api.absent('/api/v1/namespaces/fixture/configmaps/native-bad'), 'Invalid native child advanced parent wave')
            require(api.request(marker_path)['metadata']['uid'] == marker_uid
                    and api.request(marker_path)['data']['value'] == 'initial', 'Source error mutated prior configuration')
            wait(terminal_parent, 'invalid input reaches finite parent failure', 240)
            child['spec']['source']['helm']['valuesObject'].pop('value')
            private.commit({'native-current/children.yaml': yaml.safe_dump(child)})
            wait(lambda: complete('native-current'), 'Git revert recovers without a new child operation', 240)
            require(api.request(marker_path)['data']['value'] == 'initial', 'Git revert changed initial configuration')
            history('revert after finite failure')
            child['spec']['source']['helm']['valuesObject']['value'] = 'repaired'
            child['metadata']['annotations']['cloudlab.io/observability-input-digest'] = 'b' * 64
            child['spec']['source']['helm']['valuesObject']['nativeInputDigest'] = 'b' * 64
            # Update the same parent to test replacement after its failed/running operation.
            private.commit({'native-current/children.yaml': yaml.safe_dump(child)})
            wait(lambda: complete('native-current'), 'later Git fixes failed inline values', 240)
            require(api.request(marker_path)['data']['value'] == 'repaired',
                    'Current Git repair was not applied')
            history('changed input converged')
            drift = api.request(marker_path)
            drift['data']['value'] = 'synthetic-drift'
            api.request(marker_path, 'PUT', drift)
            wait(lambda: api.request(marker_path)['data']['value'] == 'repaired', 'native child self-heals drift')
            require(api.request(marker_path)['metadata']['uid'] == marker_uid, 'Repair replaced configuration identity')
            public.commit({'platform/observability/templates/sentinel.yaml': None})
            child['spec']['source']['targetRevision'] = public.revision
            private.commit({'native-current/children.yaml': yaml.safe_dump(child)})
            wait(terminal_parent, 'retained resource reaches finite parent failure', 240)
            retained = api.request(APPS + 'cloudlab-observability')['status']
            require(retained['sync']['status'] == 'OutOfSync' and retained['operationState']['phase'] == 'Succeeded'
                    and retained['sync'].get('comparedTo', {}).get('source') == child['spec']['source']
                    and retained['sync'].get('comparedTo', {}).get('destination') == child['spec']['destination']
                    and retained['operationState'].get('finishedAt')
                    and retained['operationState']['syncResult'].get('source') == child['spec']['source']
                    and retained['operationState']['syncResult']['revision'] == public.revision
                    and api.request(sentinel_path)['metadata']['uid'] == sentinel_uid,
                    'Retained resource lacks current completed nonconvergence')
            public.commit({'platform/observability/templates/sentinel.yaml': sentinel_template})
            child['spec']['source']['targetRevision'] = public.revision
            private.commit({'native-current/children.yaml': yaml.safe_dump(child)})
            wait(lambda: complete('native-current'), 'Git restoration recovers retained resource', 240)
            history('restored retained declaration')
            public.commit({'platform/observability/templates/value.yaml': None})
            child['spec']['source']['targetRevision'] = public.revision
            private.commit({'native-current/children.yaml': yaml.safe_dump(child)})
            wait(lambda: complete('native-current') and api.absent(marker_path), 'accepted complete Git removes ordinary configuration', 240)
            require(not api.absent('/api/v1/namespaces/cloudlab-observability/configmaps/native-sentinel'),
                    'Ordinary removal deleted unrelated configuration')
            print(json.dumps({'native': 'passed', 'repair': 'later Git without manual refresh',
                              'noOp': 'current comparison and unchanged UIDs',
                              'retainedResource': 'finite failure and Git-only restoration',
                              'drift': 'self-healed', 'ordinaryRemoval': 'pruned',
                              'scope': 'synthetic controller readiness; no backend, CSI or TLS qualification'}), flush=True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


RUNTIME_PUBLIC = 'https://github.com/cloudlab-fixtures/observability-public.git'
RUNTIME_PRIVATE = 'https://github.com/cloudlab-fixtures/observability-private.git'
RUNTIME_OWNER = 'https://github.com/cloudlab-fixtures/observability-owner.git'
RUNTIME_PARENT = 'cloudlab-observability-gitops'
RUNTIME_CHILDREN = ('cloudlab-observability', 'cloudlab-prometheus', 'cloudlab-loki',
                    'cloudlab-tempo', 'cloudlab-alloy', 'cloudlab-kiali')
RUNTIME_NAMESPACE = 'cloudlab-observability'
RUNTIME_MANIFEST_PATH = ('/api/v1/applications/cloudlab-observability-gitops/manifests'
                         '?appNamespace=argocd&project=cloudlab-observability-gitops')
RUNTIME_BINARY_SHA = 'e557da422ff52a729989e3d631bcc171b3f6e925631c157306c1724228e8f8f9'
RUNTIME_HTTP_LIMIT = 1024 * 1024
RUNTIME_GENERATE_PATH = '/api/v1/applicationsets/generate'


def strict_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate fixture JSON field')
            result[key] = value
        return result
    require(isinstance(raw, (bytes, str)) and len(raw) <= RUNTIME_HTTP_LIMIT, 'Fixture JSON exceeds bound')
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(RuntimeError('Nonfinite fixture JSON')))


def runtime_root_policy(current, expected, expected_uid):
    spec = current.get('spec', {})
    operation = current.get('status', {}).get('operationState', {}).get('phase')
    require(current['metadata'].get('uid') == expected_uid and spec == expected and spec.get('syncPolicy', {}).get('automated') == {
        'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False}
        and spec.get('source') == {'repoURL': RUNTIME_OWNER, 'targetRevision': 'main', 'path': 'runtime-root'}
        and current.get('operation') is None and operation not in ('Running', 'Terminating')
        and not current['metadata'].get('deletionTimestamp'), 'Root authority is active, changed or pruning')


def runtime_manifest_closure(raw, expected):
    value = strict_json(raw)
    require(isinstance(value, dict) and isinstance(value.get('manifests'), list)
            and len(value['manifests']) == 6, 'Native response must contain six manifests')
    objects = [strict_json(item) for item in value['manifests']]
    indexed = {obj.get('metadata', {}).get('name'): obj for obj in objects}
    require(len(indexed) == 6 and set(indexed) == set(RUNTIME_CHILDREN)
            and indexed == {obj['metadata']['name']: obj for obj in expected}, 'Native paused manifest closure differs')
    require(all(obj.get('apiVersion') == 'argoproj.io/v1alpha1' and obj.get('kind') == 'Application'
            and obj['metadata'].get('namespace') == 'argocd'
            and obj['metadata']['annotations'].get('argocd.argoproj.io/skip-reconcile') == 'true'
            and obj['spec']['syncPolicy']['automated'] == {
                'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False}
            for obj in objects), 'Native manifests are not the exact paused Applications')
    return objects


def normalized_runtime_kubeconfig(document):
    value = copy.deepcopy(document)
    require(set(value) <= {'apiVersion', 'kind', 'clusters', 'users', 'contexts', 'current-context', 'preferences'}
            and value.get('apiVersion') == 'v1' and value.get('kind') == 'Config'
            and all(isinstance(value.get(key), list) and len(value[key]) == 1 for key in ('clusters', 'users', 'contexts')),
            'Fixture kubeconfig scope differs')
    cluster, user, context = value['clusters'][0], value['users'][0], value['contexts'][0]
    require(set(cluster) == {'name', 'cluster'} and set(cluster['cluster']) == {'server', 'certificate-authority-data'}
            and cluster['cluster']['server'] in ('https://127.0.0.1:6443', 'https://cluster:6443')
            and set(user) == {'name', 'user'} and set(user['user']) == {'client-certificate-data', 'client-key-data'}
            and set(context) == {'name', 'context'} and set(context['context']) <= {'cluster', 'user', 'namespace'}
            and context['context'].get('cluster') == cluster['name'] and context['context'].get('user') == user['name']
            and value.get('current-context') == context['name'], 'Fixture kubeconfig endpoint or credential source differs')
    for raw in [cluster['cluster']['certificate-authority-data'], *user['user'].values()]:
        require(isinstance(raw, str) and 0 < len(raw) <= 32768 and base64.b64decode(raw, validate=True),
                'Fixture credential encoding differs')
    cluster['cluster']['server'] = 'https://cluster:6443'
    return value


def runtime_http_response(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= RUNTIME_HTTP_LIMIT, 'Dashboard response exceeded total byte bound')
    header, separator, body = raw.partition(b'\r\n\r\n')
    require(separator and len(header) <= 32768, 'Dashboard HTTP header framing differs')
    lines = header.split(b'\r\n')
    require(re.fullmatch(rb'HTTP/1[.][01] 200(?: [\x20-\x7e]*)?', lines[0]) and len(lines) <= 101,
            'Dashboard requires exact HTTP 200')
    headers = {}
    for line in lines[1:]:
        key, colon, value = line.partition(b':')
        require(colon and re.fullmatch(rb'[A-Za-z0-9-]+', key) and all(32 <= byte <= 126 or byte == 9 for byte in value),
                'Dashboard HTTP header differs')
        headers.setdefault(key.lower(), []).append(value.strip().lower())
    length, transfer, encoding = (headers.get(key, []) for key in (b'content-length', b'transfer-encoding', b'content-encoding'))
    require(len(length) <= 1 and len(transfer) <= 1 and not (length and transfer)
            and encoding in ([], [b'identity']) and headers.get(b'location') is None, 'Ambiguous dashboard HTTP framing')
    if length:
        require(re.fullmatch(rb'[0-9]{1,10}', length[0]) and int(length[0]) == len(body), 'Dashboard body length differs')
        return body
    require(transfer == [b'chunked'], 'Unsupported dashboard HTTP body framing')
    result, cursor, chunks = bytearray(), 0, 0
    while True:
        end = body.find(b'\r\n', cursor)
        require(end >= cursor and re.fullmatch(rb'[a-fA-F0-9]{1,16}', body[cursor:end]), 'Dashboard chunk length differs')
        size, cursor = int(body[cursor:end], 16), end + 2
        chunks += 1
        require(chunks <= 65536 and size <= RUNTIME_HTTP_LIMIT, 'Dashboard chunk bound exceeded')
        if not size:
            require(body[cursor:] == b'\r\n', 'Dashboard trailers or trailing bytes refused')
            return bytes(result)
        require(body[cursor + size:cursor + size + 2] == b'\r\n', 'Dashboard chunk truncated')
        result.extend(body[cursor:cursor + size])
        require(len(result) <= RUNTIME_HTTP_LIMIT, 'Dashboard body exceeds bound')
        cursor += size + 2


def runtime_listener(process, arguments, port):
    require(os.getpgid(process.pid) == process.pid
            and Path('/proc/' + str(process.pid) + '/cmdline').read_bytes().split(b'\0')[:-1] == [arg.encode() for arg in arguments]
            and Path('/proc/' + str(process.pid) + '/exe').resolve() == Path(arguments[0]).resolve(),
            'Dashboard process identity differs')
    members = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal(): continue
        try: fields = (entry / 'stat').read_text().rsplit(') ', 1)[1].split()
        except FileNotFoundError: continue
        if int(fields[2]) == process.pid: members.append(int(entry.name))
    require(members == [process.pid], 'Unexpected dashboard process group member')
    descriptors = set()
    for path in (Path('/proc') / str(process.pid) / 'fd').iterdir():
        try: target = os.readlink(path)
        except FileNotFoundError: continue
        match = re.fullmatch(r'socket:\[([0-9]+)\]', target)
        if match: descriptors.add(match[1])
    listeners = []
    for table in ('tcp', 'tcp6'):
        for line in Path('/proc/net/' + table).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == '0A' and fields[9] in descriptors:
                address, encoded_port = fields[1].split(':')
                require((table == 'tcp' and address == '0100007F') or
                        (table == 'tcp6' and address == '00000000000000000000000001000000'),
                        'Dashboard listener is not loopback-only')
                listeners.append((table, int(encoded_port, 16)))
    return ('tcp', port) in listeners


def stop_dashboard(process):
    # The leader is never polled/reaped before killing its process group.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        stop = time.monotonic() + 1
        while time.monotonic() < stop:
            if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None:
                break
            time.sleep(0.02)
    finally:
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait(timeout=5)
        if process.stdout is not None: process.stdout.close()


def runtime_binary(deadline):
    binary = Path('/usr/local/bin/argocd')
    checksum = hashlib.sha256()
    with binary.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            require(time.monotonic() < deadline, 'Dashboard binary verification deadline expired')
            checksum.update(chunk)
    require(checksum.hexdigest() == RUNTIME_BINARY_SHA, 'Dashboard CLI differs from the pinned fixture image')
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'Dashboard CLI verification deadline expired')
    version = subprocess.run([str(binary), 'version', '--client', '--short'], capture_output=True, timeout=min(5, remaining))
    require(version.returncode == 0 and version.stdout.startswith(b'argocd: v3.5.3'), 'Dashboard CLI version differs')
    return str(binary)


@contextmanager
def runtime_dashboard(directory, document, deadline):
    binary = runtime_binary(deadline)
    config = directory / 'dashboard-kubeconfig'
    descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        yaml.safe_dump(normalized_runtime_kubeconfig(document), stream)
    with socket.socket() as selected:
        selected.bind(('127.0.0.1', 0))
        port = selected.getsockname()[1]
    arguments = [str(binary), 'admin', 'dashboard', '--address', '127.0.0.1', '--port', str(port),
        '--namespace', 'argocd', '--kubeconfig', str(config), '--request-timeout', '10s',
        '--config', str(directory / 'dashboard-config'), '--loglevel', 'error']
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=True, env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(directory), 'KUBECONFIG': str(config)})
    diagnostics = bytearray()
    def drain():
        while True:
            try: chunk = os.read(process.stdout.fileno(), 8192)
            except BlockingIOError: return
            if not chunk: return
            diagnostics.extend(chunk)
            require(len(diagnostics) <= 65536, 'Dashboard diagnostics exceeded private bound')
    try:
        os.set_blocking(process.stdout.fileno(), False)
        while time.monotonic() < deadline:
            drain()
            require(os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None,
                    'Dashboard exited before its owned listener was ready')
            ready = ('Argo CD UI is available at http://127.0.0.1:' + str(port)).encode()
            if ready in [line.removesuffix(b'\r') for line in diagnostics.split(b'\n')[:-1]]:
                require(runtime_listener(process, arguments, port), 'Dashboard owned listener changed')
                break
            time.sleep(0.1)
        else: raise RuntimeError('Dashboard listener deadline expired')
        yield port, lambda: (drain(), require(runtime_listener(process, arguments, port), 'Dashboard owned listener changed'))
    finally:
        stop_dashboard(process)
        # No request client or server remains after context exit.
        with socket.socket() as check:
            check.settimeout(1)
            require(check.connect_ex(('127.0.0.1', port)) != 0, 'Dashboard listener remains after process cleanup')



class RuntimeGit(ReadOnlyGit):
    """Map only the three canonical synthetic HTTPS sources to native upload-pack."""
    repositories = ('public.git', 'private.git', 'owner.git')

    def read_git(self):
        parsed = urllib.parse.urlsplit(self.path)
        paths = {urllib.parse.urlsplit(url).path + '/' + suffix: '/' + name + '.git/' + suffix
                 for name, url in (('public', RUNTIME_PUBLIC), ('private', RUNTIME_PRIVATE), ('owner', RUNTIME_OWNER))
                 for suffix in ('info/refs', 'git-upload-pack')}
        if (self.headers.get_all('Host') not in (['github.com'], ['github.com:443']) or
                parsed.path not in paths or parsed.scheme or parsed.netloc or parsed.fragment):
            self.send_error(403)
            return
        self.path = paths[parsed.path] + ('?' + parsed.query if parsed.query else '')
        super().read_git()


class RuntimeGitServer(GitServer):
    def __init__(self, address, handler, context):
        self.context = context
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        try:
            connection.settimeout(10)
            return self.context.wrap_socket(connection, server_side=True), address
        except BaseException:
            connection.close()
            raise


def runtime_git_pki(directory):
    """Synthetic CA and github.com leaf stay inside the private fixture directory."""
    directory.mkdir(mode=0o700)
    for name in ('ca', 'server'):
        command(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(directory / (name + '.key')),
            '-out', str(directory / (name + ('.crt' if name == 'ca' else '.csr'))),
            '-subj', '/CN=Fixture-only ' + name] + (['-x509', '-days', '2', '-addext',
                'keyUsage=critical,keyCertSign,cRLSign'] if name == 'ca' else []))
        (directory / (name + '.key')).chmod(0o600)
    extension = directory / 'server.ext'
    extension.write_text('subjectAltName=DNS:github.com\nextendedKeyUsage=serverAuth\n')
    command(['openssl', 'x509', '-req', '-in', str(directory / 'server.csr'), '-CA', str(directory / 'ca.crt'),
        '-CAkey', str(directory / 'ca.key'), '-CAcreateserial', '-out', str(directory / 'server.crt'),
        '-days', '2', '-extfile', str(extension)])
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory / 'server.crt', directory / 'server.key')
    return (directory / 'ca.crt').read_text(), context


def runtime_git_settings(values, ca):
    argo = values['argo-cd']
    argo.setdefault('global', {})['hostAliases'] = [{'ip': '10.245.237.3', 'hostnames': ['github.com']}]
    argo['configs'].setdefault('tls', {})['certificates'] = {'github.com': ca}
    argo['repoServer']['podLabels'] = {'cloudlab.io/restricted-git': 'true'}
    network = {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
        'metadata': {'name': 'runtime-repo-egress', 'namespace': 'argocd'}, 'spec': {
            'podSelector': {'matchLabels': {'cloudlab.io/restricted-git': 'true'}}, 'policyTypes': ['Egress'], 'egress': [
                {'to': [{'ipBlock': {'cidr': '10.245.237.3/32'}}], 'ports': [{'protocol': 'TCP', 'port': 443}]},
                {'to': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
                         'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}],
                 'ports': [{'protocol': 'UDP', 'port': 53}, {'protocol': 'TCP', 'port': 53}]},
                {'to': [{'podSelector': {'matchLabels': {'app.kubernetes.io/component': 'redis'}}}],
                 'ports': [{'protocol': 'TCP', 'port': 6379}]}]}}
    return values, network


def runtime_fixture_settings(values):
    """Trusted disposable setup only; never a production missing-settings fallback."""
    config = values['argo-cd']['configs']
    require(config.get('cm', {}).get('admin.enabled') is False, 'Fixture admin account must remain disabled')
    require(config['cm'].get('application.resourceTrackingMethod') == 'annotation' and 'installationID' not in config['cm'],
            'Fixture requires annotation tracking without installation ID')
    extra = config.setdefault('secret', {}).setdefault('extra', {})
    if 'server.secretkey' not in extra:
        extra['server.secretkey'] = base64.urlsafe_b64encode(os.urandom(32)).decode()
    require(isinstance(extra['server.secretkey'], str) and 32 <= len(extra['server.secretkey']) <= 1024,
            'Fixture signing key profile differs')
    return values


def runtime_core_state(read):
    """Observe initialized settings only; this preflight never writes or generates secrets."""
    secret = read('/api/v1/namespaces/argocd/secrets/argocd-secret')
    project = read('/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/default')
    settings = read('/api/v1/namespaces/argocd/configmaps/argocd-cm')
    require(secret.get('kind') == 'Secret' and secret.get('apiVersion') == 'v1'
        and secret.get('type') == 'Opaque' and secret['metadata'].get('name') == 'argocd-secret'
        and secret['metadata'].get('namespace') == 'argocd' and not secret['metadata'].get('ownerReferences')
        and not secret['metadata'].get('finalizers') and isinstance(secret.get('data'), dict)
        and isinstance(secret['data'].get('server.secretkey'), str)
        and 32 <= len(base64.b64decode(secret['data']['server.secretkey'], validate=True)) <= 1024,
        'Core requires an already initialized fixture signing Secret')
    require(project.get('kind') == 'AppProject' and project.get('apiVersion') == 'argoproj.io/v1alpha1'
        and project['metadata'].get('name') == 'default' and project['metadata'].get('namespace') == 'argocd'
        and settings.get('kind') == 'ConfigMap' and settings.get('apiVersion') == 'v1'
        and settings['metadata'].get('name') == 'argocd-cm' and settings['metadata'].get('namespace') == 'argocd'
        and settings.get('data', {}).get('admin.enabled') == 'false', 'Core settings or default Project are uninitialized')
    require(settings['data'].get('application.resourceTrackingMethod') == 'annotation' and 'installationID' not in settings['data'],
            'Core requires annotation tracking without installation ID')
    result = {}
    for name, obj, payload in [('secret', secret, secret['data']), ('project', project, project.get('spec', {})),
                               ('settings', settings, settings['data'])]:
        metadata = obj['metadata']
        require(isinstance(metadata.get('uid'), str) and metadata['uid']
            and isinstance(metadata.get('resourceVersion'), str) and metadata['resourceVersion']
            and not metadata.get('deletionTimestamp'), 'Core prerequisite identity differs')
        result[name] = {'uid': metadata['uid'], 'resourceVersion': metadata['resourceVersion'],
            'payloadSHA256': hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    return result


def runtime_generate_payload(expected):
    require(isinstance(expected, dict) and set(expected) == {'apiVersion', 'kind', 'metadata', 'spec'}
        and expected['apiVersion'] == 'argoproj.io/v1alpha1' and expected['kind'] == 'ApplicationSet'
        and expected['metadata'] == {'name': RUNTIME_PARENT, 'namespace': 'argocd',
            'labels': {'cloudlab.io/owner': 'observability-platform'},
            'annotations': {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}},
        'Generate body is not the independent Root ApplicationSet')
    spec = expected['spec']
    require(set(spec) == {'goTemplate', 'goTemplateOptions', 'generators', 'syncPolicy', 'template'}
        and spec['goTemplate'] is True and spec['goTemplateOptions'] == ['missingkey=error']
        and spec['syncPolicy'] == {'applicationsSync': 'create-update', 'preserveResourcesOnDeletion': True}
        and spec['generators'] == [{'merge': {'mergeKeys': ['consumer'], 'generators': [
            {'list': {'elements': [{'consumer': 'observability'}]}}, {'git': {'repoURL': RUNTIME_PRIVATE,
                'revision': 'main', 'files': [{'path': 'platform/acceptance/observability.yaml'}]}}]}}],
        'Generate source selection differs from the accepted closed merge')
    template = spec['template']
    require(set(template) == {'metadata', 'spec'} and template['metadata'] == {'name': RUNTIME_PARENT,
        'labels': {'cloudlab.io/owner': 'observability-platform'}, 'annotations': {
            'argocd.argoproj.io/skip-reconcile': 'true', 'argocd.argoproj.io/compare-options': 'IgnoreExtraneous',
            'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false',
            'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/Application:argocd/' + RUNTIME_PARENT}},
        'Generate target metadata differs from the paused parent')
    parent = template['spec']
    require(set(parent) == {'project', 'sources', 'destination', 'syncPolicy'}
        and parent['project'] == RUNTIME_PARENT
        and parent['destination'] == {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
        and parent['syncPolicy'] == {'automated': {'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False},
            'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}
        and isinstance(parent['sources'], list) and len(parent['sources']) == 2,
        'Generate target authority differs')
    public, private = parent['sources']
    require(set(public) == {'repoURL', 'targetRevision', 'path', 'helm'}
        and public['repoURL'] == RUNTIME_PUBLIC and re.fullmatch('[a-f0-9]{40}', public['targetRevision'])
        and public['path'] == 'platform/observability/gitops' and set(public['helm']) == {'releaseName', 'valueFiles', 'valuesObject'}
        and public['helm']['releaseName'] == RUNTIME_PARENT
        and public['helm']['valueFiles'] == ['$values/services/catalog.json', '$values/platform/observability.yaml']
        and public['helm']['valuesObject'] == {'nativeSource': {'repository': RUNTIME_PUBLIC,
            'revision': public['targetRevision'], 'valuesRepository': RUNTIME_PRIVATE, 'paused': True}}
        and set(private) == {'repoURL', 'targetRevision', 'ref'} and private['repoURL'] == RUNTIME_PRIVATE
        and private['ref'] == 'values' and isinstance(private['targetRevision'], str)
        and 'Consumer source acceptance refused' in private['targetRevision'], 'Generate immutable public or gated private source differs')
    body = json.dumps({'applicationSet': expected}, sort_keys=True, separators=(',', ':')).encode()
    require(len(body) <= RUNTIME_HTTP_LIMIT, 'Generate body exceeds bound')
    return body


def runtime_generated_parent(raw, installed):
    value = strict_json(raw)
    require(isinstance(value, dict) and set(value) == {'applications'}
            and isinstance(value['applications'], list) and len(value['applications']) == 1,
            'Native Generate must return exactly one parent')
    generated = value['applications'][0]
    require(isinstance(generated, dict) and generated.get('kind', 'Application') == 'Application'
        and generated.get('apiVersion', 'argoproj.io/v1alpha1') == 'argoproj.io/v1alpha1'
        and generated.get('metadata', {}).get('name') == RUNTIME_PARENT
        and generated['metadata'].get('namespace') == 'argocd'
        and not generated['metadata'].get('uid') and not generated['metadata'].get('resourceVersion')
        and generated.get('spec') == installed['spec']
        and generated['metadata'].get('labels', {}).get('cloudlab.io/owner') == 'observability-platform'
        and generated['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') == 'true'
        and len(generated['spec'].get('sources', [])) == 2
        and all(re.fullmatch('[a-f0-9]{40}', source.get('targetRevision', '')) for source in generated['spec']['sources'])
        and generated['spec'].get('project') == RUNTIME_PARENT
        and generated['spec'].get('destination') == {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
        and generated['spec'].get('syncPolicy', {}).get('automated') == {
            'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False},
        'Generated parent differs from installed immutable paused authority')
    return generated


def runtime_core_request(port, operation, generate_body, deadline, budget, guard):
    require(operation in ('generate', 'manifests') and type(port) is int and 0 < port < 65536,
            'Unsupported Core request')
    method, path, body = ('POST', RUNTIME_GENERATE_PATH, generate_body) if operation == 'generate' else ('GET', RUNTIME_MANIFEST_PATH, b'')
    require(isinstance(body, bytes) and len(body) <= RUNTIME_HTTP_LIMIT and 0 < budget[0] <= RUNTIME_HTTP_LIMIT,
            'Core request body or cumulative response budget differs')
    guard()
    remaining = deadline - time.monotonic()
    require(remaining > 0, 'Native Core total deadline expired')
    with socket.create_connection(('127.0.0.1', port), timeout=remaining) as connection:
        request = (method + ' ' + path + ' HTTP/1.1\r\nHost: 127.0.0.1:' + str(port) +
            '\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)) +
            '\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n').encode() + body
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'Native Core total deadline expired')
        connection.settimeout(remaining)
        connection.sendall(request)
        raw = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'Native Core total deadline expired')
            connection.settimeout(remaining)
            chunk = connection.recv(min(65536, budget[0] + 1 - len(raw)))
            if not chunk: break
            raw.extend(chunk)
            require(len(raw) <= budget[0], 'Native Core cumulative response byte bound exceeded')
        budget[0] -= len(raw)
    guard()
    return runtime_http_response(bytes(raw))


def runtime_manifest_read(api, directory, document, expected_parent, expected_children, expected_set, installed_set, seconds=60):
    require(type(seconds) is int and 15 <= seconds <= 60, 'Invalid native manifest deadline')
    deadline = time.monotonic() + seconds
    generate_body = runtime_generate_payload(expected_set)
    body_hash = hashlib.sha256(generate_body).hexdigest()
    set_path = '/apis/argoproj.io/v1alpha1/namespaces/argocd/applicationsets/' + RUNTIME_PARENT
    def read(path):
        require(deadline - time.monotonic() >= 15, 'Insufficient native API budget for source check')
        return api.request(path)
    before_parent, before_set = read(APPS + RUNTIME_PARENT), read(set_path)
    for actual, expected in ((before_parent, expected_parent), (before_set, installed_set)):
        require(actual['metadata']['uid'] == expected['metadata']['uid']
                and actual['metadata']['resourceVersion'] == expected['metadata']['resourceVersion']
                and actual['spec'] == expected['spec'], 'Native Core source binding changed before read')
    require(before_set['spec'] == expected_set['spec'] and before_parent['metadata'].get('ownerReferences') == expected_parent['metadata'].get('ownerReferences')
            and before_parent['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') == 'true'
            and before_parent.get('operation') is None
            and before_parent.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'),
            'Native Core parent is not the exact skipped idle source')
    def unchanged(actual, before):
        require(actual['metadata']['uid'] == before['metadata']['uid']
            and actual['metadata']['resourceVersion'] == before['metadata']['resourceVersion'] and actual['spec'] == before['spec'],
            'Native Core source changed during read')
    initial_settings = runtime_core_state(read)
    try:
        native_expected = runtime_core_expected(expected_children)
        with runtime_dashboard(directory, document, deadline) as (port, guard):
            budget = [RUNTIME_HTTP_LIMIT]
            generated = runtime_core_request(port, 'generate', generate_body, deadline, budget, guard)
            runtime_generated_parent(generated, before_parent)
            unchanged(read(set_path), before_set)
            unchanged(read(APPS + RUNTIME_PARENT), before_parent)
            response = runtime_core_request(port, 'manifests', b'', deadline, budget, guard)
            objects = runtime_manifest_closure(response, native_expected)
            unchanged(read(APPS + RUNTIME_PARENT), before_parent)
            unchanged(read(set_path), before_set)
            require(hashlib.sha256(runtime_generate_payload(expected_set)).hexdigest() == body_hash
                    and time.monotonic() < deadline, 'Native Core input changed or total deadline expired')
    finally:
        require(runtime_core_state(read) == initial_settings, 'Core changed initialized settings during its lifetime')
    return objects


def runtime_helm(chart, values, release='fixture'):
    raw = subprocess.run(['helm', 'template', release, str(ROOT / chart), '-n', 'argocd',
        '--kube-version', '1.36.5', '-f', '-'], input=json.dumps(values), text=True, capture_output=True, timeout=90)
    require(raw.returncode == 0 and len(raw.stdout) <= 2 * RUNTIME_HTTP_LIMIT, 'Fixture chart render failed')
    return [obj for obj in yaml.safe_load_all(raw.stdout) if obj]


def runtime_public_files():
    base = ROOT / 'platform/observability/gitops'
    files = {path.relative_to(ROOT).as_posix(): path.read_bytes() for path in base.rglob('*') if path.is_file()}
    for component in ('configuration', 'prometheus', 'loki', 'tempo', 'alloy', 'kiali'):
        prefix = 'platform/observability' + ('' if component == 'configuration' else '/' + component)
        files[prefix + '/Chart.yaml'] = 'apiVersion: v2\nname: handoff-' + component + '\nversion: 0.1.0\n'
        files[prefix + '/values.yaml'] = '{}\n'
        files[prefix + '/values.json'] = '{}\n'
        files[prefix + '/templates/marker.yaml'] = ('apiVersion: v1\nkind: ConfigMap\nmetadata:\n'
            '  name: handoff-marker-' + component + '\n  namespace: {{ .Release.Namespace }}\ndata:\n'
            '  value: native\n  digest: {{ .Values.nativeInputDigest | quote }}\n')
    return files


def runtime_private_inputs():
    from playbooks.observability.tests.fixtures import native_source_inputs
    values = native_source_inputs()
    return {'catalog': values['catalog'], 'observabilityInputs': values['observabilityInputs'],
            'nativeSource': {'paused': False}}


def runtime_root_objects(public_revision, private_revision, receipt, paused):
    from playbooks.argocd.files.private_sources import acceptance_spec, consumer_contract, validate_consumer_acceptance
    values = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    preimage = '\n'.join([receipt['version'], 'observability', RUNTIME_PRIVATE, '2', *receipt['paths'],
                           receipt['revision'], receipt['nonce'], ''])
    values['repository'] = RUNTIME_PUBLIC
    values['identity']['argo'] = {'valuesRepository': RUNTIME_PRIVATE, 'valuesRevision': private_revision}
    values['services']['revision'] = public_revision
    values['observability']['configuration'] = {'enabled': True, 'paused': paused, 'revision': public_revision,
        'acceptanceCommitment': hashlib.sha256(preimage.encode()).hexdigest()}
    contract = consumer_contract(values, 'observability')
    validate_consumer_acceptance(receipt, RUNTIME_PRIVATE, contract)
    objects = [obj for obj in runtime_helm('gitops/roots/public', values) if
               (obj['kind'], obj['metadata']['name']) in {('AppProject', RUNTIME_NAMESPACE),
                   ('AppProject', RUNTIME_PARENT), ('ApplicationSet', RUNTIME_PARENT)}]
    require(len(objects) == 3, 'Selected native Root object closure differs')
    native_set = next(obj for obj in objects if obj['kind'] == 'ApplicationSet')
    require(native_set['spec'] == acceptance_spec(values, RUNTIME_PRIVATE, private_revision, consumer='observability'),
            'Native consumer acceptance contract differs')
    return objects


def runtime_expected(public_revision, private_inputs, paused):
    values = copy.deepcopy(private_inputs)
    values['nativeSource'] = {'repository': RUNTIME_PUBLIC, 'revision': public_revision,
                             'valuesRepository': RUNTIME_PRIVATE, 'paused': paused}
    return runtime_helm('platform/observability/gitops', values, RUNTIME_PARENT)


def runtime_core_expected(expected):
    objects = copy.deepcopy(expected)
    for obj in objects:
        metadata = obj['metadata']
        require(obj.get('apiVersion') == 'argoproj.io/v1alpha1' and obj.get('kind') == 'Application'
                and metadata.get('namespace') == 'argocd' and metadata.get('name') in RUNTIME_CHILDREN,
                'Core expected child identity differs')
        annotations = metadata.setdefault('annotations', {})
        require('argocd.argoproj.io/tracking-id' not in annotations and 'argocd.argoproj.io/installation-id' not in annotations,
                'Direct Helm expectation already contains tracking ownership')
        annotations['argocd.argoproj.io/tracking-id'] = RUNTIME_PARENT + ':argoproj.io/Application:argocd/' + metadata['name']
    return objects


def runtime_old_parent(public_revision):
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': RUNTIME_PARENT, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': 'observability-platform'},
                     'annotations': {'argocd.argoproj.io/skip-reconcile': 'true'}},
        'spec': {'project': RUNTIME_PARENT, 'sources': [
            {'repoURL': RUNTIME_PUBLIC, 'targetRevision': public_revision, 'path': 'platform/observability/gitops',
             'helm': {'releaseName': RUNTIME_PARENT, 'valueFiles': ['$values/services/catalog.json', '$values/platform/observability.yaml'],
                      'valuesObject': {'nativeSource': {'repository': RUNTIME_PUBLIC, 'revision': public_revision,
                                                       'valuesRepository': RUNTIME_PRIVATE}}}},
            {'repoURL': RUNTIME_PRIVATE, 'targetRevision': 'main', 'ref': 'values'}],
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
            'syncPolicy': {'automated': {'enabled': False, 'prune': False, 'selfHeal': False, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}


def runtime_current(app, revision, *, sources=False):
    status = app.get('status', {})
    sync = status.get('sync', {})
    compared = sync.get('comparedTo', {})
    return (app.get('operation') is None and status.get('operationState', {}).get('phase') not in ('Running', 'Terminating')
        and not any(condition.get('type', '').endswith('Error') for condition in status.get('conditions', []))
        and sync.get('status') == 'Synced' and status.get('health', {}).get('status') == 'Healthy'
        and sync.get('revisions' if sources else 'revision') == revision
        and compared.get('sources' if sources else 'source') == app['spec'].get('sources' if sources else 'source')
        and compared.get('destination') == app['spec']['destination'])


def runtime_path(obj):
    version, kind, metadata = obj['apiVersion'], obj['kind'], obj['metadata']
    plural = {'Application': 'applications', 'ApplicationSet': 'applicationsets', 'AppProject': 'appprojects',
              'ConfigMap': 'configmaps', 'Namespace': 'namespaces', 'NetworkPolicy': 'networkpolicies'}[kind]
    prefix = '/api/v1' if version == 'v1' else '/apis/' + version
    if kind != 'Namespace': prefix += '/namespaces/' + metadata['namespace']
    return prefix + '/' + plural + '/' + metadata['name']


def runtime_identity(obj):
    return {key: obj['metadata'].get(key) for key in ('name', 'namespace', 'uid')}


RUNTIME_RELEASE_LABEL = 'same-owner Git explicitly releases all six held children'
RUNTIME_RELEASE_STAGES = frozenset(('root-policy', 'parent-read', 'set-read', 'parent-set-identity',
    'set-spec', 'parent-spec', 'parent-unpaused', 'root-current', 'parent-current', 'child-read', 'marker-read',
    'child-identity', 'child-spec', 'child-unpaused', 'child-current', 'marker-identity', 'marker-value', 'marker-digest', 'unclassified'))


def runtime_release_entry(stage, component, exception):
    return {'stage': stage if isinstance(stage, str) and stage in RUNTIME_RELEASE_STAGES else 'unclassified',
        'component': component if isinstance(component, str) and component in RUNTIME_CHILDREN else None,
        'exceptionType': exception if exception is None or isinstance(exception, str)
            and exception in ('OSError', 'ValueError', 'RuntimeError') else 'unclassified'}


def runtime_release_observe(diagnostic, stage, action, component=None, *, predicate=False):
    def failed(exception_type):
        row = runtime_release_entry(stage, component, exception_type)
        diagnostic.setdefault('firstFailed', row)
        diagnostic['lastFailed'] = row
    try:
        result = action()
    except (OSError, ValueError, RuntimeError) as error:
        failed('OSError' if isinstance(error, OSError) else 'ValueError' if isinstance(error, ValueError) else 'RuntimeError')
        raise
    if predicate and not result:
        failed(None)
    return result


def runtime_release_wait(wait, predicate, diagnostic):
    try:
        return wait(predicate, RUNTIME_RELEASE_LABEL, 420)
    except RuntimeError as error:
        if str(error) == 'Runtime fixture timed out: ' + RUNTIME_RELEASE_LABEL:
            def closed(row):
                if not isinstance(row, dict): return None
                stage, component, exception = (row.get(key) for key in ('stage', 'component', 'exceptionType'))
                return runtime_release_entry(stage, component, exception)
            print(json.dumps({'runtimeReleaseDiagnostic': {key: closed(diagnostic.get(key))
                for key in ('firstFailed', 'lastFailed')}}, sort_keys=True, separators=(',', ':')), flush=True)
        raise


def runtime_released(api, root_path, root, parent_uid, set_path, active_set, expected_active_parent,
                     owner_source, public, accepted_revision, active_expected, owned, old_markers, diagnostic):
    def observe(stage, action, component=None, *, predicate=False):
        return runtime_release_observe(diagnostic, stage, action, component, predicate=predicate)
    observe('root-policy', lambda: runtime_root_policy(api.request(root_path), root['spec'], owned[root_path]['identity']['uid']))
    current = observe('parent-read', lambda: api.request(APPS + RUNTIME_PARENT))
    current_set = observe('set-read', lambda: api.request(set_path))
    observe('parent-set-identity', lambda: require(current['metadata']['uid'] == parent_uid
        and runtime_identity(current_set) == owned[set_path]['identity'], 'Git release replaced parent or Set UID'))
    if (not observe('set-spec', lambda: current_set['spec'] == active_set['spec'], predicate=True)
            or not observe('parent-spec', lambda: current['spec'] == expected_active_parent, predicate=True)
            or not observe('parent-unpaused', lambda: current['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') == 'false', predicate=True)
            or not observe('root-current', lambda: runtime_current(api.request(root_path), owner_source.revision), predicate=True)
            or not observe('parent-current', lambda: runtime_current(current, [public.revision, accepted_revision], sources=True), predicate=True)):
        return False
    for desired in active_expected:
        component = desired['metadata']['name']
        child = observe('child-read', lambda: api.request(runtime_path(desired)), component)
        marker_path, marker_uid, _ = old_markers[component]
        marker = observe('marker-read', lambda: api.request(marker_path), component)
        observe('child-identity', lambda: require(runtime_identity(child) == owned[runtime_path(desired)]['identity'],
                                                'Git release replaced child UID'), component)
        if (not observe('child-spec', lambda: child['spec'] == desired['spec'], component, predicate=True)
                or not observe('child-unpaused', lambda: child['metadata']['annotations'].get('argocd.argoproj.io/skip-reconcile') == 'false', component, predicate=True)
                or not observe('child-current', lambda: runtime_current(child, public.revision), component, predicate=True)
                or not observe('marker-identity', lambda: marker['metadata']['uid'] == marker_uid, component, predicate=True)
                or not observe('marker-value', lambda: marker.get('data', {}).get('value') == 'native', component, predicate=True)
                or not observe('marker-digest', lambda: marker['data'].get('digest') == desired['metadata']['annotations']['cloudlab.io/observability-input-digest'], component, predicate=True)):
            return False
    return True


def runtime_cleanup_rows(version, resource, read):
    require(isinstance(version, str) and (version == '/api/v1' or re.fullmatch(
        r'/apis/[a-z0-9][a-z0-9.-]*/v[0-9]+(?:(?:alpha|beta)[0-9]+)?', version)),
        'Cleanup discovery API version differs')
    api_version = 'v1' if version == '/api/v1' else version.removeprefix('/apis/')
    require(isinstance(resource, dict) and resource.get('namespaced') is True
        and 'list' in resource.get('verbs', []) and isinstance(resource.get('name'), str)
        and re.fullmatch(r'[a-z][a-z0-9.-]*', resource['name']) and isinstance(resource.get('kind'), str)
        and re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', resource['kind']), 'Cleanup discovery resource differs')
    listing = read(version + '/namespaces/' + RUNTIME_NAMESPACE + '/' + resource['name'])
    require(isinstance(listing, dict) and isinstance(listing.get('items'), list)
            and not listing.get('metadata', {}).get('continue'), 'Incomplete fixture cleanup discovery')
    result = []
    for item in listing['items']:
        require(isinstance(item, dict) and item.get('kind', resource['kind']) == resource['kind']
            and item.get('apiVersion', api_version) == api_version, 'Cleanup row contradicts discovery TypeMeta')
        row = copy.deepcopy(item)
        row.setdefault('kind', resource['kind'])
        row.setdefault('apiVersion', api_version)
        result.append(row)
    return result


def runtime_handoff():
    require(os.environ.get('FIXTURE_PROJECT', '').startswith('obs-lifecycle-'), 'Use an isolated lifecycle project')
    deadline = time.monotonic() + 1500
    operation_deadline = [deadline - 150]  # Reserve bounded cleanup inside the same total budget.
    def wait(predicate, label, seconds=240):
        print('Waiting: ' + label, flush=True)
        stop = min(operation_deadline[0], time.monotonic() + seconds)
        while time.monotonic() < stop:
            try:
                result = predicate()
                if result: return result
            except (OSError, ValueError, RuntimeError):
                pass
            time.sleep(2)
        raise RuntimeError('Runtime fixture timed out: ' + label)
    document = wait(lambda: yaml.safe_load(Path('/fixture/kubeconfig').read_text()), 'runtime cluster credentials')
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        class RuntimeAPI(NativeAPI):
            def request(self, *args, **kwargs):
                require(time.monotonic() + 15 < operation_deadline[0], 'Runtime fixture API deadline exhausted')
                return super().request(*args, **kwargs)
        api = RuntimeAPI(directory, document)
        owned = {}
        def remember(obj):
            path, observed = runtime_path(obj), runtime_identity(obj)
            require(path not in owned or owned[path]['identity'] == observed, 'Recorded fixture identity changed')
            owned[path] = {'identity': observed, 'kind': obj['kind']}
            return obj
        def apply(obj):
            path = runtime_path(obj)
            if path not in owned: require(api.absent(path), 'Existing fixture object cannot be adopted')
            current = api.request(path + '?fieldManager=runtime-handoff-fixture&force=false', 'PATCH', obj,
                expected=201 if api.absent(path) else 200)
            return remember(current)
        def remove(path):
            if api.absent(path): return
            current = api.request(path)
            require(runtime_identity(current) == owned[path]['identity'] and not current['metadata'].get('finalizers'),
                    'Unknown identity or finalizer blocks fixture cleanup')
            api.request(path, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'propagationPolicy': 'Orphan',
                'preconditions': {'uid': current['metadata']['uid'], 'resourceVersion': current['metadata']['resourceVersion']}})
            wait(lambda: api.absent(path), 'exact fixture cleanup', 120)
        source_root = directory / 'sources'
        source_root.mkdir()
        public = GitSource(source_root, 'public', runtime_public_files())
        private_inputs = runtime_private_inputs()
        private = GitSource(source_root, 'private', {'services/catalog.json': yaml.safe_dump({'catalog': private_inputs['catalog']}),
            'platform/observability.yaml': yaml.safe_dump({key: value for key, value in private_inputs.items() if key != 'catalog'})})
        accepted_revision = private.revision
        receipt = {'version': 'cloudlab-consumer-source-acceptance/v1', 'consumer': 'observability',
            'paths': ['services/catalog.json', 'platform/observability.yaml'], 'revision': accepted_revision, 'nonce': '2' * 64}
        private.commit({'platform/acceptance/observability.yaml': yaml.safe_dump(receipt)})
        selected = runtime_root_objects(public.revision, private.revision, receipt, True)
        projects = [obj for obj in selected if obj['kind'] == 'AppProject']
        old_parent = runtime_old_parent(public.revision)
        owner_source = GitSource(source_root, 'owner', {'runtime-root/objects.yaml': yaml.safe_dump_all(projects + [old_parent])})
        ca, tls_context = runtime_git_pki(directory / 'git-pki')
        server = RuntimeGitServer(('0.0.0.0', 443), functools.partial(RuntimeGit, directory=str(source_root)), tls_context)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        success = False
        try:
            wait(lambda: api.request('/api/v1/nodes')['items'], 'runtime cluster API')
            require(api.absent('/api/v1/namespaces/argocd') and all(api.absent(
                '/apis/apiextensions.k8s.io/v1/customresourcedefinitions/' + name + '.argoproj.io')
                for name in ('applications', 'applicationsets', 'appprojects')),
                'Runtime fixture requires a fresh cluster without existing Argo state')
            api.apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'argocd'}})
            argo = ROOT / 'platform/delivery/argocd'
            values, network = runtime_git_settings(
                runtime_fixture_settings(yaml.safe_load((argo / 'values.yaml').read_text())), ca)
            apply(network)
            values_path = directory / 'runtime-argo-values.yaml'
            values_path.write_text(yaml.safe_dump(values))
            values_path.chmod(0o600)
            install_argocd(api, directory, argo / 'charts/argo-cd-10.9.6.tgz', argo / 'artifact.lock.json',
                           values_path, application_sets=True)
            wait(lambda: all(api.request('/apis/apps/v1/namespaces/argocd/' + kind + '/' + name)
                .get('status', {}).get('readyReplicas') == 1 for kind, name in [
                    ('deployments', 'argocd-repo-server'), ('deployments', 'argocd-redis'),
                    ('deployments', 'argocd-applicationset-controller'), ('statefulsets', 'argocd-application-controller')]),
                'four pinned runtime controllers', 420)
            default_project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
                'metadata': {'name': 'default', 'namespace': 'argocd'}, 'spec': {'sourceRepos': [],
                    'destinations': [], 'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': []}}
            if api.absent(runtime_path(default_project)):
                apply(default_project)
            runtime_core_state(api.request)
            apply({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': RUNTIME_NAMESPACE}})
            owner_project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
                'metadata': {'name': 'runtime-owner', 'namespace': 'argocd'}, 'spec': {'sourceRepos': [RUNTIME_OWNER],
                    'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}],
                    'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [{'group': 'argoproj.io', 'kind': kind}
                        for kind in ('Application', 'AppProject', 'ApplicationSet')]}}
            apply(owner_project)
            root = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
                'metadata': {'name': 'cloudlab-public-root', 'namespace': 'argocd'}, 'spec': {
                    'project': 'runtime-owner', 'source': {'repoURL': RUNTIME_OWNER, 'targetRevision': 'main', 'path': 'runtime-root'},
                    'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
                    'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                        'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}
            apply(root)
            root_path = runtime_path(root)
            wait(lambda: runtime_current(api.request(root_path), owner_source.revision), 'old direct parent through actual Root owner')
            runtime_root_policy(api.request(root_path), root['spec'], owned[root_path]['identity']['uid'])
            parent = remember(api.request(APPS + RUNTIME_PARENT))
            require(parent['spec'] == old_parent['spec'] and not parent['metadata'].get('ownerReferences')
                    and parent['metadata'].get('annotations', {}).get('argocd.argoproj.io/skip-reconcile') == 'true'
                    and not any(key in parent['metadata'].get('annotations', {}) for key in
                        ('argocd.argoproj.io/compare-options', 'argocd.argoproj.io/sync-options')),
                    'Old direct parent was pre-protected or changed')
            parent_uid = parent['metadata']['uid']
            for project in projects: remember(api.request(runtime_path(project)))
            paused = runtime_expected(public.revision, private_inputs, True)
            old_markers = {}
            for obj in paused:
                held = copy.deepcopy(obj)
                held['metadata']['annotations'] = {'argocd.argoproj.io/skip-reconcile': 'true'}
                path = runtime_path(held)
                require(api.absent(path), 'Old fixture child unexpectedly exists')
                remember(api.request(path + '?fieldManager=fixture-foreign-hold&force=false', 'PATCH', held, expected=201))
                component = 'configuration' if obj['metadata']['name'] == RUNTIME_NAMESPACE else obj['metadata']['name'].removeprefix('cloudlab-')
                marker = apply({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
                    'name': 'handoff-marker-' + component, 'namespace': RUNTIME_NAMESPACE}, 'data': {'legacy': 'old'}})
                old_markers[obj['metadata']['name']] = (runtime_path(marker), marker['metadata']['uid'], marker['data'])
            runtime_root_policy(api.request(root_path), root['spec'], owned[root_path]['identity']['uid'])
            owner_source.commit({'runtime-root/objects.yaml': yaml.safe_dump_all(selected)})
            native_set = next(obj for obj in selected if obj['kind'] == 'ApplicationSet')
            set_path = runtime_path(native_set)
            def adopted():
                runtime_root_policy(api.request(root_path), root['spec'], owned[root_path]['identity']['uid'])
                current_set, current = api.request(set_path), api.request(APPS + RUNTIME_PARENT)
                require(current['metadata']['uid'] == parent_uid, 'ApplicationSet transition replaced direct parent')
                owners = current['metadata'].get('ownerReferences', [])
                return (current_set['spec'] == native_set['spec'] and len(owners) == 1
                    and owners[0] == {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': RUNTIME_PARENT,
                        'uid': current_set['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}
                    and current['spec']['sources'][1]['targetRevision'] == accepted_revision
                    and current['metadata'].get('annotations', {}).get('argocd.argoproj.io/compare-options') == 'IgnoreExtraneous'
                    and current['metadata']['annotations'].get('argocd.argoproj.io/sync-options') == 'Prune=false,Delete=false'
                    and current['metadata']['annotations'].get('argocd.argoproj.io/skip-reconcile') == 'true'
                    and current['spec']['syncPolicy']['automated']['enabled'] is False
                    and current.get('operation') is None and current.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating')
                    and current)
            parent = wait(adopted, 'accepted native Set preserves direct-parent UID', 420)
            remember(api.request(set_path))
            wait(lambda: runtime_current(api.request(root_path), owner_source.revision), 'same Root ignores protected generated parent')
            parent = api.request(APPS + RUNTIME_PARENT)
            installed_set = api.request(set_path)
            manifests = runtime_manifest_read(api, directory, document, parent, paused, native_set, installed_set)
            for desired in manifests:
                current = api.request(runtime_path(desired))
                require(runtime_identity(current) == owned[runtime_path(desired)]['identity']
                        and current['spec'] == desired['spec'] and current.get('operation') is None
                        and current.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating'),
                        'Paused child changed before complete adoption')
                patches = [{'op': 'test', 'path': '/metadata/uid', 'value': current['metadata']['uid']},
                    {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
                    {'op': 'test', 'path': '/spec', 'value': current['spec']},
                    {'op': 'replace', 'path': '/spec', 'value': desired['spec']},
                    {'op': 'replace', 'path': '/metadata/annotations', 'value': desired['metadata']['annotations']}]
                api.request(runtime_path(desired), 'PATCH', patches, content_type='application/json-patch+json')
            held_until = time.monotonic() + 12
            while time.monotonic() < held_until:
                for desired in paused:
                    actual = api.request(runtime_path(desired))
                    marker_path, marker_uid, old_data = old_markers[desired['metadata']['name']]
                    marker = api.request(marker_path)
                    require(runtime_identity(actual) == owned[runtime_path(desired)]['identity']
                        and actual['spec'] == desired['spec']
                        and actual['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'] == 'true'
                        and actual.get('operation') is None and actual.get('status', {}).get('operationState', {}).get('phase') not in ('Running', 'Terminating')
                        and marker['metadata']['uid'] == marker_uid and marker['data'] == old_data,
                        'Paused adoption reconciled a child or marker')
                time.sleep(1)
            active = runtime_root_objects(public.revision, private.revision, receipt, False)
            active_set = next(obj for obj in active if obj['kind'] == 'ApplicationSet')
            expected_active_parent = copy.deepcopy(parent['spec'])
            expected_active_parent['sources'][0]['helm']['valuesObject']['nativeSource']['paused'] = False
            expected_active_parent['syncPolicy']['automated'].update(enabled=True, selfHeal=True)
            runtime_root_policy(api.request(root_path), root['spec'], owned[root_path]['identity']['uid'])
            owner_source.commit({'runtime-root/objects.yaml': yaml.safe_dump_all(active)})
            active_expected = runtime_expected(public.revision, private_inputs, False)
            release_diagnostic = {}
            def released():
                return runtime_released(api, root_path, root, parent_uid, set_path, active_set, expected_active_parent,
                    owner_source, public, accepted_revision, active_expected, owned, old_markers, release_diagnostic)
            runtime_release_wait(wait, released, release_diagnostic)
            marker_path, marker_uid, _ = old_markers[RUNTIME_NAMESPACE]
            marker = api.request(marker_path)
            api.request(marker_path, 'PATCH', [
                {'op': 'test', 'path': '/metadata/uid', 'value': marker_uid},
                {'op': 'test', 'path': '/metadata/resourceVersion', 'value': marker['metadata']['resourceVersion']},
                {'op': 'replace', 'path': '/data/value', 'value': 'fixture-drift'}], content_type='application/json-patch+json')
            wait(lambda: api.request(marker_path).get('data', {}).get('value') == 'native'
                and api.request(marker_path)['metadata']['uid'] == marker_uid, 'released native child repairs owned marker drift')
            success = True
        finally:
            operation_deadline[0] = deadline
            try:
                order = [('Application', 'cloudlab-public-root'), ('ApplicationSet', RUNTIME_PARENT), ('Application', RUNTIME_PARENT)]
                for kind, name in order:
                    for path, row in list(owned.items()):
                        if row['kind'] == kind and row['identity']['name'] == name: remove(path)
                for kind in ('Application', 'ConfigMap', 'NetworkPolicy', 'AppProject'):
                    for path, row in list(owned.items()):
                        if row['kind'] == kind: remove(path)
                # Namespace deletion is left to the coordinating parent's exact Docker
                # lifecycle if any unrecorded native resources remain.
                namespace_path = '/api/v1/namespaces/' + RUNTIME_NAMESPACE
                if namespace_path in owned and not api.absent(namespace_path):
                    remaining = []
                    versions = ['/api/v1'] + ['/apis/' + row['preferredVersion']['groupVersion']
                        for row in api.request('/apis')['groups']]
                    for version in versions:
                        for resource in api.request(version)['resources']:
                            if resource.get('namespaced') and 'list' in resource.get('verbs', []) and '/' not in resource['name']:
                                remaining.extend(runtime_cleanup_rows(version, resource, api.request))
                    for obj in remaining:
                        require((obj['kind'], obj['metadata']['name']) in {('ConfigMap', 'kube-root-ca.crt'), ('ServiceAccount', 'default')}
                                and not obj['metadata'].get('ownerReferences') and not obj['metadata'].get('finalizers'),
                                'Unknown namespace resource blocks fixture cleanup')
                    current = api.request(namespace_path)
                    require(runtime_identity(current) == owned[namespace_path]['identity'], 'Fixture namespace replaced')
                    api.request(namespace_path, 'DELETE', {'apiVersion': 'v1', 'kind': 'DeleteOptions', 'preconditions': {
                        'uid': current['metadata']['uid'], 'resourceVersion': current['metadata']['resourceVersion']}})
                    wait(lambda: api.absent(namespace_path), 'exact fixture namespace cleanup', 120)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
        require(success and all(api.absent(path) for path in owned), 'Runtime fixture cleanup is incomplete')
        print(json.dumps({'runtimeHandoff': 'passed', 'parentUIDPreserved': True, 'sixChildUIDsPreserved': True,
            'pausedNativeManifests': True, 'explicitGitRelease': True, 'driftRepair': True,
            'cleanup': 'complete', 'scope': 'disposable controller ownership only; production transport unsupported'}, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument('--runtime-handoff', action='store_true')
        arguments = parser.parse_args()
        runtime_handoff() if arguments.runtime_handoff else run()
    except Exception as error:
        # Never print credentials, API response bodies or subprocess output.
        print(str(error) if isinstance(error, RuntimeError) else 'Lifecycle fixture failed: ' + type(error).__name__, flush=True)
        raise SystemExit(1) from None
