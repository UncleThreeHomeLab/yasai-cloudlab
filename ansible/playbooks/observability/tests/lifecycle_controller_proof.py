"""Disposable Argo controller proof; synthetic workloads, never a stack qualification."""
import functools
import json
import os
from pathlib import Path
import tempfile
import threading
import time

import yaml

from playbooks.argocd.tests.fixtures import (
    GitServer, GitSource, NativeAPI, ReadOnlyGit, install_argocd, require)

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


if __name__ == '__main__':
    try:
        run()
    except Exception as error:
        # Never print credentials, API response bodies or subprocess output.
        print(str(error) if isinstance(error, RuntimeError) else 'Lifecycle fixture failed: ' + type(error).__name__, flush=True)
        raise SystemExit(1) from None
