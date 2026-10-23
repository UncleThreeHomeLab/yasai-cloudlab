import copy
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from playbooks.rollouts.files.check import check, ROOT
from playbooks.rollouts.files.remote import owned
from playbooks.rollouts.tests.fixtures import definition, objects
from playbooks.rollouts.tests.proof import analysis_result, traffic_result
from playbooks.services.files.contract import render, validate
from playbooks.services.files.gitops import resources


class RolloutsTests(TestCase):
    def test_controller_artifact_images_and_plugin_are_pinned_without_application_secret_access(self):
        self.assertTrue(check()['pinned_plugin_checksum'])

    def test_platform_monitor_uses_watched_namespace_and_trusted_revision_labels(self):
        import yaml
        monitor = yaml.safe_load((ROOT / 'platform/delivery/rollouts/templates/monitor.yaml').read_text())
        self.assertEqual(monitor['metadata']['namespace'], 'cloudlab-observability')
        self.assertEqual(monitor['spec']['selector']['matchLabels'], {'cloudlab.io/release-analysis': 'approved'})
        endpoint = monitor['spec']['podMetricsEndpoints'][0]
        self.assertEqual(endpoint['port'], 'http-metrics')
        self.assertEqual(endpoint['relabelings'][1]['targetLabel'], 'revision')
        self.assertEqual(endpoint['relabelings'][2]['targetLabel'], 'service')
        self.assertEqual(monitor['spec']['targetLimit'], 8)

    def test_exporter_http_protocol_and_missing_low_sample_and_fault_fixtures(self):
        import importlib.util
        import os
        import threading
        import urllib.request
        import urllib.error
        spec = importlib.util.spec_from_file_location('rollouts_exporter', Path(__file__).with_name('server.py'))
        exporter = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {'CLOUDLAB_REVISION': 'fixture-revision'}):
            spec.loader.exec_module(exporter)
        server = exporter.ThreadingHTTPServer(('127.0.0.1', 0), exporter.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = 'http://127.0.0.1:' + str(server.server_port)
        request = urllib.request.Request(origin + '/canary-proof', headers={'User-Agent': 'CloudLab-Release-Proof/1.0'})
        try:
            with urllib.request.urlopen(origin + '/metrics', timeout=5) as response:
                self.assertEqual(response.headers['Content-Type'], 'text/plain; version=0.0.4; charset=utf-8')
                self.assertIn(b'status="503"} 0', response.read())
            with urllib.request.urlopen(request, timeout=5) as response:
                self.assertEqual(response.headers['X-CloudLab-Revision'], 'fixture-revision')
            self.assertEqual(exporter.COUNTS['200'], 1)
            exporter.MODE = 'low-samples'
            with urllib.request.urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)
            self.assertEqual(exporter.COUNTS['200'], 1)
            exporter.MODE = 'missing'
            with urllib.request.urlopen(origin + '/metrics', timeout=5) as response:
                self.assertEqual(response.read(), b'')
                self.assertIn('version=0.0.4', response.headers['Content-Type'])
            exporter.MODE = 'faulty'
            with self.assertRaises(urllib.error.HTTPError) as failure:
                urllib.request.urlopen(request, timeout=5)
            self.assertEqual(failure.exception.code, 503)
            failure.exception.close()
            self.assertEqual(exporter.COUNTS['503'], 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_analysis_is_per_revision_fail_closed_and_uses_accepted_baseline(self):
        value = definition()
        rendered = render(validate(value))
        route = next(o for o in rendered if o['kind'] == 'HTTPRoute')
        self.assertEqual(route['spec']['parentRefs'][0]['kind'], 'Gateway')
        self.assertTrue(all(b['group'] == '' and b['kind'] == 'Service' for b in route['spec']['rules'][0]['backendRefs']))
        self.assertNotIn('Deployment', {o['kind'] for o in rendered})
        rollout = next(o for o in rendered if o['kind'] == 'Rollout')
        self.assertEqual(rollout['spec']['strategy']['canary']['trafficRouting']['plugins'], {
            'argoproj-labs/gatewayAPI': {'namespace': 'cloudlab-service-proof', 'disableInProgressLabel': True,
                                       'httpRoutes': [{'name': value['name']}]}})
        analysis = next(o for o in rendered if o['kind'] == 'AnalysisTemplate')['spec']
        accepted = json.loads((ROOT / 'charts/service/release-policy.json').read_text())
        from playbooks.observability.files.slo import definition as slo
        self.assertTrue(accepted.items() <= slo()['release'].items())
        for metric in analysis['metrics']:
            self.assertEqual(metric['initialDelay'], str(accepted['duration_seconds'] + 10) + 's')
            self.assertEqual((metric['count'], metric['failureLimit'], metric['consecutiveErrorLimit'], metric['inconclusiveLimit']), (1, 0, 0, 0))
            for guard in ('len(result) == 1', '!isNaN(result[0])', '!isInf(result[0])'):
                self.assertIn(guard, metric['successCondition'])
            self.assertIn('revision="{{args.revision}}"', metric['provider']['prometheus']['query'])
            self.assertIn('namespace="cloudlab-service-proof"', metric['provider']['prometheus']['query'])
            if metric['name'] != 'scrape-health':
                self.assertIn('traffic="release"', metric['provider']['prometheus']['query'])
            self.assertNotIn('or vector', metric['provider']['prometheus']['query'])
        self.assertTrue(any('>= 230' in m['successCondition'] for m in analysis['metrics']))

    def test_unsafe_stateful_uninstrumented_and_reserved_revision_inputs_refuse(self):
        for mutate in (lambda v: v['persistence'].update(enabled=True),
                       lambda v: v.update(exposure={'class': 'none'}),
                       lambda v: v['ports'].pop(),
                       lambda v: v['environment'].update(CLOUDLAB_REVISION='forged')):
            value = definition()
            mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate(value)

    def test_catalog_delegates_only_weight_and_selector_fields(self):
        value = definition()
        approval = {'name': 'release-proof', 'namespace': 'cloudlab-app-release-proof',
                    'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
                    'valuesPath': 'apps/synthetic.yaml', 'secretReferences': [], 'configMaps': []}
        rendered = resources(value, approval, approval['repository'], 'a' * 40)
        project = next(o for o in rendered if o['kind'] == 'AppProject')
        kinds = {r['kind'] for r in project['spec']['namespaceResourceWhitelist']}
        self.assertTrue({'Rollout', 'AnalysisTemplate'} <= kinds)
        self.assertFalse({'ReplicaSet', 'AnalysisRun', 'Secret', 'ServiceMonitor', 'PodMonitor'} & kinds)
        template = next(o for o in rendered if o['kind'] == 'ApplicationSet')['spec']['template']['spec']
        self.assertIn('RespectIgnoreDifferences=true', template['syncPolicy']['syncOptions'])
        ignore = template['ignoreDifferences']
        self.assertEqual(len(ignore), 3)
        self.assertTrue(ignore[0]['jqPathExpressions'][0].endswith('| .weight'))
        self.assertTrue(all(o['jsonPointers'] == ['/spec/selector/rollouts-pod-template-hash'] for o in ignore[1:]))

    def test_traffic_split_evidence_rejects_wrong_weights_missing_unknown_or_dropped(self):
        good = {'stable_samples': 355, 'canary_samples': 365, 'unknown_revision': 0, 'dropped_iterations': 0}
        for change in ({}, {'stable_samples': 700, 'canary_samples': 20}, {'canary_samples': 0},
                       {'stable_samples': 288, 'canary_samples': 432}, {'canary_samples': float('nan')},
                       {'unknown_revision': 1}, {'dropped_iterations': 1}):
            document = dict(good, **change)
            process = Mock(returncode=0)
            process.communicate.return_value = (json.dumps(document), '')
            if change:
                with self.assertRaises(RuntimeError):
                    traffic_result(process)
            else:
                self.assertEqual(traffic_result(process), good)

    def test_negative_fixtures_must_establish_their_actual_failure_cause(self):
        state = {'analysis_phase': 'Successful', 'metrics': [
            {'name': name, 'phase': 'Successful', 'values': [value]} for name, value in (
                ('samples', '[300]'), ('errors', '[0]'), ('maximum', '[0.1]'), ('p95', '[0.01]'), ('scrape-health', '[1]'))]}
        self.assertEqual(analysis_result('healthy', state, {'failed_samples': 0}), 300)
        with self.assertRaises(RuntimeError):
            analysis_result('faulty', state, {'failed_samples': 10})
        faulty = copy.deepcopy(state)
        faulty['metrics'][1].update(phase='Failed', values=['[1]'])
        self.assertEqual(analysis_result('faulty', faulty, {'failed_samples': 10}), 300)
        missing = copy.deepcopy(state)
        missing['metrics'][0].update(phase='Failed', values=['[]'])
        self.assertIsNone(analysis_result('missing', missing, {'failed_samples': 0}))
        missing['metrics'][-1].update(phase='Failed', values=['[0]'])
        with self.assertRaises(RuntimeError):
            analysis_result('missing', missing, {'failed_samples': 0})

    def test_foreign_disposable_owner_refuses_mutation(self):
        with self.assertRaises(RuntimeError):
            owned({'metadata': {'labels': {}}}, 'a' * 32)

    def test_repeated_cleanup_of_absent_fixture_is_a_noop(self):
        from playbooks.rollouts.files import remote
        with patch.object(remote, 'get', return_value=None), patch.object(remote, 'kube') as kube:
            self.assertEqual(remote.run({'nonce': 'a' * 32, 'action': 'cleanup'}), {'fixture_removed': True})
            kube.assert_not_called()

    def test_new_rollout_with_no_analysis_runs_has_a_readable_snapshot(self):
        from playbooks.rollouts.files.remote import snapshot
        def get(kind, *_args, **_kwargs):
            if kind == 'rollout.argoproj.io':
                return {'metadata': {'uid': 'fixture'}, 'status': {'phase': 'Healthy', 'currentPodHash': 'new'}}
            return None
        with patch('playbooks.rollouts.files.remote.get', side_effect=get):
            self.assertEqual(snapshot()['current'], 'new')
            self.assertIsNone(snapshot()['analysis'])

    def test_signed_prerequisite_uses_native_ready_conditions_and_accepted_owners(self):
        from datetime import datetime, timezone
        from playbooks.rollouts.files import remote
        image = 'registry.example.invalid/cloudlab-public/notes@sha256:' + 'a' * 64
        metadata = {'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-services:owned'}}
        status = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
        policy = {'metadata': copy.deepcopy(metadata), 'status': status,
                  'spec': {'validationFailureAction': 'Enforce', 'rules': [{'verifyImages': [
                      {'imageReferences': ['registry.example.invalid/cloudlab-public/notes@sha256:*']}]}]}}
        delivery = {'metadata': metadata, 'status': status,
                    'spec': {'dataFrom': [{'extract': {'key': 'harbor-cloudlab-public-pull'}}]}}
        def get(kind, name=None, namespace=None):
            if kind.startswith('lease.'):
                return {'spec': {'holderIdentity': 'controller', 'renewTime': datetime.now(timezone.utc).isoformat()}}
            if kind == 'configmap':
                return {'data': {'trafficRouterPlugins': 'pinned-checksum'}}
            if kind == 'deployment':
                return {'spec': {'template': {'spec': {'containers': [{'image': 'controller-image'}]}}}}
            if kind == 'deployments':
                return {'items': [{'metadata': {'name': 'notes-api', 'uid': 'retained'},
                                   'spec': {'template': {'spec': {'containers': [{'image': image}]}}}}]}
            if kind == 'httproute':
                return {'items': [{'spec': {'parentRefs': [{'namespace': 'cloudlab-gateway-private'}],
                                           'hostnames': ['notes.internal.example.invalid']}}]}
            if kind == 'service':
                return {'spec': {'clusterIP': '192.0.2.1'}}
            if kind.startswith('policy.'):
                return policy
            if kind.startswith('externalsecret.'):
                return delivery
            raise AssertionError(kind)
        request = {'nonce': 'a' * 32, 'action': 'prerequisites', 'revision': 'b' * 40,
                   'controller_image': 'controller-image', 'plugin_sha256': 'pinned-checksum'}
        with patch.object(remote, 'get', side_effect=get), patch.object(remote, 'application_ready', return_value=True), \
                patch.object(remote, 'kube', return_value=Mock(returncode=1, stdout='no')):
            self.assertEqual(remote.run(request)['artifact']['image'], image)
            policy['metadata']['annotations'] = {}
            with self.assertRaises(RuntimeError):
                remote.run(request)

    def test_fixture_has_no_persistence_credentials_or_broad_project(self):
        rows = objects('https://github.com/example/platform.git', 'a' * 40, 'test.internal.example.invalid')
        self.assertFalse({'Secret', 'PersistentVolumeClaim'} & {o['kind'] for o in rows})
        project = next(o for o in rows if o['kind'] == 'AppProject')
        self.assertEqual(project['spec']['clusterResourceWhitelist'], [])
        self.assertEqual(project['spec']['destinations'][0]['namespace'], 'cloudlab-app-rollouts-proof')

    def test_live_fixture_reuses_signed_artifact_and_only_eso_owned_pull_delivery(self):
        artifact = {'image': 'registry.example.invalid/cloudlab-public/notes@sha256:' + 'a' * 64,
                    'policy_hash': 'b' * 64, 'policy': {'validationFailureAction': 'Enforce', 'rules': []},
                    'delivery': {'target': {'name': 'harbor-application-pull', 'creationPolicy': 'Owner'},
                                 'dataFrom': [{'extract': {'key': 'harbor-cloudlab-public-pull'}}]}}
        before = copy.deepcopy(artifact)
        rows = objects('https://github.com/example/platform.git', 'a' * 40, 'test.internal.example.invalid', artifact)
        app = next(o for o in rows if o['kind'] == 'Application')
        value = app['spec']['source']['helm']['valuesObject']
        validate(value)
        self.assertEqual(value['image'], artifact['image'])
        self.assertEqual(value['secrets'], [])
        self.assertEqual(next(o for o in rows if o['kind'] == 'ExternalSecret')['spec'], artifact['delivery'])
        self.assertEqual(next(o for o in rows if o['kind'] == 'Policy')['spec'], artifact['policy'])
        self.assertFalse({'Secret', 'PersistentVolumeClaim'} & {o['kind'] for o in rows})
        self.assertEqual(artifact, before)

    def test_rollout_and_analysis_match_the_pinned_controller_schemas(self):
        import subprocess
        import yaml
        import jsonschema
        raw = subprocess.check_output(['helm', 'template', 'argo-rollouts',
                                       str(ROOT / 'platform/delivery/rollouts'), '--include-crds'], timeout=90)
        schemas = {o['spec']['names']['kind']: o['spec']['versions'][0]['schema']['openAPIV3Schema']
                   for o in yaml.safe_load_all(raw) if o and o['kind'] == 'CustomResourceDefinition'}
        for obj in render(definition()):
            if obj['kind'] in schemas:
                jsonschema.validate(obj, schemas[obj['kind']])

    def test_signed_release_application_keeps_exact_digest_and_enforcement_boundary(self):
        value = definition()
        approval = {'name': 'release-proof', 'namespace': 'cloudlab-app-release-proof',
                    'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
                    'valuesPath': 'apps/synthetic.yaml', 'secretReferences': [], 'configMaps': [],
                    'artifact': {'repository': 'registry.example.invalid/cloudlab-public/release-proof',
                                 'project': 'cloudlab-public', 'releasePath': 'apps/releases/release-proof.json',
                                 'sourceRepository': 'example/producer', 'action': 'Enforce',
                                 'identities': ['https://github.com/example/producer/.github/workflows/ci.yaml@refs/heads/main']}}
        rendered = resources(value, approval, approval['repository'], 'a' * 40)
        appset = next(o for o in rendered if o['kind'] == 'ApplicationSet')['spec']
        self.assertEqual(appset['generators'][0]['git']['files'], [{'path': 'apps/releases/release-proof.json'}])
        desired = appset['template']['spec']['source']['helm']['valuesObject']
        self.assertEqual(desired['image'], 'registry.example.invalid/cloudlab-public/release-proof@{{ .digest }}')
        self.assertTrue(desired['rollouts']['enabled'])
        self.assertEqual(desired['imagePullSecrets'], [{'name': 'harbor-application-pull'}])
        policy = next(o for o in rendered if o['kind'] == 'Policy')
        self.assertEqual(policy['spec']['validationFailureAction'], 'Enforce')
