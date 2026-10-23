import copy
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from playbooks.rollouts.files.check import check, ROOT
from playbooks.rollouts.files.remote import owned
from playbooks.rollouts.tests.fixtures import definition, objects
from playbooks.rollouts.tests.proof import traffic_result
from playbooks.services.files.contract import render, validate
from playbooks.services.files.gitops import resources


class RolloutsTests(TestCase):
    def test_controller_artifact_images_and_plugin_are_pinned_without_secret_access(self):
        self.assertTrue(check()['pinned_plugin_checksum'])

    def test_analysis_is_per_revision_fail_closed_and_uses_accepted_baseline(self):
        value = definition()
        rendered = render(validate(value))
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
        self.assertTrue({'Rollout', 'AnalysisTemplate', 'ServiceMonitor'} <= kinds)
        self.assertFalse({'ReplicaSet', 'AnalysisRun', 'Secret'} & kinds)
        template = next(o for o in rendered if o['kind'] == 'ApplicationSet')['spec']['template']['spec']
        self.assertIn('RespectIgnoreDifferences=true', template['syncPolicy']['syncOptions'])
        ignore = template['ignoreDifferences']
        self.assertEqual(len(ignore), 3)
        self.assertTrue(ignore[0]['jqPathExpressions'][0].endswith('| .weight'))
        self.assertTrue(all(o['jsonPointers'] == ['/spec/selector/rollouts-pod-template-hash'] for o in ignore[1:]))

    def test_traffic_split_evidence_rejects_wrong_weights_missing_unknown_or_dropped(self):
        good = {'stable_samples': 355, 'canary_samples': 365, 'unknown_revision': 0, 'dropped_iterations': 0}
        for change in ({}, {'stable_samples': 700, 'canary_samples': 20}, {'canary_samples': 0},
                       {'unknown_revision': 1}, {'dropped_iterations': 1}):
            document = dict(good, **change)
            process = Mock(returncode=0)
            process.communicate.return_value = (json.dumps(document), '')
            if change:
                with self.assertRaises(RuntimeError):
                    traffic_result(process)
            else:
                self.assertEqual(traffic_result(process), good)

    def test_foreign_disposable_owner_refuses_mutation(self):
        with self.assertRaises(RuntimeError):
            owned({'metadata': {'labels': {}}}, 'a' * 32)

    def test_new_rollout_with_no_analysis_runs_has_a_readable_snapshot(self):
        from playbooks.rollouts.files.remote import snapshot
        def get(kind, *_args, **_kwargs):
            if kind == 'rollout.argoproj.io':
                return {'metadata': {'uid': 'fixture'}, 'status': {'phase': 'Healthy', 'currentPodHash': 'new'}}
            return None
        with patch('playbooks.rollouts.files.remote.get', side_effect=get):
            self.assertEqual(snapshot()['current'], 'new')
            self.assertIsNone(snapshot()['analysis'])

    def test_fixture_has_no_persistence_credentials_or_broad_project(self):
        rows = objects('https://github.com/example/platform.git', 'a' * 40, 'test.internal.example.invalid')
        self.assertFalse({'Secret', 'PersistentVolumeClaim'} & {o['kind'] for o in rows})
        project = next(o for o in rows if o['kind'] == 'AppProject')
        self.assertEqual(project['spec']['clusterResourceWhitelist'], [])
        self.assertEqual(project['spec']['destinations'][0]['namespace'], 'cloudlab-app-rollouts-proof')

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
