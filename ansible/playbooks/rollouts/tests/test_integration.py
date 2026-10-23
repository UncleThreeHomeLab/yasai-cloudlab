import copy
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import Mock, patch

from playbooks.rollouts.files.check import check, ROOT
from playbooks.rollouts.tests.fixtures import definition
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
