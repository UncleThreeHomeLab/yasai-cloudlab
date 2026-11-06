"""Synthetic native phase rendering; qualification references never authorize live use."""
import copy
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

from playbooks.observability.tests.fixtures import notification_inputs

ROOT = Path(__file__).resolve().parents[4]
REGISTRY = Path('platform/observability/gitops/handoff-profiles.json')
PHASES = ('baseline', 'maintenance', 'persistent-maintenance', 'persistent-normal',
          'native-paused', 'native')
ANNOTATIONS = ('cloudlab.io/observability-handoff-operation',
               'cloudlab.io/observability-handoff-phase',
               'cloudlab.io/observability-handoff-baseline',
               'cloudlab.io/observability-handoff-target-cluster-uid')
TARGET_UID = '11111111-2222-4333-8444-555555555555'


class HandoffPhasesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        shutil.copytree(ROOT / 'platform/observability', cls.root / 'platform/observability')
        cls.registry = json.loads((cls.root / REGISTRY).read_text())
        cls.references = {name: {'version': version, 'profile': name, 'codeRevision': 'a' * 40,
            'moduleDigests': {'synthetic-module': '1' * 64},
            'artifactDigests': {'synthetic-proof': '2' * 64},
            'imagePins': {'synthetic': 'example.invalid/fixture@sha256:' + '3' * 64}}
            for name, version in cls.registry['requiredProfiles'].items()}
        cls.references['handoff']['scope'] = {'kind': 'full-entrypoint-integration'}
        cls.references['handoff']['artifactDigests']['handoff-evidence.json'] = '2' * 64
        cls.registry['acceptedArtifacts'] = cls.references
        (cls.root / REGISTRY).write_text(json.dumps(cls.registry))

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def helm(self, chart, values, *, root=None, valid=True, release='fixture', raw=False, include_crds=False):
        root = self.root if root is None else root
        path = root / chart
        arguments = ['helm', 'template', release, str(path), '--kube-version', '1.36.5',
                     '--namespace', 'argocd' if chart.endswith('/gitops') else 'cloudlab-observability']
        if include_crds:
            arguments.append('--include-crds')
        if (path / 'values.json').is_file():
            arguments += ['-f', str(path / 'values.json')]
        result = subprocess.run(arguments + ['-f', '-'], input=yaml.safe_dump(values),
                                capture_output=True, text=True, timeout=90)
        if not valid:
            self.assertNotEqual(result.returncode, 0, 'Unsafe phase input unexpectedly rendered')
            return result.stderr
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout if raw else [obj for obj in yaml.safe_load_all(result.stdout) if obj]

    def inputs(self, phase='baseline'):
        values = notification_inputs()
        values['nativeSource']['activationQualification'] = '2' * 64
        apps = self.helm('platform/observability/gitops', values)
        baselines = {app['metadata']['name']: app for app in apps}
        for app in baselines.values():
            app['spec']['source']['targetRevision'] = 'b' * 40
        alertmanager = baselines['cloudlab-prometheus']['spec']['source']['helm']['valuesObject']['kube-prometheus-stack']['alertmanager']
        baselines['cloudlab-prometheus']['spec']['source']['helm']['valuesObject']['kube-prometheus-stack']['cloudlabNativeLifecycle'] = False
        alertmanager['alertmanagerSpec']['storage'] = {'emptyDir': {'sizeLimit': '64Mi'}}
        alertmanager['alertmanagerSpec'].pop('persistentVolumeClaimRetentionPolicy')
        values['ownershipHandoff'] = {'version': 'cloudlab-observability-handoff/v1',
            'operationId': '0123456789abcdef', 'phase': phase,
            'targetClusterUID': TARGET_UID,
            'baselineApplications': baselines, 'qualifications': copy.deepcopy(self.references),
            'approvedStorageTarget': 'alertmanager-retained-1gi-v1'}
        return values

    def applications(self, values):
        values = copy.deepcopy(values)
        values['nativeSource'].setdefault('activationQualification', '2' * 64)
        return {app['metadata']['name']: app for app in self.helm('platform/observability/gitops', values)}

    def test_absent_handoff_preserves_native_bytes(self):
        values = notification_inputs()
        values['nativeSource']['activationQualification'] = '2' * 64
        output = self.helm('platform/observability/gitops', values, raw=True)
        self.assertEqual(hashlib.sha256(output.encode()).hexdigest(),
                         '4dd8ecd160cb0c14a667073112c61138a835d6a2a9b4d0db44fbe795c0d13e34')
        storage_line = '                storage:\n'
        self.assertEqual(output.count(storage_line), 1)
        original = output.replace(storage_line, storage_line + '                  emptyDir: null\n')
        self.assertEqual(hashlib.sha256(original.encode()).hexdigest(),
                         '46cbf0dac3513e821050b6db6c0c85c49fb4674434ea4478023757e7ea3c88ac')
        application = next(app for app in yaml.safe_load_all(output) if app and app['metadata']['name'] == 'cloudlab-observability')
        configuration = self.helm('platform/observability', application['spec']['source']['helm']['valuesObject'],
                                  root=ROOT, release='cloudlab-observability', raw=True)
        self.assertEqual(hashlib.sha256(configuration.encode()).hexdigest(),
                         '9ac6e57c9b76af0be8e37ba76cf6a923aa0ad919f04ab4d70dc83ef13f5a1d71')

    def test_persistent_inline_storage_omits_null_without_changing_native_prometheus_render(self):
        applications = []
        for paused in (False, True):
            values = notification_inputs()
            values['nativeSource']['paused'] = paused
            applications.append(self.applications(values)['cloudlab-prometheus'])
        for phase in ('persistent-maintenance', 'persistent-normal', 'native-paused', 'native'):
            applications.append(self.applications(self.inputs(phase))['cloudlab-prometheus'])
        checked = set()
        for app in applications:
            values = app['spec']['source']['helm']['valuesObject']
            stack = values['kube-prometheus-stack']
            self.assertIs(stack['cloudlabNativeLifecycle'], True)
            self.assertEqual(set(stack['alertmanager']['alertmanagerSpec']['storage']), {'volumeClaimTemplate'})
            identity = json.dumps(values, sort_keys=True)
            if identity in checked:
                continue
            checked.add(identity)
            original = copy.deepcopy(values)
            original['kube-prometheus-stack']['alertmanager']['alertmanagerSpec']['storage']['emptyDir'] = None
            arguments = {'release': 'cloudlab-prometheus', 'raw': True, 'include_crds': True}
            self.assertEqual(self.helm('platform/observability/prometheus', original, **arguments),
                             self.helm('platform/observability/prometheus', values, **arguments))

    def test_unqualified_registry_and_foreign_references_block_every_phase(self):
        values = self.inputs()
        error = self.helm('platform/observability/gitops', values, root=ROOT, valid=False)
        self.assertIn('lacks matching reviewed native qualification', error)
        values['ownershipHandoff']['qualifications']['storage']['artifactDigests']['synthetic-proof'] = '4' * 64
        self.helm('platform/observability/gitops', values, valid=False)

    def test_scope_target_and_activation_remain_required_without_handoff(self):
        values = notification_inputs()
        values['nativeSource']['paused'] = False
        self.helm('platform/observability/gitops', values, valid=False)
        values['nativeSource']['activationQualification'] = '2' * 64
        self.assertEqual(len(self.helm('platform/observability/gitops', values)), 6)
        for pointer in ('0' * 64, '4' * 64, None):
            invalid = copy.deepcopy(values)
            invalid['nativeSource']['activationQualification'] = pointer
            self.helm('platform/observability/gitops', invalid, valid=False)
        handoff = self.inputs('native-paused')
        mechanism = copy.deepcopy(self.references['handoff'])
        mechanism['scope'] = {'kind': 'mechanism-rehearsal',
                              'targetClusterUIDSHA256': hashlib.sha256(TARGET_UID.encode()).hexdigest()}
        registry = copy.deepcopy(self.registry)
        registry['acceptedArtifacts']['handoff'] = mechanism
        (self.root / REGISTRY).write_text(json.dumps(registry))
        try:
            self.helm('platform/observability/gitops', values, valid=False)
            handoff['ownershipHandoff']['qualifications']['handoff'] = copy.deepcopy(mechanism)
            rendered = self.helm('platform/observability/gitops', handoff)
            self.assertTrue(all(app['metadata']['annotations'][ANNOTATIONS[3]] == TARGET_UID for app in rendered))
            changed_target = copy.deepcopy(handoff)
            changed_target['ownershipHandoff']['targetClusterUID'] = '22222222-3333-4444-8555-666666666666'
            self.helm('platform/observability/gitops', changed_target, valid=False)
            handoff['ownershipHandoff']['phase'] = 'native'
            self.helm('platform/observability/gitops', handoff, valid=False)
            handoff['ownershipHandoff']['qualifications']['handoff']['scope'] = {'kind': 'full-entrypoint-integration'}
            self.assertIn('matching reviewed native qualification', self.helm(
                'platform/observability/gitops', handoff, valid=False))
        finally:
            (self.root / REGISTRY).write_text(json.dumps(self.registry))

    def test_public_blank_activation_overrides_private_full_native_pointer(self):
        private = self.inputs('native')
        source = private['nativeSource']
        public = {'repository': source['repository'], 'identity': {'argo': {
            'valuesRepository': source['valuesRepository'], 'valuesRevision': 'b' * 40}},
            'observability': {'configuration': {'enabled': True, 'paused': True,
                'revision': source['revision'], 'acceptanceCommitment': '1' * 64,
                'activationQualification': ''}}}
        parent = next(obj for obj in self.helm('gitops/roots/public', public, root=ROOT)
            if obj['kind'] == 'ApplicationSet' and obj['metadata']['name'] == 'cloudlab-observability-gitops')
        highest = parent['spec']['template']['spec']['sources'][0]['helm']['valuesObject']
        self.assertEqual(private['nativeSource']['activationQualification'], '2' * 64)
        self.assertEqual(highest['nativeSource']['activationQualification'], '')
        with tempfile.TemporaryDirectory() as directory:
            lower, higher = Path(directory) / 'private.yaml', Path(directory) / 'public.yaml'
            lower.write_text(yaml.safe_dump(private))
            higher.write_text(yaml.safe_dump(highest))
            result = subprocess.run(['helm', 'template', 'fixture',
                str(self.root / 'platform/observability/gitops'), '-n', 'argocd',
                '--kube-version', '1.36.5', '-f', str(lower), '-f', str(higher)],
                capture_output=True, text=True, timeout=90)
        self.assertNotEqual(result.returncode, 0, 'Private activation escaped the public empty capability')
        self.assertIn('activationQualification', result.stderr)

    def test_public_baseline_digest_helper_matches_go_escaped_phase_provenance(self):
        values = self.inputs()
        baseline = values['ownershipHandoff']['baselineApplications']
        baseline['cloudlab-prometheus']['spec']['source']['helm']['valuesObject']['serviceDashboards'] = {
            'svc-fixture.json': '{"title":"<>&\u2028\u2029"}'}
        template = self.root / 'platform/observability/gitops/templates/digest-helper-fixture.yaml'
        template.write_text('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: digest-helper-fixture}\n'
                            'data:\n  digest: {{ include "observability.handoffBaselineDigest" .Values.ownershipHandoff.baselineApplications | quote }}\n'
                            '  preimage: {{ toJson .Values.ownershipHandoff.baselineApplications | quote }}\n')
        try:
            rendered = self.helm('platform/observability/gitops', values)
        finally:
            template.unlink()
        data = next(obj for obj in rendered if obj['kind'] == 'ConfigMap')['data']
        digest, encoded = data['digest'], data['preimage']
        self.assertIn('\\u003c\\u003e\\u0026\\u2028\\u2029', encoded)
        self.assertEqual(digest, hashlib.sha256(encoded.encode()).hexdigest())
        for application in (obj for obj in rendered if obj['kind'] == 'Application'):
            self.assertEqual(application['metadata']['annotations'][ANNOTATIONS[2]], digest)

    def test_actual_legacy_application_declarations_preserve_three_sync_options(self):
        from playbooks.observability.files.bootstrap import application
        from playbooks.observability.files.payload import compile_payload
        values = self.inputs()
        payload = compile_payload({'repository': values['nativeSource']['repository'], 'revision': 'b' * 40},
                                  dict(values['observabilityInputs'], gatewayIP='192.0.2.1'))
        baseline = {app['metadata']['name']: app for app in
                    (application(payload, name) for name in ('configuration', *payload['components']))}
        values['ownershipHandoff']['baselineApplications'] = baseline
        for app in baseline.values():
            self.assertNotIn('annotations', app['metadata'])
            self.assertEqual(len(app['spec']['syncPolicy']['syncOptions']), 3)
        for phase in ('baseline', 'maintenance'):
            values['ownershipHandoff']['phase'] = phase
            for name, app in self.applications(values).items():
                self.assertEqual(app['spec']['syncPolicy']['syncOptions'], baseline[name]['spec']['syncPolicy']['syncOptions'])
                if name in ('cloudlab-loki', 'cloudlab-tempo', 'cloudlab-alloy'):
                    expected = copy.deepcopy(baseline[name]['spec'])
                    expected['syncPolicy']['automated'] = app['spec']['syncPolicy']['automated']
                    self.assertEqual(app['spec'], expected)
                    self.assertNotIn('valuesObject', app['spec']['source']['helm'])
        for phase in ('native-paused', 'native'):
            values['ownershipHandoff']['phase'] = phase
            for app in self.applications(values).values():
                self.assertEqual(app['spec']['syncPolicy']['syncOptions'], [
                    'FailOnSharedResource=true', 'ServerSideApply=true',
                    'DisableClientSideApplyMigration=true', 'PruneLast=true'])
        values['ownershipHandoff']['phase'] = 'maintenance'
        options = baseline['cloudlab-alloy']['spec']['syncPolicy']['syncOptions']
        for invalid in (options + ['PrunePropagationPolicy=foreground'],
                        ['FailOnSharedResource=true', 'ServerSideApply=false', 'DisableClientSideApplyMigration=true'],
                        list(reversed(options))):
            row = copy.deepcopy(values)
            row['ownershipHandoff']['baselineApplications']['cloudlab-alloy']['spec']['syncPolicy']['syncOptions'] = invalid
            self.helm('platform/observability/gitops', row, valid=False)

    def test_exact_baseline_and_finite_phase_controls_reject_escape_paths(self):
        original = self.inputs()
        cases = []
        for key, value in [('phase', 'shell'), ('operationId', 'wrong'), ('qualified', True),
                           ('targetClusterUID', None), ('targetClusterUID', '00000000-0000-0000-0000-000000000000'),
                           ('approvedStorageTarget', 'other-claim'), ('command', ['sh']),
                           ('manifests', [{'kind': 'Pod'}])]:
            row = copy.deepcopy(original)
            row['ownershipHandoff'][key] = value
            cases.append(row)
        row = copy.deepcopy(original)
        del row['ownershipHandoff']['baselineApplications']['cloudlab-alloy']
        cases.append(row)
        row = copy.deepcopy(original)
        row['observabilityInputs']['ownershipHandoffInternal'] = {'phase': 'maintenance'}
        cases.append(row)
        row = copy.deepcopy(original)
        row['ownershipHandoff']['baselineApplications']['cloudlab-alloy']['spec']['source']['targetRevision'] = 'c' * 40
        cases.append(row)
        for location, key, value in [('root', 'status', {}), ('metadata', 'finalizers', ['delete']),
                                     ('metadata', 'ownerReferences', []), ('metadata', 'annotations', {'other': 'value'}),
                                     ('spec', 'operation', {}), ('source', 'plugin', {'name': 'shell'}),
                                     ('helm', 'parameters', [{'name': 'image', 'value': 'foreign'}])]:
            row = copy.deepcopy(original)
            app = row['ownershipHandoff']['baselineApplications']['cloudlab-alloy']
            target = {'root': app, 'metadata': app['metadata'], 'spec': app['spec'],
                      'source': app['spec']['source'], 'helm': app['spec']['source']['helm']}[location]
            target[key] = value
            cases.append(row)
        for row in cases:
            with self.subTest(case=cases.index(row)):
                self.helm('platform/observability/gitops', row, valid=False)

    def test_six_children_holds_and_other_four_specs_preserved(self):
        original = self.inputs()
        baseline = original['ownershipHandoff']['baselineApplications']
        for phase in PHASES:
            values = copy.deepcopy(original)
            values['ownershipHandoff']['phase'] = phase
            children = self.applications(values)
            contract = json.loads((ROOT / 'platform/observability/contract.json').read_text())['ownership_handoff']['phases'][phase]
            self.assertEqual(set(children), set(baseline))
            for name, app in children.items():
                annotations = app['metadata']['annotations']
                self.assertEqual(annotations[ANNOTATIONS[0]], '0123456789abcdef')
                self.assertEqual(annotations[ANNOTATIONS[1]], phase)
                self.assertRegex(annotations[ANNOTATIONS[2]], r'^[a-f0-9]{64}$')
                self.assertEqual(annotations[ANNOTATIONS[3]], TARGET_UID)
                self.assertEqual(annotations['argocd.argoproj.io/skip-reconcile'], str(phase == 'native-paused').lower())
                automated = app['spec']['syncPolicy']['automated']
                self.assertEqual(automated, {'enabled': phase == 'native', 'prune': phase == 'native',
                                            'selfHeal': phase == 'native', 'allowEmpty': False})
                self.assertEqual(automated, contract['automated'])
                self.assertEqual(annotations['argocd.argoproj.io/skip-reconcile'], str(contract['skipReconcile']).lower())
                if phase not in ('native-paused', 'native') and name not in ('cloudlab-observability', 'cloudlab-prometheus'):
                    expected = copy.deepcopy(baseline[name]['spec'])
                    expected['syncPolicy']['automated'] = automated
                    self.assertEqual(app['spec'], expected)

    def test_literal_rule_annotations_survive_but_alternate_config_sources_fail(self):
        values = self.inputs('maintenance')
        prometheus = values['ownershipHandoff']['baselineApplications']['cloudlab-prometheus']['spec']['source']['helm']['valuesObject']
        prometheus['nativeLifecycle']['serviceRules'] = {'svc-fixture': {'groups': [{
            'name': 'fixture', 'rules': [{'alert': 'Svc_fixture_Alert', 'expr': 'vector(1)',
                'annotations': {'summary': '{{ $labels.service }}'}}]}]}}
        prometheus['serviceDashboards'] = {'svc-fixture.json': json.dumps({'panels': [
            {'targets': [{'expr': 'up', 'legendFormat': '{{ namespace }}'}]}]})}
        reference = {'password': {'name': 'synthetic-monitor', 'key': 'password'},
                     'username': {'name': 'synthetic-monitor', 'key': 'username'}}
        prometheus['kube-prometheus-stack']['prometheus'] = {'additionalServiceMonitors': [{
            'name': 'fixture-secret-reference', 'selector': {'matchLabels': {'app': 'fixture'}},
            'endpoints': [{'port': 'http-metrics', 'basicAuth': reference}]}]}
        rendered = self.resources(self.applications(values)['cloudlab-prometheus'])
        rule = rendered[('monitoring.coreos.com/v1', 'PrometheusRule', 'cloudlab-observability', 'svc-fixture')]
        self.assertEqual(rule['spec']['groups'][0]['rules'][0]['annotations']['summary'], '{{ $labels.service }}')
        dashboard = rendered[('v1', 'ConfigMap', 'cloudlab-observability', 'cloudlab-dashboards')]
        self.assertEqual(json.loads(dashboard['data']['svc-fixture.json'])['panels'][0]['targets'][0]['legendFormat'], '{{ namespace }}')
        monitor = rendered[('monitoring.coreos.com/v1', 'ServiceMonitor', 'cloudlab-observability', 'fixture-secret-reference')]
        self.assertEqual(monitor['spec']['endpoints'][0]['basicAuth'], reference)
        spec = prometheus['kube-prometheus-stack']['alertmanager']['alertmanagerSpec']
        spec.update({'configSecret': 'alertmanager-cloudlab', 'alertmanagerConfiguration': {},
                     'alertmanagerConfigSelector': {}, 'alertmanagerConfigNamespaceSelector': {}})
        self.applications(values)
        spec['configSecret'] = ''
        self.applications(values)
        for key, value in [('stringConfig', 'alternate'), ('tplConfig', True)]:
            row = copy.deepcopy(values)
            alertmanager = row['ownershipHandoff']['baselineApplications']['cloudlab-prometheus']['spec']['source']['helm']['valuesObject']['kube-prometheus-stack']['alertmanager']
            alertmanager[key] = value
            self.helm('platform/observability/gitops', row, valid=False)
        for key, value in [('configSecret', 'unmuted-alternate'),
                           ('alertmanagerConfiguration', {'name': 'unmuted-alternate'}),
                           ('alertmanagerConfigSelector', {'matchLabels': {'alerts': 'enabled'}}),
                           ('alertmanagerConfigNamespaceSelector', {'matchLabels': {'alerts': 'enabled'}})]:
            row = copy.deepcopy(values)
            spec = row['ownershipHandoff']['baselineApplications']['cloudlab-prometheus']['spec']['source']['helm']['valuesObject']['kube-prometheus-stack']['alertmanager']['alertmanagerSpec']
            spec[key] = value
            self.helm('platform/observability/gitops', row, valid=False)

    def resources(self, app):
        source = app['spec']['source']
        objects = self.helm(source['path'], source['helm']['valuesObject'], release=source['helm']['releaseName'])
        resources = []
        for obj in objects:
            resources.extend(obj['items'] if obj['kind'] == 'List' else [obj])
        return {(obj['apiVersion'], obj['kind'], obj.get('metadata', {}).get('namespace', ''), obj['metadata']['name']): obj for obj in resources}

    def test_native_resource_deltas_are_only_fixed_deny_secret_storage_and_quota(self):
        values = self.inputs()
        baseline = values['ownershipHandoff']['baselineApplications']
        configuration = self.resources(baseline['cloudlab-observability'])
        prometheus = self.resources(baseline['cloudlab-prometheus'])
        deny = ('security.istio.io/v1', 'AuthorizationPolicy', 'cloudlab-observability',
                'cloudlab-observability-handoff-write-deny')
        for phase in PHASES[:4]:
            values['ownershipHandoff']['phase'] = phase
            children = self.applications(values)
            current = self.resources(children['cloudlab-observability'])
            if phase in ('maintenance', 'persistent-maintenance'):
                policy = current.pop(deny)
                self.assertEqual(policy['spec'], {'action': 'DENY', 'rules': [
                    {'to': [{'operation': {'ports': ['9093']}}]}]})
                self.assertEqual(policy['metadata']['labels'], {'cloudlab.io/owner': 'observability-platform'})
            self.assertEqual(current, configuration)
            current = self.resources(children['cloudlab-prometheus'])
            changed = {key for key in current if current[key] != prometheus.get(key)}
            expected = set()
            if phase in ('maintenance', 'persistent-maintenance'):
                expected.add(('v1', 'Secret', 'cloudlab-observability', 'alertmanager-cloudlab'))
                key = ('v1', 'Secret', 'cloudlab-observability', 'alertmanager-cloudlab')
                original_config = yaml.safe_load(base64.b64decode(prometheus[key]['data']['alertmanager.yaml']))
                expected_config = copy.deepcopy(original_config)
                expected_config['receivers'] = [{'name': receiver['name']} for receiver in original_config['receivers']]
                self.assertEqual(yaml.safe_load(base64.b64decode(current[key]['data']['alertmanager.yaml'])), expected_config)
                expected_secret = copy.deepcopy(prometheus[key])
                expected_secret['data']['alertmanager.yaml'] = current[key]['data']['alertmanager.yaml']
                self.assertEqual(current[key], expected_secret)
            if phase in ('persistent-maintenance', 'persistent-normal'):
                expected.add(('monitoring.coreos.com/v1', 'Alertmanager', 'cloudlab-observability', 'cloudlab'))
                am = current[('monitoring.coreos.com/v1', 'Alertmanager', 'cloudlab-observability', 'cloudlab')]
                storage = am['spec'].pop('storage')
                self.assertEqual(set(storage), {'volumeClaimTemplate'})
                retention = am['spec'].pop('persistentVolumeClaimRetentionPolicy')
                self.assertNotIn('name', storage['volumeClaimTemplate'].get('metadata', {}))
                self.assertEqual(storage['volumeClaimTemplate']['spec'], {
                    'storageClassName': 'cloudlab-telemetry', 'accessModes': ['ReadWriteOnce'],
                    'volumeMode': 'Filesystem', 'resources': {'requests': {'storage': '1Gi'}}})
                self.assertEqual(retention, {'whenDeleted': 'Retain', 'whenScaled': 'Retain'})
                old = copy.deepcopy(prometheus[('monitoring.coreos.com/v1', 'Alertmanager', 'cloudlab-observability', 'cloudlab')])
                old['spec'].pop('storage')
                self.assertEqual(am, old)
            self.assertEqual(changed, expected)
            contract = json.loads((ROOT / 'platform/observability/contract.json').read_text())['ownership_handoff']['phases'][phase]
            declared = {(entry['apiVersion'], entry['kind'], entry['namespace'], entry['name'])
                        for entry in contract['baselineResourceDeltas']
                        if entry['kind'] in ('Secret', 'Alertmanager')}
            self.assertEqual(changed, declared)
            self.assertEqual(set(current), set(prometheus))
        values['ownershipHandoff']['phase'] = 'baseline'
        values['ownershipHandoff']['quotaIncrease'] = {'requestsStorageGiB': 72, 'persistentVolumeClaims': 6}
        current = self.resources(self.applications(values)['cloudlab-observability'])
        quota = ('v1', 'ResourceQuota', 'cloudlab-observability', 'telemetry-budget')
        expected = copy.deepcopy(configuration)
        expected[quota]['spec']['hard'].update({'requests.storage': '72Gi', 'persistentvolumeclaims': '6'})
        self.assertEqual(current, expected)


if __name__ == '__main__':
    unittest.main()
