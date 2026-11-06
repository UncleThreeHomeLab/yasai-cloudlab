"""Offline boundaries for scoped native reads; no cluster or credentials."""
import base64
from contextlib import contextmanager
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import shutil
import subprocess
import time
import unittest
from unittest.mock import Mock, patch

import yaml

from playbooks.argocd.files.private_sources import acceptance_spec
from playbooks.observability.files import native_transport as transport
from playbooks.observability.files.bootstrap import application as bootstrap_application
from playbooks.observability.files.payload import compile_payload
from playbooks.observability.tests.fixtures import native_source_inputs, notification_inputs, helm

ROOT = Path('/workspace')


def uid(number):
    return '%08x-0000-0000-0000-000000000000' % number


class NativeTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        values = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
        source = native_source_inputs()['nativeSource']
        values['repository'] = source['repository']
        values['identity']['argo'] = {'valuesRepository': source['valuesRepository'], 'valuesRevision': 'c' * 40}
        values['services']['revision'] = 'a' * 40
        values['observability']['configuration'] = {'enabled': True, 'paused': True, 'revision': 'a' * 40, 'acceptanceCommitment': '2' * 64}
        expected = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'metadata': {
            'name': transport.PARENT, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': 'observability-platform'},
            'annotations': {'argocd.argoproj.io/sync-options': 'Prune=false,Delete=false'}},
            'spec': acceptance_spec(values, source['valuesRepository'], 'c' * 40, consumer='observability')}
        observed = copy.deepcopy(expected)
        observed['metadata'].update(uid=uid(1), resourceVersion='1')
        parent = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application'} | copy.deepcopy(expected['spec']['template'])
        parent['metadata'].update(namespace='argocd', uid=uid(2), resourceVersion='2', ownerReferences=[{
            'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': transport.PARENT,
            'uid': uid(1), 'controller': True, 'blockOwnerDeletion': True}])
        parent['spec']['sources'][1]['targetRevision'] = 'b' * 40
        pods = {}
        for number, component, name, image in ((3, 'repo', 'repo-server', transport.ARGO_IMAGE), (4, 'redis', 'redis', transport.REDIS_IMAGE)):
            pods[component] = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'argocd-' + name + '-abcde-12345',
                'namespace': 'argocd', 'uid': uid(number), 'resourceVersion': str(number),
                'labels': {'app.kubernetes.io/component': name}}, 'spec': {'containers': [{'name': name, 'image': image}]},
                'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        cls.service = {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'kubernetes', 'namespace': 'default',
            'uid': uid(5), 'resourceVersion': '5'}, 'spec': {'clusterIP': '10.43.0.1',
            'ports': [{'name': 'https', 'port': 443, 'targetPort': 6443, 'protocol': 'TCP'}]}}
        cls.endpoints = {'apiVersion': 'v1', 'kind': 'Endpoints', 'metadata': {'name': 'kubernetes', 'namespace': 'default',
            'uid': uid(6), 'resourceVersion': '6'}, 'subsets': [{'addresses': [{'ip': '192.0.2.10'}],
            'ports': [{'name': 'https', 'port': 6443, 'protocol': 'TCP'}]}]}
        cls.initial = {'version': 1, 'operation': 'a' * 16, 'codeSHA256': transport.digest(Path(transport.__file__).read_bytes()),
            'source': {'expectedSet': expected, 'set': observed, 'parent': parent, 'pods': pods},
            'api': transport.api_targets(cls.service, cls.endpoints)}
        inputs = native_source_inputs()
        inputs['nativeSource']['paused'] = True
        cls.children = helm('platform/observability/gitops', inputs)
        cls.phase_directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.phase_directory.cleanup)
        chart = Path(cls.phase_directory.name) / 'gitops'
        shutil.copytree(ROOT / 'platform/observability/gitops', chart)
        registry_path = chart / 'handoff-profiles.json'
        registry = json.loads(registry_path.read_text())
        cls.references = {name: {'version': version, 'profile': name, 'codeRevision': 'a' * 40,
            'moduleDigests': {'synthetic-module': '1' * 64}, 'artifactDigests': {'synthetic-proof': '2' * 64},
            'imagePins': {'synthetic': 'example.invalid/fixture@sha256:' + '3' * 64}}
            for name, version in registry['requiredProfiles'].items()}
        cls.references['handoff']['scope'] = {'kind': 'full-entrypoint-integration'}
        cls.references['handoff']['artifactDigests'] = {'handoff-evidence.json': '2' * 64}
        registry['acceptedArtifacts'] = cls.references
        registry_path.write_text(json.dumps(registry))
        phase_values = notification_inputs()
        phase_values['nativeSource']['activationQualification'] = '2' * 64
        payload = compile_payload({'repository': phase_values['nativeSource']['repository'], 'revision': 'd' * 40},
            dict(phase_values['observabilityInputs'], gatewayIP='192.0.2.12'))
        baselines = {obj['metadata']['name']: obj for obj in
            (bootstrap_application(payload, name) for name in ('configuration', 'prometheus', 'loki', 'tempo', 'alloy', 'kiali'))}
        if any('annotations' in obj['metadata'] for obj in baselines.values()):
            raise RuntimeError('Legacy baseline regression must preserve actual bootstrap metadata')
        if any('valuesObject' in baselines[name]['spec']['source']['helm'] for name in ('cloudlab-loki', 'cloudlab-tempo', 'cloudlab-alloy')):
            raise RuntimeError('Legacy empty components must preserve valuesObject omission')
        cls.baselines = copy.deepcopy(baselines)
        phase_values['ownershipHandoff'] = {'version': 'cloudlab-observability-handoff/v1',
            'operationId': cls.initial['operation'], 'phase': 'baseline', 'baselineApplications': baselines,
            'qualifications': cls.references, 'approvedStorageTarget': 'alertmanager-retained-1gi-v1', 'targetClusterUID': uid(99)}
        cls.phase_apps = {}
        for phase in ('baseline', 'maintenance', 'persistent-maintenance', 'persistent-normal', 'native-paused', 'native'):
            phase_values['ownershipHandoff']['phase'] = phase
            result = subprocess.run(['helm', 'template', transport.PARENT, str(chart), '--kube-version', '1.36.5',
                '--namespace', 'argocd', '-f', '-'], input=yaml.safe_dump(phase_values),
                capture_output=True, text=True, timeout=90)
            if result.returncode: raise RuntimeError('Synthetic native phase render failed: ' + result.stderr)
            cls.phase_apps[phase] = {obj['metadata']['name']: obj for obj in yaml.safe_load_all(result.stdout) if obj}
            # Pinned native Core adds only this qualified tracking annotation to the rendered Applications.
            for name, obj in cls.phase_apps[phase].items():
                obj['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = transport.PARENT + ':argoproj.io/Application:argocd/' + name

        kiali = helm('platform/observability/kiali', cls.phase_apps['native-paused']['cloudlab-kiali']['spec']['source']['helm']['valuesObject'])
        cls.kiali_route = next(obj for obj in kiali if obj['kind'] == 'HTTPRoute' and obj['metadata']['name'] == 'kiali')
        cls.kiali_route['metadata'].setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = (
            'cloudlab-kiali:gateway.networking.k8s.io/HTTPRoute:cloudlab-observability/kiali')

    def setUp(self):
        self.value = copy.deepcopy(self.initial)

    def downstream_value(self, phase='baseline'):
        value = copy.deepcopy(self.initial)
        value['profile'] = 'downstream'
        value['source']['phaseApplications'] = copy.deepcopy(self.phase_apps[phase])
        value['source']['phaseContext'] = {'version': 'cloudlab-observability-handoff/v1',
            'operationId': value['operation'], 'phase': phase,
            'baselineDigest': self.phase_apps[phase]['cloudlab-observability']['metadata']['annotations']['cloudlab.io/observability-handoff-baseline'],
            'baselineRevision': 'd' * 40, 'privateRevision': value['source']['parent']['spec']['sources'][1]['targetRevision'],
            'qualificationsSHA256': transport.digest(transport.canonical(self.references)),
            'approvedStorageTarget': 'alertmanager-retained-1gi-v1'}
        value['source']['downstream'] = {}
        projected = value['source']['phaseApplications']
        for number, name in enumerate(transport.DOWNSTREAM, 20):
            accepted = copy.deepcopy(value['source']['phaseApplications'][name])
            observed = copy.deepcopy(projected[name])
            observed['metadata'].update(uid=uid(number), resourceVersion=str(number))
            value['source']['downstream'][name] = {'accepted': accepted, 'observed': observed}
        return value

    def phase_parent_value(self, phase='baseline'):
        value = self.downstream_value(phase)
        value['profile'] = 'phase-parent'
        value['source'].pop('downstream')
        value['source'].pop('phaseApplications')
        if phase == 'baseline':
            value['source']['originalBaselineApps'] = {}
            for number, name in enumerate(transport.DOWNSTREAM, 30):
                accepted = copy.deepcopy(self.baselines[name])
                observed = copy.deepcopy(accepted)
                observed['metadata'].update(uid=uid(number), resourceVersion=str(number))
                value['source']['originalBaselineApps'][name] = {'accepted': accepted, 'observed': observed}
        return value

    def test_phase_parent_discovers_five_native_closures_without_expected_applications(self):
        for phase, apps in self.phase_apps.items():
            value = self.phase_parent_value(phase)
            raw = transport.canonical({'manifests': [transport.canonical(obj).decode() for obj in apps.values()]})
            if phase == 'native':
                with self.assertRaises(RuntimeError): transport.validate_input(value)
                continue
            transport.validate_input(value)
            self.assertEqual(transport.phase_manifests(raw, value['source']), list(apps.values()))
            self.assertNotIn('phaseApplications', value['source'])
            self.assertEqual(transport.input_limit(value), transport.DOWNSTREAM_LIMIT if phase == 'baseline' else transport.LIMIT)
            bad = copy.deepcopy(value)
            bad['source']['phaseApplications'] = apps
            with self.assertRaises(RuntimeError): transport.validate_input(bad)
            for field in ('phase', 'baselineDigest', 'privateRevision'):
                changed = copy.deepcopy(value)
                changed['source']['phaseContext'][field] = 'invalid'
                with self.subTest(phase=phase, field=field), self.assertRaises(RuntimeError): transport.validate_input(changed)
            for field in ('tracking', 'source', 'provenance'):
                changed = copy.deepcopy(apps)
                obj = changed['cloudlab-alloy']
                if field == 'tracking': obj['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
                if field == 'source': obj['spec']['source']['targetRevision'] = 'f' * 40
                if field == 'provenance': obj['metadata']['annotations']['cloudlab.io/observability-handoff-baseline'] = 'f' * 64
                with self.subTest(phase=phase, field=field), self.assertRaises(RuntimeError):
                    transport.phase_manifests(transport.canonical({'manifests': [transport.canonical(obj).decode() for obj in changed.values()]}), value['source'])
        value = self.phase_parent_value()
        for name in transport.DOWNSTREAM:
            self.assertTrue(value['source']['originalBaselineApps'][name]['observed']['spec']['syncPolicy']['automated']['enabled'])
        missing = copy.deepcopy(value)
        missing['source'].pop('originalBaselineApps')
        with self.assertRaises(RuntimeError): transport.validate_input(missing)

    def test_kiali_inventory_binding_is_mandatory_for_baseline_and_downstream(self):
        self.assertEqual(transport.DOWNSTREAM, ('cloudlab-observability', 'cloudlab-prometheus', 'cloudlab-kiali'))
        self.assertEqual(transport.DOWNSTREAM_PATHS['cloudlab-kiali'],
            '/api/v1/applications/cloudlab-kiali/manifests?appNamespace=argocd&project=cloudlab-observability')
        for value, key in ((self.phase_parent_value(), 'originalBaselineApps'), (self.downstream_value(), 'downstream')):
            transport.validate_input(value)
            value['source'][key].pop('cloudlab-kiali')
            with self.assertRaises(RuntimeError): transport.validate_input(value)
        original = self.phase_parent_value()['source']['originalBaselineApps']['cloudlab-kiali']
        self.assertEqual(original['accepted']['spec']['source']['path'], 'platform/observability/kiali')
        self.assertEqual(original['accepted']['spec']['source']['targetRevision'], 'd' * 40)
        self.assertEqual(original['accepted']['spec'], original['observed']['spec'])
        self.assertIn('kiali-server', original['accepted']['spec']['source']['helm']['valuesObject'])

    def test_phase_parent_baseline_fixed_gets_and_private_bounds_are_not_response_selected(self):
        value = self.phase_parent_value()
        docs = transport.declarations(value)
        pod = docs['job']['spec']['template']['spec']
        self.assertEqual(pod['containers'][0]['resources']['requests']['memory'], '512Mi')
        self.assertEqual(next(v for v in pod['volumes'] if v['name'] == 'result')['emptyDir']['sizeLimit'], '40Mi')
        raw = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        for name in transport.DOWNSTREAM:
            connection.recv.side_effect = [raw, b'']
            with patch.object(transport.socket, 'create_connection', return_value=connection):
                transport.core_request(12345, name, b'', time.monotonic() + 5, [transport.DOWNSTREAM_LIMIT],
                    Mock(), 'phase-parent', baseline_inventory=True)
                self.assertTrue(connection.sendall.call_args.args[0].startswith(('GET ' + transport.DOWNSTREAM_PATHS[name] + ' HTTP/1.1').encode()))
        connection.recv.side_effect = [raw, b'']
        with patch.object(transport.socket, 'create_connection', return_value=connection):
            with self.assertRaises(RuntimeError): transport.core_request(12345, transport.DOWNSTREAM[0], b'', time.monotonic() + 5,
                [len(raw) - 1], Mock(), 'phase-parent', baseline_inventory=True)
        with patch.object(transport.socket, 'create_connection') as connect:
            with self.assertRaises(RuntimeError): transport.core_request(12345, transport.DOWNSTREAM[0], b'', time.monotonic() + 5,
                [transport.LIMIT], Mock(), 'phase-parent')
            connect.assert_not_called()
        value['source']['originalBaselineApps']['cloudlab-observability']['observed']['operation'] = {}
        with self.assertRaises(RuntimeError): transport.validate_input(value)

    def test_initial_baseline_reads_original_sources_before_any_staging_and_rejects_movement(self):
        value = self.phase_parent_value()
        source = value['source']
        generated = copy.deepcopy(source['parent'])
        for key in ('uid', 'resourceVersion', 'ownerReferences'): generated['metadata'].pop(key, None)
        inventory = [{'apiVersion': 'apiextensions.k8s.io/v1', 'kind': 'CustomResourceDefinition',
            'metadata': {'name': 'full.example.invalid'}, 'spec': {'schema': 'x' * (transport.LIMIT + 1)}}]
        @contextmanager
        def dashboard(*args): yield 12345, Mock()
        for changed in (None, 'uid', 'resourceVersion', 'spec', 'operation', 'kiali-resourceVersion'):
            observed = {transport.SETS + transport.PARENT: source['set'], transport.APPS + transport.PARENT: source['parent']}
            observed.update({transport.APPS + name: entry['observed'] for name, entry in source['originalBaselineApps'].items()})
            observed.update({'/api/v1/namespaces/argocd/pods/' + pod['metadata']['name']: pod for pod in source['pods'].values()})
            observed = copy.deepcopy(observed)
            events = []
            def read(path):
                events.append(('api', path))
                return copy.deepcopy(observed[path])
            def core(_port, operation, _body, _deadline, budget, _guard, profile, baseline_inventory=False):
                self.assertEqual(profile, 'phase-parent')
                self.assertTrue(baseline_inventory)
                events.append(('core', operation))
                if operation == 'generate': result = transport.canonical({'applications': [generated]})
                elif operation == 'manifests': result = transport.canonical({'manifests': [transport.canonical(obj).decode() for obj in self.phase_apps['baseline'].values()]})
                else:
                    self.assertIn(operation, transport.DOWNSTREAM)
                    self.assertEqual(observed[transport.APPS + operation]['spec'], source['originalBaselineApps'][operation]['accepted']['spec'])
                    self.assertEqual(observed[transport.APPS + operation]['spec']['source']['targetRevision'], 'd' * 40)
                    self.assertEqual(self.phase_apps['baseline']['cloudlab-observability']['spec']['source']['targetRevision'], 'a' * 40)
                    result = transport.canonical({'manifests': [transport.canonical(obj).decode() for obj in inventory]})
                    if changed and (changed != 'kiali-resourceVersion' or operation == 'cloudlab-kiali'):
                        obj = observed[transport.APPS + operation]
                        if changed == 'kiali-resourceVersion': obj['metadata']['resourceVersion'] = 'changed'
                        elif changed == 'spec': obj['spec']['source']['targetRevision'] = 'e' * 40
                        elif changed == 'operation': obj['operation'] = {}
                        else: obj['metadata'][changed] = uid(88) if changed == 'uid' else 'changed'
                budget[0] -= len(result)
                return result
            client = Mock(deadline=time.monotonic() + 90, read=Mock(side_effect=read))
            with self.subTest(changed=changed), patch.object(transport, 'dashboard', dashboard), \
                    patch.object(transport, 'initialized_state', return_value={}), patch.object(transport, 'core_request', side_effect=core):
                if changed:
                    with self.assertRaises(RuntimeError): transport.native_read(value, Path('/unused'), client)
                else:
                    result = transport.native_read(value, Path('/unused'), client)
                    self.assertEqual(result, {'parent': list(self.phase_apps['baseline'].values()),
                        'baseline': {name: inventory for name in transport.DOWNSTREAM}})
                    self.assertEqual([event[1] for event in events if event[0] == 'core'], ['generate', 'manifests', *transport.DOWNSTREAM])
                    for number, event in enumerate(events):
                        if event[0] == 'core':
                            before = events[number - len(transport.DOWNSTREAM):number]
                            after = events[number + 1:number + 1 + len(transport.DOWNSTREAM)]
                            expected = [('api', transport.APPS + name) for name in transport.DOWNSTREAM]
                            self.assertEqual(before, expected)
                            self.assertEqual(after, expected)

    def test_actual_six_native_phase_renders_require_complete_provenance_source_and_tracking(self):
        for phase in self.phase_apps:
            value = self.downstream_value(phase)
            if phase == 'native':
                with self.assertRaises(RuntimeError): transport.validate_input(value)
                continue
            transport.validate_input(value)
            objects = list(value['source']['phaseApplications'].values())
            raw = transport.canonical({'manifests': [transport.canonical(obj).decode() for obj in objects]})
            legacy_options = ['FailOnSharedResource=true', 'ServerSideApply=true', 'DisableClientSideApplyMigration=true']
            expected_options = legacy_options + (['PruneLast=true'] if phase in ('native-paused', 'native') else [])
            with self.subTest(phase=phase):
                self.assertTrue(all(obj['spec']['syncPolicy']['syncOptions'] == expected_options for obj in objects))
                for obj in objects:
                    missing_values = obj['metadata']['name'] in ('cloudlab-loki', 'cloudlab-tempo', 'cloudlab-alloy') and phase not in ('native-paused', 'native')
                    self.assertEqual('valuesObject' not in obj['spec']['source']['helm'], missing_values)
                self.assertEqual(transport.phase_manifests(raw, value['source']), objects)
            for options in (list(reversed(expected_options)), expected_options + ['Replace=true'], expected_options[:-1]):
                bad = copy.deepcopy(value)
                bad['source']['phaseApplications']['cloudlab-alloy']['spec']['syncPolicy']['syncOptions'] = options
                with self.subTest(phase=phase, options=options), self.assertRaises(RuntimeError): transport.phase_applications(bad['source'])
                if phase != 'native-paused':
                    with self.assertRaises(RuntimeError): transport.manifests(raw, value['source'])
            if phase not in ('native-paused', 'native'):
                canonical = copy.deepcopy(value)
                canonical['source']['phaseApplications']['cloudlab-alloy']['spec']['syncPolicy']['syncOptions'] = legacy_options + ['PruneLast=true']
                transport.phase_applications(canonical['source'])
            for component in ('cloudlab-observability', 'cloudlab-prometheus'):
                bad = copy.deepcopy(value)
                bad['source']['phaseApplications'][component]['spec']['source']['helm'].pop('valuesObject')
                with self.subTest(phase=phase, adapter=component), self.assertRaises(RuntimeError): transport.phase_applications(bad['source'])
            for changed in ('source', 'provenance', 'phase', 'tracking', 'extra', 'missing-target', 'zero-target', 'different-target'):
                bad = copy.deepcopy(objects)
                target = next(obj for obj in bad if obj['metadata']['name'] == 'cloudlab-alloy')
                if changed == 'source': target['spec']['source']['targetRevision'] = 'f' * 40
                if changed == 'provenance': target['metadata']['annotations']['cloudlab.io/observability-handoff-baseline'] = 'f' * 64
                if changed == 'phase': target['metadata']['annotations']['cloudlab.io/observability-handoff-phase'] = 'substitution'
                if changed == 'tracking': target['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
                if changed == 'extra': target['metadata']['annotations']['foreign.example/annotation'] = 'unexpected'
                marker = 'cloudlab.io/observability-handoff-target-cluster-uid'
                if changed == 'missing-target': target['metadata']['annotations'].pop(marker)
                if changed == 'zero-target': target['metadata']['annotations'][marker] = uid(0)
                if changed == 'different-target': target['metadata']['annotations'][marker] = uid(100)
                with self.subTest(phase=phase, changed=changed), self.assertRaises(RuntimeError):
                    transport.phase_manifests(transport.canonical({'manifests': [transport.canonical(obj).decode() for obj in bad]}), value['source'])
        value = self.downstream_value()
        self.assertEqual(value['source']['phaseApplications']['cloudlab-alloy']['spec']['source']['targetRevision'], 'd' * 40)
        for changed in ('operationId', 'privateRevision', 'baselineDigest', 'qualificationsSHA256', 'phase'):
            bad = copy.deepcopy(value)
            bad['source']['phaseContext'][changed] = 'invalid'
            with self.subTest(context=changed), self.assertRaises(RuntimeError): transport.validate_input(bad)

    def test_activation_pointer_is_explicit_and_bound_to_the_exact_authenticated_set(self):
        expected = copy.deepcopy(self.initial['source']['expectedSet'])
        original = transport.generate_payload(expected)
        native = expected['spec']['template']['spec']['sources'][0]['helm']['valuesObject']['nativeSource']
        self.assertEqual(set(native), {'repository', 'revision', 'valuesRepository', 'paused', 'activationQualification'})
        self.assertEqual(native['activationQualification'], '')
        self.assertEqual(json.loads(original)['applicationSet'], expected)
        native['activationQualification'] = '2' * 64
        self.assertEqual(json.loads(transport.generate_payload(expected))['applicationSet'], expected)
        for pointer in ('0' * 64, 'not-a-digest', {}, False):
            native['activationQualification'] = pointer
            with self.subTest(pointer=pointer), self.assertRaises(RuntimeError): transport.generate_payload(expected)
        native.pop('activationQualification')
        with self.assertRaisesRegex(RuntimeError, 'Authenticated Root activation qualification is required'):
            transport.generate_payload(expected)

    def test_downstream_qualifies_live_annotation_tracking_without_installation_id(self):
        secret = {'kind': 'Secret', 'apiVersion': 'v1', 'type': 'Opaque',
            'metadata': {'name': 'argocd-secret', 'namespace': 'argocd', 'uid': uid(40), 'resourceVersion': '1'},
            'data': {'server.secretkey': base64.b64encode(b'x' * 32).decode()}}
        project = {'kind': 'AppProject', 'apiVersion': 'argoproj.io/v1alpha1',
            'metadata': {'name': 'default', 'namespace': 'argocd', 'uid': uid(41), 'resourceVersion': '1'}, 'spec': {}}
        settings = {'kind': 'ConfigMap', 'apiVersion': 'v1',
            'metadata': {'name': 'argocd-cm', 'namespace': 'argocd', 'uid': uid(42), 'resourceVersion': '1'},
            'data': {'admin.enabled': 'false', 'application.resourceTrackingMethod': 'annotation'}}
        objects = {'/api/v1/namespaces/argocd/secrets/argocd-secret': secret,
            '/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/default': project,
            '/api/v1/namespaces/argocd/configmaps/argocd-cm': settings}
        read = lambda path: copy.deepcopy(objects[path])
        transport.initialized_state(read, 'downstream')
        for data in ({'admin.enabled': 'false'}, {'admin.enabled': 'false', 'application.resourceTrackingMethod': 'label'},
                {'admin.enabled': 'false', 'application.resourceTrackingMethod': 'annotation', 'installationID': 'foreign'}):
            settings['data'] = data
            transport.initialized_state(read)  # Parent-only preflight remains unchanged.
            with self.assertRaises(RuntimeError): transport.initialized_state(read, 'downstream')

    def test_downstream_profile_binds_accepted_phase_and_keeps_parent_declarations(self):
        value = self.downstream_value()
        transport.validate_input(value)
        transport.validate_downstream(value['source'], list(value['source']['phaseApplications'].values()))
        docs = transport.declarations(value)
        parent = transport.declarations(self.initial)
        pod = docs['job']['spec']['template']['spec']
        self.assertEqual(pod['containers'][0]['resources'], {'requests': {'cpu': '100m', 'memory': '512Mi'},
            'limits': {'cpu': '1', 'memory': '768Mi'}})
        self.assertEqual(next(v for v in pod['volumes'] if v['name'] == 'result')['emptyDir'], {'medium': 'Memory', 'sizeLimit': '40Mi'})
        self.assertEqual(docs['role']['rules'], parent['role']['rules'])
        for case in ('unknown-profile', 'live-only', 'spec', 'active', 'source', 'digest'):
            bad = copy.deepcopy(value)
            phase = bad['source']['downstream'][transport.DOWNSTREAM[0]]
            if case == 'unknown-profile': bad['profile'] = 'arbitrary'
            if case == 'live-only': phase.pop('accepted')
            if case == 'spec': phase['observed']['spec']['source']['path'] = 'other'
            if case == 'active': phase['observed']['operation'] = {}
            if case == 'source': phase['accepted']['spec']['source']['repoURL'] = 'https://github.com/other/other.git'
            if case == 'digest':
                for key in ('accepted', 'observed'):
                    phase[key]['metadata']['annotations']['cloudlab.io/observability-input-digest'] = 'f' * 64
                    phase[key]['spec']['source']['helm']['valuesObject']['nativeInputDigest'] = 'f' * 64
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                transport.validate_input(bad)
                transport.validate_downstream(bad['source'], list(bad['source']['phaseApplications'].values()))

    def test_downstream_core_uses_only_two_fixed_gets_and_total_budget(self):
        raw = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'
        for name, path in transport.DOWNSTREAM_PATHS.items():
            connection = Mock()
            connection.__enter__ = Mock(return_value=connection)
            connection.__exit__ = Mock(return_value=False)
            connection.recv.side_effect = [raw, b'']
            with patch.object(transport.socket, 'create_connection', return_value=connection):
                budget = [transport.DOWNSTREAM_LIMIT]
                self.assertEqual(transport.core_request(12345, name, b'', time.monotonic() + 5, budget, Mock(), 'downstream'), b'{}')
                self.assertTrue(connection.sendall.call_args.args[0].startswith(('GET ' + path + ' HTTP/1.1\r\n').encode()))
                self.assertEqual(budget[0], transport.DOWNSTREAM_LIMIT - len(raw))
        with patch.object(transport.socket, 'create_connection') as connect:
            for profile, operation in [('parent', transport.DOWNSTREAM[0]), ('downstream', 'other'), ('response-selected', 'manifests')]:
                with self.assertRaises(RuntimeError): transport.core_request(12345, operation, b'', time.monotonic() + 5,
                    [transport.DOWNSTREAM_LIMIT], Mock(), profile)
            connect.assert_not_called()
        payload = b'HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n' + b'x' * (transport.LIMIT + 1)
        self.assertEqual(len(transport.decode_response(payload, transport.DOWNSTREAM_LIMIT)), transport.LIMIT + 1)
        with self.assertRaises(RuntimeError): transport.decode_response(payload)

    def test_downstream_read_preserves_full_inventory_and_rejects_phase_uid_rv_drift(self):
        value = self.downstream_value('native-paused')
        generated = copy.deepcopy(value['source']['parent'])
        for key in ('uid', 'resourceVersion', 'ownerReferences'): generated['metadata'].pop(key, None)
        inventory = [{'apiVersion': 'apiextensions.k8s.io/v1', 'kind': 'CustomResourceDefinition',
            'metadata': {'name': 'large.example.invalid'}, 'spec': {'schema': 'x' * (transport.LIMIT + 1)}},
            {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'all-fields', 'namespace': 'cloudlab-observability'},
                'data': {'preserved': 'yes'}}]
        @contextmanager
        def dashboard(*args): yield 12345, Mock()
        for changed in (None, 'uid', 'resourceVersion', 'kiali-resourceVersion'):
            observed = {transport.SETS + transport.PARENT: value['source']['set'], transport.APPS + transport.PARENT: value['source']['parent']}
            observed.update({transport.APPS + name: phase['observed'] for name, phase in value['source']['downstream'].items()})
            observed.update({'/api/v1/namespaces/argocd/pods/' + pod['metadata']['name']: pod for pod in value['source']['pods'].values()})
            observed = copy.deepcopy(observed)
            def core(_port, operation, _body, _deadline, budget, _guard, profile):
                self.assertEqual(profile, 'downstream')
                if operation == 'generate': result = transport.canonical({'applications': [generated]})
                elif operation == 'manifests': result = transport.canonical({'manifests': [transport.canonical(obj).decode() for obj in list(value['source']['phaseApplications'].values())]})
                else:
                    resources = [self.kiali_route] if operation == 'cloudlab-kiali' else inventory
                    result = transport.canonical({'manifests': [transport.canonical(obj).decode() for obj in resources]})
                    if changed == 'kiali-resourceVersion':
                        if operation == 'cloudlab-kiali': observed[transport.APPS + operation]['metadata']['resourceVersion'] = 'changed'
                    elif changed: observed[transport.APPS + transport.DOWNSTREAM[0]]['metadata'][changed] = uid(88) if changed == 'uid' else 'changed'
                budget[0] -= len(result)
                return result
            client = Mock(deadline=time.monotonic() + 90, read=Mock(side_effect=lambda path: copy.deepcopy(observed[path])))
            with self.subTest(changed=changed), patch.object(transport, 'dashboard', dashboard), \
                    patch.object(transport, 'initialized_state', return_value={}), patch.object(transport, 'core_request', side_effect=core):
                if changed:
                    with self.assertRaises(RuntimeError): transport.native_read(value, Path('/unused'), client)
                else:
                    result = transport.native_read(value, Path('/unused'), client)
                    self.assertEqual(result, {'parent': list(value['source']['phaseApplications'].values()),
                        **{name: [self.kiali_route] if name == 'cloudlab-kiali' else inventory for name in transport.DOWNSTREAM}})
                    self.assertEqual(result['cloudlab-kiali'][0]['spec']['rules'][0]['backendRefs'][0]['name'], 'cloudlab-kiali')
                    self.assertEqual(result['cloudlab-kiali'][0]['metadata']['annotations']['argocd.argoproj.io/tracking-id'],
                        'cloudlab-kiali:gateway.networking.k8s.io/HTTPRoute:cloudlab-observability/kiali')

    def test_downstream_encoded_result_overflow_is_not_published(self):
        value = self.downstream_value()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            input_path = directory / 'input.json'
            input_path.write_bytes(transport.canonical(value))
            real_path = Path
            def scoped_path(name):
                if str(name) == '/assets/input.json': return input_path
                if str(name) == '/work/private': return directory / 'private'
                return real_path(name)
            with patch.object(transport, 'Path', side_effect=scoped_path), \
                    patch.dict(transport.os.environ, {'CLOUDLAB_POD_UID': uid(99)}), \
                    patch.object(transport, 'NativeClient'), \
                    patch.object(transport, 'native_read', return_value={'parent': [],
                        **{name: [] for name in transport.DOWNSTREAM}, 'encoded': '"' * (transport.DOWNSTREAM_LIMIT // 2)}), \
                    patch.object(transport, 'RESULT', directory / 'result.json'):
                with self.assertRaisesRegex(RuntimeError, 'custody bound'): transport.pod_main()
                self.assertFalse((directory / 'result.json').exists())

    def test_downstream_custody_limit_comes_from_protected_input(self):
        value = self.downstream_value()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'manifest.json'
            raw = transport.canonical({'expires': time.monotonic() + 10, 'manifests': 'x' * (transport.LIMIT + 1), 'profile': 'parent'})
            target.write_bytes(raw); target.chmod(0o600)
            with patch.object(transport, 'RESULT', target):
                self.assertEqual(transport.collect_file(value), raw)
                with self.assertRaises(RuntimeError): transport.collect_file()
                with target.open('r+b') as stream: stream.truncate(transport.DOWNSTREAM_LIMIT + 1)
                with self.assertRaises(RuntimeError): transport.collect_file(value)
        status = {'status': 'ready', 'sha256': 'a' * 64, 'bytes': transport.DOWNSTREAM_LIMIT + 1}
        with self.assertRaises(RuntimeError): transport.collect(Mock(), Mock(), {}, Mock(), value, {}, status)

    def test_existing_image_pins_match_accepted_locks(self):
        lock = json.loads((ROOT / 'platform/delivery/argocd/artifact.lock.json').read_text())
        self.assertIn(transport.ARGO_IMAGE, {name + '@' + digest for name, digest in lock['images'].items()})
        python = json.loads((ROOT / 'platform/identity/keycloak/artifact.lock.json').read_text())['images']['python']
        self.assertEqual(transport.PYTHON_IMAGE, python)

    def test_invalid_source_scope_authority_or_code_fails_before_declarations(self):
        transport.validate_input(self.value)
        for case in ('operation', 'code', 'parent', 'active', 'set', 'pod', 'api'):
            bad = copy.deepcopy(self.value)
            if case == 'operation': bad['operation'] = '../other'
            if case == 'code': bad['codeSHA256'] = '0' * 64
            if case == 'parent': bad['source']['parent']['spec']['project'] = 'other'
            if case == 'active': bad['source']['parent']['operation'] = {}
            if case == 'set': bad['source']['expectedSet']['spec']['templatePatch'] = 'spec: {}'
            if case == 'pod': bad['source']['pods']['repo']['metadata']['namespace'] = 'other'
            if case == 'api': bad['api']['serviceIP'] = '127.0.0.1'
            with self.subTest(case=case), self.assertRaises(RuntimeError): transport.declarations(bad)

    def test_job_is_suspended_restricted_token_bound_and_short_lived(self):
        docs = transport.declarations(self.value, uid(8))
        job, role = docs['job'], docs['role']
        self.assertTrue(job['spec']['suspend'])
        self.assertEqual((job['spec']['activeDeadlineSeconds'], job['spec']['backoffLimit'], job['spec']['ttlSecondsAfterFinished']), (180, 0, 60))
        pod = job['spec']['template']['spec']
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertEqual(pod['restartPolicy'], 'Never')
        self.assertEqual(pod['securityContext']['runAsUser'], 999)
        self.assertTrue(pod['containers'][0]['securityContext']['readOnlyRootFilesystem'])
        self.assertFalse(any(mount['name'] == 'token' for mount in pod['initContainers'][0]['volumeMounts']))
        projected = next(volume for volume in pod['volumes'] if volume['name'] == 'token')['projected']
        self.assertEqual(projected['sources'][0]['serviceAccountToken']['expirationSeconds'], 600)
        self.assertEqual(docs['account']['metadata']['ownerReferences'][0]['uid'], uid(8))
        self.assertNotIn('ownerReferences', docs['binding']['metadata'])
        self.assertEqual(role['rules'][-1]['resourceNames'], sorted(pod['metadata']['name'] for pod in self.value['source']['pods'].values()))
        self.assertFalse(any('pods/exec' in rule['resources'] for rule in role['rules']))
        self.assertEqual(docs['binding']['subjects'], [{'kind': 'ServiceAccount', 'name': transport.JOB,
            'namespace': transport.namespace(self.value['operation'])}])
        self.assertTrue(docs['assets']['immutable'])
        network = docs['network']['spec']
        self.assertEqual(network['ingress'], [])
        self.assertEqual([row['ports'] for row in network['egress']], [[{'protocol': 'TCP', 'port': 443}], [{'protocol': 'TCP', 'port': 6443}]])

    def test_native_manifest_closure_rejects_extra_sources_or_enabled_automation(self):
        raw = transport.canonical({'manifests': [transport.canonical(obj).decode() for obj in self.children]})
        self.assertEqual(transport.manifests(raw, self.value['source']), self.children)
        for case in ('extra', 'source', 'pause'):
            children = copy.deepcopy(self.children)
            if case == 'extra': children.append(copy.deepcopy(children[0]))
            if case == 'source': children[0]['spec']['sources'] = []
            if case == 'pause': children[0]['spec']['syncPolicy']['automated']['enabled'] = True
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                transport.manifests(transport.canonical({'manifests': [transport.canonical(obj).decode() for obj in children]}), self.value['source'])

    def test_api_endpoint_and_profile_changes_are_rejected(self):
        service = copy.deepcopy(self.service)
        service['spec']['externalName'] = 'other.invalid'
        with self.assertRaises(RuntimeError): transport.api_targets(service, self.endpoints)
        docs = transport.declarations(self.value, uid(8))
        job = copy.deepcopy(docs['job'])
        job['metadata'].update(uid=uid(8), resourceVersion='8')
        job['spec']['selector'] = {'matchLabels': {'batch.kubernetes.io/controller-uid': uid(8)}}
        job['spec']['template']['metadata']['creationTimestamp'] = None
        job['spec']['template']['metadata']['labels']['batch.kubernetes.io/controller-uid'] = uid(8)
        transport.declared(job, docs['job'])
        job['spec']['template']['spec']['containers'][0]['envFrom'] = [{'secretRef': {'name': 'other'}}]
        with self.assertRaises(RuntimeError): transport.declared(job, docs['job'])

    def test_prepare_journals_suspended_job_before_sa_grant_and_unsuspension(self):
        record, objects, events = {}, {}, []
        objects['/api/v1/namespaces/default/services/kubernetes'] = copy.deepcopy(self.service)
        objects['/api/v1/namespaces/default/endpoints/kubernetes'] = copy.deepcopy(self.endpoints)
        objects[transport.SETS + transport.PARENT] = copy.deepcopy(self.value['source']['set'])
        objects[transport.APPS + transport.PARENT] = copy.deepcopy(self.value['source']['parent'])
        for pod in self.value['source']['pods'].values(): objects[transport.path_for(pod)] = copy.deepcopy(pod)
        def persist(): events.append(('save', copy.deepcopy(record)))
        def request(path, method='GET', body=None, content_type=None):
            if method == 'GET': return copy.deepcopy(objects.get(path))
            if method == 'POST':
                obj = copy.deepcopy(body)
                if obj['kind'] == 'ServiceAccount':
                    self.assertIn('job', events[-1][1]['objects'])
                    self.assertEqual(obj['metadata']['ownerReferences'][0]['uid'], record['objects']['job']['identity']['uid'])
                obj['metadata'].update(uid=uid(20 + len(events)), resourceVersion=str(20 + len(events)))
                objects[transport.path_for(obj)] = obj
                events.append((obj['kind'], obj['metadata']['name']))
                return copy.deepcopy(obj)
            self.assertEqual(method, 'PATCH')
            self.assertEqual(content_type, 'application/json-patch+json')
            self.assertIn('unsuspendIntent', events[-1][1])
            current = objects[path]
            self.assertEqual(body[0]['value'], current['metadata']['uid'])
            self.assertEqual(body[1]['value'], current['metadata']['resourceVersion'])
            current['spec']['suspend'] = False
            current['metadata']['resourceVersion'] = '999'
            events.append(('unsuspend', path))
            return copy.deepcopy(current)
        result = transport.prepare(request, record, persist, self.value)
        self.assertFalse(result['spec']['suspend'])
        order = [event[0] for event in events if event[0] != 'save']
        self.assertEqual(order, ['Namespace', 'NetworkPolicy', 'Job', 'ConfigMap', 'ServiceAccount', 'Role', 'RoleBinding', 'unsuspend'])
        count = len(order)
        transport.prepare(request, record, persist, self.value)
        self.assertEqual(len([event for event in events if event[0] != 'save']), count)
        record['cleanupStarted'] = True
        with self.assertRaises(RuntimeError): transport.prepare(request, record, persist, self.value)

    def test_collect_uses_fixed_private_exec_and_checks_container_identity(self):
        for profile in ('parent', 'downstream', 'baseline', 'maintenance'):
            self.value = (copy.deepcopy(self.initial) if profile == 'parent' else self.downstream_value() if profile == 'downstream'
                else self.phase_parent_value(profile))
            inventories = {name: [{'apiVersion': 'v1', 'kind': 'ConfigMap',
                'metadata': {'name': name}, 'data': {'large': 'x' * transport.LIMIT}}] for name in transport.DOWNSTREAM}
            inventories['cloudlab-kiali'] = [self.kiali_route]
            if profile == 'parent': result_objects = self.children
            elif profile == 'downstream': result_objects = {'parent': list(self.value['source']['phaseApplications'].values()), **inventories}
            elif profile == 'baseline': result_objects = {'parent': list(self.phase_apps[profile].values()), 'baseline': inventories}
            else: result_objects = list(self.phase_apps[profile].values())
            docs = transport.declarations(self.value, uid(8))
            record = {'context': {'operation': self.value['operation'], 'inputSHA256': transport.digest(transport.canonical(self.value)),
                'codeSHA256': self.value['codeSHA256']}, 'objects': {}, 'unsuspended': True, 'cleanupStarted': False}
            objects = {}
            for number, key in enumerate(('job', 'assets', 'account', 'role', 'binding'), 8):
                obj = copy.deepcopy(docs[key]); obj['metadata'].update(uid=uid(number), resourceVersion=str(number))
                path = transport.path_for(obj); objects[path] = obj
                record['objects'][key] = {'path': path, 'identity': transport.identity(obj), 'fingerprint': transport.fingerprint(obj)}
            pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': transport.JOB + '-abc12',
                'namespace': transport.namespace(self.value['operation']), 'uid': uid(99), 'resourceVersion': '99',
                'ownerReferences': [{'apiVersion': 'batch/v1', 'kind': 'Job', 'name': transport.JOB,
                    'uid': uid(8), 'controller': True, 'blockOwnerDeletion': True}]},
                'spec': copy.deepcopy(docs['job']['spec']['template']['spec']), 'status': {'containerStatuses': [
                    {'name': 'transport', 'restartCount': 0, 'containerID': 'containerd://' + 'a' * 64, 'state': {'running': {'startedAt': '2026-11-05T00:00:00Z'}}}]}}
            path = transport.path_for(pod); objects[path] = pod
            raw = transport.canonical({'version': 1, 'operation': self.value['operation'], 'podUID': uid(99),
                'inputSHA256': record['context']['inputSHA256'], 'expires': time.monotonic() + 20, 'manifests': result_objects})
            status = {'status': 'ready', 'sha256': transport.digest(raw), 'bytes': len(raw)}
            execute = Mock(return_value=raw)
            request = lambda path: copy.deepcopy(objects[path])
            self.assertEqual(transport.collect(request, execute, record, Mock(), self.value, pod, status), result_objects)
            execute.assert_called_once_with(transport.namespace(self.value['operation']), pod['metadata']['name'], 'transport', transport.COLLECT)
            if profile in ('baseline', 'downstream'):
                missing = transport.strict_json(raw, transport.DOWNSTREAM_LIMIT)
                inventory_map = missing['manifests']['baseline'] if profile == 'baseline' else missing['manifests']
                inventory_map.pop('cloudlab-kiali')
                missing_raw = transport.canonical(missing)
                missing_status = {'status': 'ready', 'sha256': transport.digest(missing_raw), 'bytes': len(missing_raw)}
                with self.assertRaises(RuntimeError):
                    transport.collect(request, Mock(return_value=missing_raw), record, Mock(), self.value, pod, missing_status)
            def changed(ns, name, container, arguments):
                objects[path]['status']['containerStatuses'][0]['containerID'] = 'containerd://' + 'b' * 64
                return raw
            with self.assertRaises(RuntimeError):
                transport.collect(request, changed, record, Mock(), self.value, pod, status)

    def test_custody_file_is_private_bounded_and_expires(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'manifest.json'
            raw = transport.canonical({'expires': time.monotonic() + 10, 'manifests': []})
            target.write_bytes(raw); target.chmod(0o600)
            with patch.object(transport, 'RESULT', target):
                self.assertEqual(transport.collect_file(), raw)
                target.write_bytes(transport.canonical({'expires': time.monotonic() - 1, 'manifests': []}))
                with self.assertRaises(RuntimeError): transport.collect_file()
                target.chmod(0o644)
                with self.assertRaises(RuntimeError): transport.collect_file()

    def test_cleanup_requests_job_then_binding_and_resume_revokes_first(self):
        docs = transport.declarations(self.value, uid(8))
        objects, record = {}, {'context': {'operation': self.value['operation']}, 'objects': {}, 'cleanupStarted': False}
        for number, key in enumerate(('job', 'binding', 'role'), 8):
            obj = copy.deepcopy(docs[key]); obj['metadata'].update(uid=uid(number), resourceVersion=str(number))
            path = transport.path_for(obj)
            objects[path] = obj
            record['objects'][key] = {'path': path, 'identity': transport.identity(obj), 'fingerprint': transport.fingerprint(obj)}
        for resumed in (False, True):
            calls = []
            state = copy.deepcopy(record); state['cleanupStarted'] = resumed
            def request(path, method='GET', body=None):
                if method == 'DELETE': calls.append(path); return {}
                return copy.deepcopy(objects[path])
            result = transport.cleanup(request, state, Mock())
            expected = ['binding', 'job', 'role'] if resumed else ['job', 'binding', 'role']
            self.assertEqual(calls, [record['objects'][key]['path'] for key in expected])
            self.assertTrue(result['bindingRevocationRequested'])
        calls = []
        def failed_job(path, method='GET', body=None):
            if method == 'DELETE':
                calls.append(path)
                if path == record['objects']['job']['path']: raise RuntimeError('job delete unconfirmed')
                return {}
            return copy.deepcopy(objects[path])
        with self.assertRaises(RuntimeError): transport.cleanup(failed_job, copy.deepcopy(record), Mock())
        self.assertEqual(calls, [record['objects']['job']['path'], record['objects']['binding']['path']])
        bad = copy.deepcopy(record)
        bad['objects']['binding']['path'] = '/other'
        observed = []
        def scoped_request(path, method='GET', body=None):
            observed.append(path)
            return copy.deepcopy(objects[path]) if method == 'GET' else {}
        with self.assertRaises(RuntimeError): transport.cleanup(scoped_request, bad, Mock())
        self.assertNotIn('/other', observed)

    def test_dashboard_requires_complete_exact_ready_line_before_exclusive_process_guard(self):
        marker = b'Argo CD UI is available at http://127.0.0.1:12346'
        for case in ('fragmented-ready', 'wrong-port', 'no-marker', 'extra-member'):
            process = Mock(pid=12345)
            process.stdout.fileno.return_value = 9
            channel = Mock()
            channel.__enter__ = Mock(return_value=channel)
            channel.__exit__ = Mock(return_value=False)
            channel.getsockname.return_value = ('127.0.0.1', 12346)
            channel.connect_ex.return_value = 111
            clock = [0]
            chunks = ([marker, b'', b'\n', b''] if case == 'fragmented-ready' else
                [marker.replace(b'12346', b'12347') + b'\n', b''] if case == 'wrong-port' else
                [marker + b'\n', b''] if case == 'extra-member' else [b''])
            def read(_fd, _count): return chunks.pop(0) if chunks else b''
            def sleep(_seconds):
                guard.assert_not_called()  # An early socket or startup child cannot release the caller.
                clock[0] += 1
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(transport, 'core_binary', return_value='/usr/local/bin/argocd'), \
                    patch.object(transport.subprocess, 'Popen', return_value=process), \
                    patch.object(transport.socket, 'socket', return_value=channel), \
                    patch.object(transport.os, 'set_blocking'), patch.object(transport.os, 'read', side_effect=read), \
                    patch.object(transport.os, 'waitid', return_value=None), \
                    patch.object(transport.time, 'monotonic', side_effect=lambda: clock[0]), \
                    patch.object(transport.time, 'sleep', side_effect=sleep), \
                    patch.object(transport, 'owned_listener', side_effect=RuntimeError('extra member') if case == 'extra-member' else None,
                        return_value=True) as guard, patch.object(transport, 'stop_core') as cleanup:
                if case == 'fragmented-ready':
                    with transport.dashboard(Path(temporary), Mock(server='https://10.43.0.1:443'), 2):
                        self.assertEqual(clock[0], 1)
                        guard.assert_called_once()
                else:
                    with self.assertRaisesRegex(RuntimeError, 'extra member' if case == 'extra-member' else 'deadline expired'):
                        with transport.dashboard(Path(temporary), Mock(server='https://10.43.0.1:443'), 2):
                            self.fail('Core released caller before valid readiness and process guard')
                    if case == 'extra-member': guard.assert_called_once()
                    else: guard.assert_not_called()
                cleanup.assert_called_once_with(process)

    def test_dashboard_environment_and_flags_bind_same_private_kubeconfig(self):
        process = Mock(pid=12345)
        process.stdout.fileno.return_value = 9
        channel = Mock()
        channel.__enter__ = Mock(return_value=channel)
        channel.__exit__ = Mock(return_value=False)
        channel.getsockname.return_value = ('127.0.0.1', 12346)
        channel.connect_ex.return_value = 111
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(transport, 'core_binary', return_value='/usr/local/bin/argocd'), \
                patch.object(transport.subprocess, 'Popen', return_value=process) as launch, \
                patch.object(transport.socket, 'socket', return_value=channel), \
                patch.object(transport.os, 'set_blocking'), patch.object(transport.os, 'read', side_effect=[b'Argo CD UI is available at http://127.0.0.1:12346\n', b'', b'']), \
                patch.object(transport.os, 'waitid', return_value=None), \
                patch.object(transport, 'owned_listener', return_value=True), patch.object(transport, 'stop_core') as stop:
            client = Mock(server='https://10.43.0.1:443')
            with transport.dashboard(Path(temporary), client, time.monotonic() + 10): pass
            arguments = launch.call_args.args[0]
            config = Path(temporary) / 'kubeconfig'
            self.assertEqual(launch.call_args.kwargs['env']['KUBECONFIG'], str(config))
            self.assertEqual(arguments[arguments.index('--kubeconfig') + 1], str(config))
            self.assertEqual(arguments[arguments.index('--config') + 1], str(Path(temporary) / 'argo-config'))
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            document = json.loads(config.read_bytes())
            self.assertEqual(document['users'][0]['user'], {'tokenFile': str(transport.TOKEN)})
            self.assertEqual(document['clusters'][0]['cluster'],
                {'server': client.server, 'certificate-authority': str(transport.CA)})
            stop.assert_called_once_with(process)

    def test_api_read_near_core_deadline_cannot_use_longer_pod_deadline(self):
        client = object.__new__(transport.NativeClient)
        client.value = self.value
        client.deadline = 90
        client.paths = {transport.SETS + transport.PARENT}
        def stalled(address, timeout):
            self.assertEqual(timeout, 1)
            self.assertEqual(client.deadline, 60)
            raise TimeoutError('synthetic stalled API read')
        with patch.object(transport.time, 'monotonic', side_effect=[0, 59, 59]), \
                patch.object(transport, 'TOKEN', Mock(read_text=Mock(return_value='a.b.c'))), \
                patch.object(transport.socket, 'create_connection', side_effect=stalled) as connect:
            with self.assertRaises(TimeoutError): transport.native_read(self.value, Path('/unused'), client)
            connect.assert_called_once()
        self.assertEqual(client.deadline, 90)

    def test_core_request_deadline_and_fixed_operations_fail_closed(self):
        with patch.object(transport.socket, 'create_connection') as connect:
            with self.assertRaises(RuntimeError): transport.core_request(12345, 'create', b'{}', time.monotonic() + 1, [1024], lambda: None)
            with self.assertRaises(RuntimeError): transport.core_request(12345, 'generate', b'{}', time.monotonic() - 1, [1024], lambda: None)
            connect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
