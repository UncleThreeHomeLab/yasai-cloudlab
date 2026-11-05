"""Native chart owners form an acyclic graph and protect retained resources."""
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import unittest

import yaml

from playbooks.observability.files.chart import render
from playbooks.observability.files.package import projections, retained
from playbooks.observability.tests.fixtures import helm, native_overrides, native_source_inputs

ROOT = Path(__file__).resolve().parents[4]
IDENTITIES = {('PodMonitor', name) for name in ('notes', 'mesh-control', 'mesh-ambient', 'mesh-gateways')}
IDENTITIES |= {('ServiceMonitor', name) for name in ('alloy', 'native-dns')}
IDENTITIES |= {('HTTPRoute', name) for name in ('grafana', 'kiali')}


class NativeLifecycleTests(unittest.TestCase):
    def test_native_alertmanager_uses_only_retained_claim_template(self):
        values = native_overrides(native_source_inputs())['cloudlab-prometheus']
        self.assertIs(values['kube-prometheus-stack']['cloudlabNativeLifecycle'], True)
        manager = next(o for o in render('prometheus', values) if o['kind'] == 'Alertmanager')
        expected = values['kube-prometheus-stack']['alertmanager']['alertmanagerSpec']
        self.assertEqual(manager['spec']['storage'], {'volumeClaimTemplate': expected['storage']['volumeClaimTemplate']})
        self.assertEqual(manager['spec']['persistentVolumeClaimRetentionPolicy'],
                         {'whenDeleted': 'Retain', 'whenScaled': 'Retain'})

    def test_native_loki_adapter_closes_governing_service_without_changing_persistent_identity(self):
        values = native_overrides(native_source_inputs())['cloudlab-loki']
        self.assertIs(values['loki']['cloudlabNativeLifecycle'], True)
        native, legacy = render('loki', values), render('loki')
        statefulset = next(o for o in native if o['kind'] == 'StatefulSet')
        previous = next(o for o in legacy if o['kind'] == 'StatefulSet')
        service = next(o for o in native if o['kind'] == 'Service' and o['metadata']['name'] == statefulset['spec']['serviceName'])
        self.assertEqual(service['spec']['clusterIP'], 'None')
        self.assertTrue(all(statefulset['spec']['template']['metadata']['labels'][key] == value
                            for key, value in service['spec']['selector'].items()))
        for field in ('selector', 'serviceName', 'volumeClaimTemplates'):
            self.assertEqual(statefulset['spec'][field], previous['spec'][field])
        self.assertTrue(any(o['kind'] == 'Service' and o['metadata']['name'] == 'loki-headless' for o in legacy))
        self.assertFalse(any(o['kind'] == 'Service' and o['metadata']['name'] == 'loki-headless' for o in native))

    def test_legacy_and_native_resources_keep_exact_specs_with_single_native_owner(self):
        projections(check=True)
        inputs = native_source_inputs()
        legacy = helm('platform/observability', dict(inputs['observabilityInputs'], enabled=True))
        expected = {(o['kind'], o['metadata']['name']): o for o in legacy
                    if (o['kind'], o['metadata']['name']) in IDENTITIES}
        self.assertEqual(set(expected), IDENTITIES)
        overrides = native_overrides(inputs)
        configuration = helm('platform/observability', overrides['cloudlab-observability'])
        self.assertFalse(any(o['apiVersion'].startswith('monitoring.coreos.com/') or o['kind'] == 'HTTPRoute'
                             for o in configuration))
        self.assertTrue(any(o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'cloudlab-alloy' for o in configuration))
        actual = {}
        for component in ('prometheus', 'kiali'):
            for obj in render(component, overrides['cloudlab-' + component]):
                key = obj['kind'], obj['metadata']['name']
                if key not in IDENTITIES:
                    continue
                self.assertNotIn(key, actual)
                self.assertEqual(obj, expected[key])
                actual[key] = component
        self.assertEqual(set(actual), IDENTITIES)
        self.assertEqual(actual[('HTTPRoute', 'kiali')], 'kiali')
        self.assertTrue(all(owner == 'prometheus' for key, owner in actual.items() if key != ('HTTPRoute', 'kiali')))
        for component in ('prometheus', 'kiali'):
            self.assertFalse(any((o['kind'], o['metadata']['name']) in IDENTITIES for o in render(component)))

    def test_native_data_and_shared_credentials_are_retained_before_pruning(self):
        overrides = native_overrides(native_source_inputs())
        configuration = helm('platform/observability', overrides['cloudlab-observability'])
        for obj in configuration:
            if obj['kind'] in ('Namespace', 'StorageClass', 'ExternalSecret'):
                self.assertEqual(obj['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')
        prometheus = render('prometheus', overrides['cloudlab-prometheus'])
        pvc = next(o for o in prometheus if o['kind'] == 'PersistentVolumeClaim' and 'grafana' in o['metadata']['name'])
        self.assertEqual(pvc['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')
        loki = render('loki', overrides['cloudlab-loki'])
        statefulset = next(o for o in loki if o['kind'] == 'StatefulSet')
        self.assertEqual(statefulset['spec']['persistentVolumeClaimRetentionPolicy'], {'whenDeleted': 'Retain', 'whenScaled': 'Retain'})
        for obj in render('tempo', overrides['cloudlab-tempo']):
            if obj['kind'] == 'StatefulSet':
                policy = obj['spec'].get('persistentVolumeClaimRetentionPolicy', {})
                self.assertEqual(policy.get('whenDeleted', 'Retain'), 'Retain')
                self.assertEqual(policy.get('whenScaled', 'Retain'), 'Retain')

    def test_native_issuer_egress_is_private_gateway_only_and_legacy_stays_unchanged(self):
        inputs = native_source_inputs()
        values = dict(inputs['observabilityInputs'], enabled=True)
        def private_rules(objects):
            boundary = next(o for o in objects if o['kind'] == 'NetworkPolicy' and o['metadata']['name'] == 'telemetry-boundary')
            return [r for r in boundary['spec']['egress'] if any(
                t.get('namespaceSelector', {}).get('matchLabels', {}).get('kubernetes.io/metadata.name') == 'cloudlab-gateway-private'
                for t in r.get('to', []))]
        self.assertEqual(private_rules(helm('platform/observability', values)), [])
        native = private_rules(helm('platform/observability', native_overrides(inputs)['cloudlab-observability']))
        self.assertEqual(len(native), 1)
        self.assertEqual(native[0]['to'][0]['podSelector'], {'matchLabels': {'gateway.networking.k8s.io/gateway-name': 'cloudlab'}})
        self.assertEqual(native[0]['ports'], [{'protocol': 'TCP', 'port': 443}, {'protocol': 'TCP', 'port': 15008}])


class AlertmanagerNativePackageTests(unittest.TestCase):
    def test_exact_pinned_patch_and_byte_identical_legacy_rendering(self):
        path = ROOT / 'platform/observability/prometheus'
        lock = json.loads((path / 'artifact.lock.json').read_text())
        raw = (path / 'upstream.tgz').read_bytes()
        patched = retained(raw)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), lock['upstream_sha256'])
        self.assertEqual(patched, (path / lock['archive']).read_bytes())
        self.assertEqual(hashlib.sha256(patched).hexdigest(), lock['sha256'])
        self.assertEqual(patched, retained(raw))
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / 'original'
            shutil.copytree(path, original)
            target = 'kube-prometheus-stack/templates/alertmanager/alertmanager.yaml'
            with tarfile.open(fileobj=io.BytesIO(raw)) as source:
                upstream = source.extractfile(target).read()
            output = io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(patched)) as source, tarfile.open(fileobj=output, mode='w:gz') as dest:
                for member in source:
                    data = upstream if member.name == target else source.extractfile(member).read()
                    member.size = len(data)
                    dest.addfile(member, io.BytesIO(data))
            (original / lock['archive']).write_bytes(output.getvalue())
            def rendered(directory, overlay):
                result = subprocess.run(['helm', 'template', 'cloudlab-prometheus', str(directory),
                    '-n', 'cloudlab-observability', '--kube-version', '1.36.5', '-f', str(directory / 'values.json'), '-f', '-'],
                    input=yaml.safe_dump(overlay), capture_output=True, text=True, timeout=90)
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout
            baseline = rendered(original, {})
            self.assertEqual(rendered(path, {}), baseline)
            self.assertEqual(rendered(path, {'kube-prometheus-stack': {'cloudlabNativeLifecycle': False}}), baseline)
            # The source hash rejects a changed template before any artifact can be accepted.
            changed = io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(raw)) as source, tarfile.open(fileobj=changed, mode='w:gz') as dest:
                for member in source:
                    data = source.extractfile(member).read() + (b'\n' if member.name == target else b'')
                    member.size = len(data)
                    dest.addfile(member, io.BytesIO(data))
            with self.assertRaisesRegex(ValueError, 'Pinned Alertmanager template changed'):
                retained(changed.getvalue())

    def test_native_alertmanager_rejects_wrong_types_missing_claim_and_unknown_modes(self):
        values = native_overrides(native_source_inputs())['cloudlab-prometheus']
        for flag in ('true', 1, 0, None, [], {}):
            bad = copy.deepcopy(values)
            bad['kube-prometheus-stack']['cloudlabNativeLifecycle'] = flag
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                render('prometheus', bad)
        for storage in (None, 'claim', [], {'volumeClaimTemplate': None}, {'volumeClaimTemplate': {}},
                        {'ephemeral': {}}, {'unknown': {}, 'volumeClaimTemplate': {'spec': {}}}):
            bad = copy.deepcopy(values)
            bad['kube-prometheus-stack']['alertmanager']['alertmanagerSpec']['storage'] = storage
            with self.subTest(storage=storage), self.assertRaises(ValueError):
                render('prometheus', bad)


class NativeApplicationHealthTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('argocd'), 'Run the pinned native lifecycle Compose image for Lua checks')
    def test_pinned_native_lua_scopes_current_health_and_preserves_legacy_parent_ordering(self):
        version = subprocess.check_output(['argocd', 'version', '--client', '--short'], text=True, timeout=30)
        self.assertEqual(version.split(':', 1)[-1].strip().split('+')[0], 'v3.5.3')
        values = yaml.safe_load((ROOT / 'platform/delivery/argocd/values.yaml').read_text())
        script = values['argo-cd']['configs']['cm']['resource.customizations.health.argoproj.io_Application']
        marker = 'a' * 64
        source = {'repoURL': 'https://github.com/example/platform.git', 'targetRevision': 'b' * 40,
                  'path': 'platform/observability/prometheus', 'helm': {'valuesObject': {
                      'nativeInputDigest': marker, 'nativeLifecycle': {'enabled': True}}}}
        obj = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
               'metadata': {'name': 'cloudlab-prometheus', 'namespace': 'argocd',
                   'labels': {'cloudlab.io/owner': 'observability-platform'}, 'annotations': {
                       'cloudlab.io/observability-health': 'required', 'cloudlab.io/observability-input-digest': marker}},
               'spec': {'source': source, 'project': 'cloudlab-observability', 'destination': {
                   'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-observability'},
                   'syncPolicy': {'automated': {'enabled': True}}},
               'status': {'sync': {'status': 'Synced', 'revision': 'b' * 40,
                                  'comparedTo': {'source': copy.deepcopy(source)}},
                          'operationState': {'phase': 'Succeeded', 'finishedAt': '2026-01-01T00:00:00Z',
                              'syncResult': {'source': copy.deepcopy(source), 'revision': 'b' * 40}},
                          'health': {'status': 'Healthy'}}}
        obj['status']['sync']['comparedTo']['destination'] = copy.deepcopy(obj['spec']['destination'])
        cases = [(copy.deepcopy(obj), 'Healthy')]
        def changed(change, expected):
            row = copy.deepcopy(obj)
            change(row)
            cases.append((row, expected))
        changed(lambda r: r['status']['sync']['comparedTo']['source'].update(targetRevision='c' * 40), 'Progressing')
        changed(lambda r: r['status']['sync']['comparedTo'].pop('destination'), 'Progressing')
        changed(lambda r: r['status']['sync']['comparedTo']['destination'].update(namespace='stale'), 'Progressing')
        changed(lambda r: r['status']['sync']['comparedTo']['destination'].update(server='https://stale.example.invalid'), 'Progressing')
        changed(lambda r: r['spec']['syncPolicy']['automated'].update(enabled=False), 'Progressing')
        changed(lambda r: r.pop('status'), 'Progressing')
        changed(lambda r: r.update(operation={'sync': {}}), 'Progressing')
        changed(lambda r: r['status']['health'].update(status='Progressing', message='Waiting for HTTPRoute status'), 'Progressing')
        changed(lambda r: r['status']['operationState'].pop('finishedAt'), 'Healthy')
        changed(lambda r: r['status'].pop('operationState'), 'Healthy')
        for phase in ('Running', 'Terminating'):
            changed(lambda r, value=phase: r['status']['operationState'].update(phase=value), 'Progressing')
        for phase in ('Succeeded', 'Failed', 'Error'):
            changed(lambda r, value=phase: (r['status']['operationState'].update(phase=value),
                r['status']['operationState']['syncResult'].update(revision='c' * 40),
                r['status']['operationState']['syncResult']['source'].update(targetRevision='c' * 40)), 'Healthy')
        changed(lambda r: r['status']['sync'].update(revision='c' * 40), 'Progressing')
        changed(lambda r: (r['spec']['source']['helm']['valuesObject'].update(nativeInputDigest='c' * 64),
            r['metadata']['annotations'].update({'cloudlab.io/observability-input-digest': 'c' * 64})), 'Progressing')
        changed(lambda r: r['status']['sync'].update(status='OutOfSync'), 'Degraded')
        changed(lambda r: (r['status']['sync'].update(status='OutOfSync'),
                           r['status']['operationState'].update(phase='Running')), 'Progressing')
        changed(lambda r: (r['status']['sync'].update(status='OutOfSync'),
                           r['status']['operationState'].pop('finishedAt')), 'Progressing')
        changed(lambda r: (r['status']['sync'].update(status='OutOfSync'),
                           r['status']['sync']['comparedTo']['source'].update(targetRevision='c' * 40)), 'Progressing')
        changed(lambda r: r['status']['sync'].update(status='Unknown'), 'Progressing')
        changed(lambda r: r['status']['health'].update(status='Unknown'), 'Progressing')
        changed(lambda r: r['status']['health'].update(status='Degraded'), 'Degraded')
        for phase in ('Failed', 'Error'):
            changed(lambda r, value=phase: r['status']['operationState'].update(phase=value), 'Healthy')
            changed(lambda r, value=phase: (r['status']['operationState'].update(phase=value),
                r['status']['sync'].update(status='OutOfSync')), 'Degraded')
        changed(lambda r: (r['status']['sync'].update(status='OutOfSync'),
            r['status'].pop('operationState')), 'Progressing')
        changed(lambda r: r['status'].update(conditions=[{'type': 'ComparisonError', 'message': 'fixture error'}]), 'Degraded')
        changed(lambda r: r['metadata']['annotations'].pop('cloudlab.io/observability-health'), 'Degraded')
        changed(lambda r: r['metadata']['annotations'].pop('cloudlab.io/observability-input-digest'), 'Degraded')
        changed(lambda r: r['metadata'].update(annotations={}), 'Degraded')
        changed(lambda r: r['spec']['source']['helm']['valuesObject'].pop('nativeInputDigest'), 'Degraded')
        for malformed in ('z' * 64, 'A' * 64, ' ' + 'a' * 63, 'a' * 63 + ' ', True):
            changed(lambda r, value=malformed: r['metadata']['annotations'].update(
                {'cloudlab.io/observability-input-digest': value}), 'Degraded')
        for name, path in {'cloudlab-observability': 'platform/observability',
                           'cloudlab-loki': 'platform/observability/loki',
                           'cloudlab-tempo': 'platform/observability/tempo',
                           'cloudlab-alloy': 'platform/observability/alloy',
                           'cloudlab-kiali': 'platform/observability/kiali'}.items():
            row = copy.deepcopy(obj)
            row['metadata']['name'] = name
            row['spec']['source']['path'] = path
            row['status']['sync']['comparedTo']['source'] = copy.deepcopy(row['spec']['source'])
            row['status']['operationState']['syncResult']['source'] = copy.deepcopy(row['spec']['source'])
            cases.append((row, 'Healthy'))
        legacy = copy.deepcopy(obj)
        legacy['metadata']['annotations'] = {}
        legacy['spec']['source']['helm']['valuesObject'] = {'kube-prometheus-stack': {'enabled': True}}
        legacy['status']['health']['status'] = 'Degraded'
        cases.append((legacy, 'Healthy'))
        for controls in ({'nativeInputDigest': marker}, {'nativeLifecycle': {'enabled': True}},
                         {'nativeInputDigest': marker, 'nativeLifecycle': {'enabled': True}}):
            unrelated = copy.deepcopy(legacy)
            unrelated['metadata']['name'] = 'unrelated-chart'
            unrelated['metadata']['labels']['cloudlab.io/owner'] = 'unrelated-owner'
            unrelated['spec']['source']['helm']['valuesObject'] = copy.deepcopy(controls)
            cases.append((unrelated, 'Healthy'))
            # Exact native identity still fails closed when markers and owner are lost.
            native = copy.deepcopy(obj)
            native['metadata']['annotations'] = {}
            native['metadata']['labels']['cloudlab.io/owner'] = 'wrong-owner'
            native['spec']['source']['helm']['valuesObject'] = copy.deepcopy(controls)
            cases.append((native, 'Degraded'))
        for key in ('cloudlab.io/observability-health', 'cloudlab.io/observability-input-digest'):
            renamed = copy.deepcopy(obj)
            renamed['metadata']['name'] = 'unrelated-chart'
            renamed['metadata']['annotations'] = {key: obj['metadata']['annotations'][key]}
            renamed['spec']['source']['helm']['valuesObject'] = {}
            cases.append((renamed, 'Degraded'))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'cm.json').write_text(json.dumps({'apiVersion': 'v1', 'kind': 'ConfigMap',
                'metadata': {'name': 'argocd-cm'}, 'data': {'resource.customizations.health.argoproj.io_Application': script}}))
            for resource, expected in cases:
                with self.subTest(expected=expected, resource=resource):
                    (path / 'object.json').write_text(json.dumps(resource))
                    result = subprocess.run(['argocd', 'admin', 'settings', 'resource-overrides', 'health',
                        str(path / 'object.json'), '--argocd-cm-path', str(path / 'cm.json'),
                        '--load-cluster-settings=false', '--kubeconfig', '/dev/null'],
                        capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('STATUS: ' + expected, result.stdout.splitlines())

    @unittest.skipUnless(shutil.which('argocd'), 'Run the pinned native lifecycle Compose image for Lua checks')
    def test_pinned_route_health_never_ignores_unresolved_backends(self):
        route = {'apiVersion': 'gateway.networking.k8s.io/v1', 'kind': 'HTTPRoute',
                 'metadata': {'name': 'fixture-only', 'generation': 1},
                 'spec': {'parentRefs': [{'name': 'missing'}],
                          'rules': [{'backendRefs': [{'name': 'missing', 'port': 80}]}]}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            config = yaml.safe_load((ROOT / 'platform/delivery/argocd/values.yaml').read_text())['argo-cd']['configs']['cm']
            (path / 'cm.json').write_text(json.dumps({'apiVersion': 'v1', 'kind': 'ConfigMap',
                'metadata': {'name': 'argocd-cm'}, 'data': config}))
            for status in (None, {'parents': [{'parentRef': {'name': 'missing'}, 'controllerName': 'fixture-only',
                    'conditions': [{'type': 'Accepted', 'status': 'True', 'observedGeneration': 1},
                                   {'type': 'ResolvedRefs', 'status': 'False', 'reason': 'BackendNotFound', 'observedGeneration': 1}]}]}):
                if status:
                    route['status'] = status
                (path / 'object.json').write_text(json.dumps(route))
                result = subprocess.run(['argocd', 'admin', 'settings', 'resource-overrides', 'health',
                    str(path / 'object.json'), '--argocd-cm-path', str(path / 'cm.json'),
                    '--load-cluster-settings=false', '--kubeconfig', '/dev/null'], capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('STATUS: Healthy', result.stdout.splitlines())


if __name__ == '__main__':
    unittest.main()
