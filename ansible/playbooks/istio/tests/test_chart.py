"""Mesh packaging must retain private exposure and a single resource owner."""
import copy
import io
import json
import subprocess
import tarfile
import unittest
from pathlib import Path

import yaml

import chart
import fixtures
import vendor_charts


class MeshChartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.groups = {name: chart.render(name) for name in vendor_charts.PATHS}

    def test_locked_components_and_existing_gateway_api(self):
        self.assertEqual(chart.validate(self.groups), 46)
        self.assertEqual(len(chart.gateway_api()), 10)
        self.assertEqual(len(chart.gateways()), 4)

    def test_competing_owners_and_mutable_images_fail(self):
        groups = copy.deepcopy(self.groups)
        groups['istiod'].append(copy.deepcopy(groups['base'][0]))
        with self.assertRaisesRegex(ValueError, 'competing'):
            chart.validate(groups)
        groups = copy.deepcopy(self.groups)
        deployment = next(o for o in groups['istiod'] if o['kind'] == 'Deployment')
        deployment['spec']['template']['spec']['containers'][0]['image'] = 'pilot:latest'
        with self.assertRaisesRegex(ValueError, 'pinned'):
            chart.validate(groups)

    def test_public_service_and_missing_crd_retention_fail(self):
        groups = copy.deepcopy(self.groups)
        next(o for o in groups['istiod'] if o['kind'] == 'Service')['spec']['type'] = 'LoadBalancer'
        with self.assertRaisesRegex(ValueError, 'internal'):
            chart.validate(groups)
        groups = copy.deepcopy(self.groups)
        next(o for o in groups['base'] if o['kind'] == 'CustomResourceDefinition')['metadata']['annotations'] = {}
        with self.assertRaisesRegex(ValueError, 'retention'):
            chart.validate(groups)

    def test_patch_changes_only_base_crd_template(self):
        def members(raw):
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                return {member.name: archive.extractfile(member).read() for member in archive}
        for component in vendor_charts.PATHS:
            raw = (vendor_charts.ROOT / component / 'upstream.tgz').read_bytes()
            before, after = members(raw), members(vendor_charts.patched(raw, component))
            self.assertEqual(before.keys(), after.keys())
            changed = [name for name in before if before[name] != after[name]]
            self.assertEqual(changed, ['base/templates/crds.yaml'] if component == 'base' else [])
            if changed:
                self.assertEqual(after[changed[0]].replace(vendor_charts.ANNOTATION, b''), before[changed[0]])

    def test_k3s_cni_paths_and_explicit_ambient_enrollment(self):
        daemon = next(o for o in self.groups['cni'] if o['kind'] == 'DaemonSet')
        paths = {v['hostPath']['path'] for v in daemon['spec']['template']['spec']['volumes'] if 'hostPath' in v}
        self.assertTrue({'/var/lib/rancher/k3s/data/cni', '/var/lib/rancher/k3s/agent/etc/cni/net.d'} <= paths)
        self.assertNotIn('istio.io/dataplane-mode', fixtures.namespace('plain')['metadata']['labels'])
        self.assertEqual(fixtures.namespace('mesh', ambient=True)['metadata']['labels']['istio.io/dataplane-mode'], 'ambient')

    def test_no_namespace_or_workload_ownership_in_gateway_project(self):
        root = chart.ROOT.parents[2] / 'gitops/roots/public'
        raw = subprocess.check_output(['helm', 'template', 'root', str(root), '--set', 'mesh.enabled=true'])
        projects = {o['metadata']['name']: o['spec'] for o in yaml.safe_load_all(raw) if o and o['kind'] == 'AppProject'}
        gateway = projects['cloudlab-gateways']
        self.assertEqual(gateway['clusterResourceWhitelist'], [])
        self.assertEqual({r['kind'] for r in gateway['namespaceResourceWhitelist']}, {'Gateway', 'ConfigMap'})
        self.assertEqual({d['namespace'] for d in gateway['destinations']}, {'cloudlab-gateway-public', 'cloudlab-gateway-private'})

    def test_network_denial_uses_the_same_authorized_identity(self):
        allowed = fixtures.pod('mesh', 'allowed', 'pinned-image', 'allowed')
        denied = fixtures.pod('mesh', 'denied', 'pinned-image', 'allowed', network=False)
        self.assertEqual(allowed['spec']['serviceAccountName'], denied['spec']['serviceAccountName'])
        self.assertNotEqual(allowed['metadata']['labels'], denied['metadata']['labels'])
        ports = fixtures.network_policy('mesh', allow_hbone=True)['spec']['ingress'][0]['ports']
        self.assertEqual({p['port'] for p in ports}, {15008})
        self.assertEqual(fixtures.network_policy('mesh', allow_hbone=False)['spec']['ingress'], [])

    def test_nonroot_backend_can_write_only_its_ephemeral_content_volume(self):
        backend = fixtures.pod('fixture', 'backend', 'pinned-image', 'backend', server=True)['spec']
        self.assertEqual(backend['securityContext']['fsGroup'], backend['securityContext']['runAsGroup'])
        self.assertTrue(backend['containers'][0]['securityContext']['readOnlyRootFilesystem'])
        self.assertEqual(backend['volumes'], [{'name': 'www', 'emptyDir': {'sizeLimit': '1Mi'}}])


class SharedGatewayTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[4]

    def render(self, path, values, success=True):
        files = ['-f', str(self.root / path / 'values.json')] if path == 'platform/connectivity/gateways' else []
        result = subprocess.run(['helm', 'template', 'cloudlab-gateways', str(self.root / path), *files, '-f', '-'],
                                input=json.dumps(values), capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode == 0, success, result.stderr if success else 'invalid input accepted')
        return [o for o in yaml.safe_load_all(result.stdout) if o] if success else []

    def shared(self):
        from playbooks.keycloak.files.integrations import argo
        return {'zone': 'example.invalid', 'production': True, 'sharedInputs': True,
                **argo('https://login.example.invalid/realms/platform', 'https://cd.example.invalid',
                       ['https://cd.internal.example.invalid'])['helm']}

    def test_shared_documents_preserve_exact_legacy_resources(self):
        native = self.render('platform/connectivity/gateways', self.shared())
        legacy = self.render('platform/connectivity/gateways', {'zone': 'example.invalid',
            'argo': {'public': 'cd.example.invalid', 'private': 'cd.internal.example.invalid'}})
        self.assertEqual(native, legacy)
        self.assertEqual(len(native), 6)
        # Shared identity values cannot implicitly select native mode.
        values = self.shared(); values.pop('sharedInputs')
        self.assertEqual(len(self.render('platform/connectivity/gateways', values)), 4)

    def test_shared_input_failures_are_not_empty_route_intent(self):
        for missing in ('argo-cd', 'production'):
            values = self.shared(); values.pop(missing)
            self.render('platform/connectivity/gateways', values, False)
        for malformed in ({}, {'configs': {}}, {'configs': {'cm': {}, 'rbac': {}}}):
            values = self.shared(); values['argo-cd'] = malformed
            self.render('platform/connectivity/gateways', values, False)
        for oidc in ('', '[]', 'issuer: https://foreign.invalid/realms/platform\nclientID: argocd',
                     'issuer: https://login.example.invalid/realms/platform\nclientID: foreign'):
            values = self.shared(); values['argo-cd']['configs']['cm']['oidc.config'] = oidc
            self.render('platform/connectivity/gateways', values, False)
        for origin in ('https://cd.example.invalid:443', 'https://u@cd.example.invalid', 'https://cd.example.invalid/',
                       'https://cd.example.invalid?q=1', 'https://cd.example.invalid#f', 'https://cd.example.invalid ',
                       'https://deep.cd.example.invalid', 'https://internal.example.invalid',
                       'https://cd.internal.example.invalid', 'http://cd.example.invalid'):
            values = self.shared(); values['argo-cd']['configs']['cm']['url'] = origin
            self.render('platform/connectivity/gateways', values, False)
        for additional in ('', '[]', '- https://cd.internal.example.invalid\n- https://other.example.invalid', '{}'):
            values = self.shared(); values['argo-cd']['configs']['cm']['additionalUrls'] = additional
            self.render('platform/connectivity/gateways', values, False)
        values = self.shared(); values['argo'] = {'public': 'other.example.invalid', 'private': 'cd.internal.example.invalid'}
        self.render('platform/connectivity/gateways', values, False)

    def binding(self):
        return {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}

    def native_root(self):
        return {'identity': {'argo': self.binding()}, 'mesh': {'configuration': {'enabled': True, 'revision': 'a' * 40}}}

    def test_root_disabled_and_absent_binding_preserve_existing_graph(self):
        path = 'gitops/roots/public'
        base = self.render(path, {})
        self.assertEqual(base, self.render(path, {'mesh': {'configuration': {'enabled': False}}}))
        self.assertEqual(base, self.render(path, {'mesh': {'configuration': {'enabled': True}}}))
        with_binding = self.render(path, {'identity': {'argo': self.binding()}, 'mesh': {'configuration': {'enabled': False}}})
        self.assertFalse(any(o['metadata']['name'] == 'cloudlab-gateways-source' for o in with_binding))
        self.assertFalse(any(o['kind'] == 'Application' and o['metadata']['name'] == 'cloudlab-gateways' for o in base))

    def test_native_root_is_scoped_and_retains_credentials(self):
        path = 'gitops/roots/public'; values = self.native_root(); native = self.render(path, values)
        app = next(o for o in native if o['kind'] == 'Application' and o['metadata']['name'] == 'cloudlab-gateways')
        self.assertIsNone(app['spec']['source'])
        source = app['spec']['sources'][0]
        self.assertEqual(source['targetRevision'], 'a' * 40)
        self.assertEqual(source['path'], 'platform/connectivity/gateways')
        self.assertEqual(source['helm'], {'releaseName': 'cloudlab-gateways', 'valuesObject': {'sharedInputs': True},
            'valueFiles': ['values.json', '$values/platform/certificates.yaml', '$identity/identity/argo-values.yaml']})
        self.assertEqual(app['spec']['sources'][1], {'repoURL': self.binding()['valuesRepository'], 'targetRevision': 'main', 'ref': 'values'})
        self.assertEqual(app['spec']['sources'][2], {'repoURL': self.binding()['valuesRepository'], 'targetRevision': 'b' * 40, 'ref': 'identity'})
        self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
        self.assertNotIn('finalizers', app['metadata'])
        baseline = self.render(path, {'identity': {'argo': self.binding()}, 'mesh': {'configuration': {'enabled': False}}})
        for name in ('cloudlab-istio-base', 'cloudlab-istio-istiod', 'cloudlab-istio-cni', 'cloudlab-istio-ztunnel'):
            self.assertEqual([o for o in native if o['metadata']['name'] == name], [o for o in baseline if o['metadata']['name'] == name])
        project = next(o['spec'] for o in native if o['kind'] == 'AppProject' and o['metadata']['name'] == 'cloudlab-gateways')
        old = next(o['spec'] for o in baseline if o['kind'] == 'AppProject' and o['metadata']['name'] == 'cloudlab-gateways')
        self.assertEqual(project | {'sourceRepos': old['sourceRepos']}, old)
        self.assertEqual(project['sourceRepos'][1:], [self.binding()['valuesRepository']])
        eso = next(o for o in native if o['metadata']['name'] == 'cloudlab-gateways-source')
        target = eso['spec']['target']
        self.assertEqual((target['creationPolicy'], target['deletionPolicy']), ('Owner', 'Retain'))
        self.assertEqual(target['template']['data']['project'], 'cloudlab-gateways')
        self.assertEqual(target['template']['data']['url'], self.binding()['valuesRepository'])
        self.assertEqual(eso['spec']['dataFrom'], [{'extract': {'key': 'github-argocd'}}])
        self.assertEqual(eso['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')

    def test_native_root_rejects_bad_binding_pin_and_prerequisites(self):
        path = 'gitops/roots/public'
        for binding in ({}, None, False, self.binding() | {'valuesRevision': 'main'}):
            values = self.native_root(); values['identity']['argo'] = binding
            self.render(path, values, False)
        for pin in ('main', '', 'a' * 39):
            values = self.native_root(); values['mesh']['configuration']['revision'] = pin
            self.render(path, values, False)
        for field in ('enabled', 'reconcile'):
            for invalid in (False, 'true'):
                values = self.native_root(); values['externalSecrets'] = {field: invalid}
                self.render(path, values, False)


if __name__ == '__main__':
    unittest.main()
