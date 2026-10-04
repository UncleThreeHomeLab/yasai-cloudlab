"""Mesh packaging must retain private exposure and a single resource owner."""
import copy
import io
import json
import subprocess
import tarfile
import unittest

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


if __name__ == '__main__':
    unittest.main()
