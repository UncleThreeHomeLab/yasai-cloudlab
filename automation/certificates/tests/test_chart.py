"""Reject unsafe certificate packaging before any live installation."""
import copy
import io
import json
import tarfile
import subprocess
import unittest
from unittest.mock import patch
import yaml

import chart
import vendor_chart


class CertificateChartTests(unittest.TestCase):
    def test_native_argo_routes_attach_only_to_the_matching_gateway_exposure(self):
        namespaces = {o['metadata']['name']: o['metadata']['labels']
                      for o in chart.configuration_render() if o['kind'] == 'Namespace'}
        root = chart.ROOT.parents[1] / 'connectivity/gateways'
        raw = subprocess.check_output(['helm', 'template', 'gateways', str(root), '-f', str(root / 'values.json'),
            '--set', 'zone=example.invalid', '--set', 'argo.public=cd.example.invalid',
            '--set', 'argo.private=cd.internal.example.invalid'])
        objects = [o for o in yaml.safe_load_all(raw) if o]
        gateways = {o['metadata']['namespace']: o for o in objects if o['kind'] == 'Gateway'}
        routes = [o for o in objects if o['kind'] == 'HTTPRoute']
        self.assertEqual(len(routes), 2)
        for route in routes:
            namespace = route['metadata']['namespace']
            selector = gateways[namespace]['spec']['listeners'][0]['allowedRoutes']['namespaces']
            self.assertEqual(selector['from'], 'Selector')
            labels = selector['selector']['matchLabels']
            self.assertTrue(all(namespaces[namespace].get(k) == v for k, v in labels.items()))
            other = next(name for name in namespaces if name != namespace)
            self.assertFalse(all(namespaces[other].get(k) == v for k, v in labels.items()))

    @classmethod
    def setUpClass(cls):
        cls.objects = chart.render()
        cls.lock = vendor_chart.verify()

    def altered(self, objects):
        data = '\n---\n'.join(json.dumps(obj) for obj in objects).encode()
        with patch.object(chart.subprocess, 'check_output', side_effect=[self.lock['helm_version'], data, data]):
            return chart.render()

    def test_vendor_patch_changes_only_six_crd_annotations(self):
        def members(raw):
            with tarfile.open(fileobj=io.BytesIO(raw)) as package:
                return {obj.name: package.extractfile(obj).read() for obj in package}
        raw = (chart.ROOT / 'upstream.tgz').read_bytes()
        original, result = members(raw), members(vendor_chart.patched(raw))
        self.assertEqual(original.keys(), result.keys())
        changed = [name for name in original if original[name] != result[name]]
        self.assertEqual(len(changed), 6)
        for name in changed:
            self.assertTrue(name.startswith('cert-manager/templates/crd-'))
            self.assertEqual(result[name].replace(
                b'    argocd.argoproj.io/sync-options: ServerSideApply=true,Prune=false,Delete=false\n', b''), original[name])

    def test_mutable_image_and_public_service_are_rejected(self):
        objects = copy.deepcopy(self.objects)
        next(obj for obj in objects if obj['kind'] == 'Deployment')['spec']['template']['spec']['containers'][0]['image'] = 'unsafe:latest'
        with self.assertRaisesRegex(ValueError, 'image'):
            self.altered(objects)
        objects = copy.deepcopy(self.objects)
        next(obj for obj in objects if obj['kind'] == 'Service')['spec']['type'] = 'LoadBalancer'
        with self.assertRaisesRegex(ValueError, 'private'):
            self.altered(objects)

    def test_retention_and_hook_guards(self):
        objects = copy.deepcopy(self.objects)
        next(obj for obj in objects if obj['kind'] == 'CustomResourceDefinition')['metadata']['annotations'].pop('argocd.argoproj.io/sync-options')
        with self.assertRaisesRegex(ValueError, 'retention'):
            self.altered(objects)
        objects = copy.deepcopy(self.objects)
        objects[0]['metadata'].setdefault('annotations', {})['helm.sh/hook'] = 'pre-delete'
        with self.assertRaisesRegex(ValueError, 'hooks'):
            self.altered(objects)

    def test_credentials_remain_eso_owned_with_explicit_template(self):
        secret = next(obj for obj in self.objects if obj['kind'] == 'ExternalSecret')['spec']
        self.assertEqual(secret['target']['creationPolicy'], 'Owner')
        self.assertEqual(secret['target']['deletionPolicy'], 'Retain')
        self.assertEqual(secret['target']['template']['mergePolicy'], 'Replace')
        self.assertEqual(set(secret['target']['template']['data']), {'API_TOKEN', 'ZONE_ID'})
        self.assertFalse(any(obj['kind'] == 'Secret' for obj in self.objects))

    def test_staging_excludes_production_and_invalid_zone_is_rejected(self):
        objects = chart.configuration_render()
        self.assertFalse(any(obj['metadata']['name'] == 'cloudlab-acme-production' for obj in objects))
        self.assertEqual(sum(obj['kind'] == 'Certificate' for obj in objects), 1)
        self.assertEqual(sum(obj['kind'] == 'Certificate' for obj in chart.configuration_render(production=True)), 3)
        for zone in ['*.example.invalid', 'example.invalid/path', 'example.invalid\nother']:
            with self.subTest(zone=zone), self.assertRaises(subprocess.CalledProcessError):
                chart.configuration_render(zone)

    def test_projects_restrict_credential_and_gateway_ownership(self):
        path = chart.ROOT.parents[2] / 'gitops/roots/public'
        raw = subprocess.check_output(['helm', 'template', 'root', str(path), '--set', 'certificates.enabled=true'])
        projects = {obj['metadata']['name']: obj['spec'] for obj in yaml.safe_load_all(raw)
                    if obj and obj['kind'] == 'AppProject'}
        operator = projects['cloudlab-cert-manager']
        configuration = projects['cloudlab-certificates']
        self.assertEqual([item['namespace'] for item in operator['destinations']], ['cert-manager'])
        self.assertEqual({item['namespace'] for item in configuration['destinations']},
                         {'cert-manager', 'cloudlab-gateway-public', 'cloudlab-gateway-private'})
        for project in (operator, configuration):
            kinds = {item['kind'] for item in project['namespaceResourceWhitelist']}
            self.assertFalse({'Secret', 'Application', 'AppProject', 'Gateway', 'HTTPRoute', '*'} & kinds)
        self.assertEqual(configuration['namespaceResourceWhitelist'], [{'group': 'cert-manager.io', 'kind': 'Certificate'}])


if __name__ == '__main__':
    unittest.main()
