"""Preserve upstream schemas, controller ownership and unverified health limitations."""
import copy
import io
import tarfile
import unittest

from automation.connectivity import chart, vendor_operator


class ChartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.operator = chart.render(chart.ROOT / 'platform/connectivity/tailscale-operator')
        cls.access = chart.render(chart.ROOT / 'platform/connectivity/access', 'admin@example.invalid')

    def test_locked_render_preserves_supported_modes_and_does_not_claim_health_probes(self):
        result = chart.validate(self.operator, self.access)
        self.assertEqual(result['proxygroup_replicas'], 2)
        self.assertIs(result['resources_applied'], False)
        self.assertIs(result['proxy_probe_support'], False)

    def test_vendor_patch_changes_only_retention_annotations(self):
        before = (vendor_operator.ROOT / 'upstream.tgz').read_bytes()
        after = vendor_operator.patched(before)
        self.assertEqual(after, vendor_operator.patched(before))
        with tarfile.open(fileobj=io.BytesIO(before)) as source, tarfile.open(fileobj=io.BytesIO(after)) as target:
            self.assertEqual(source.getnames(), target.getnames())
            changes = 0
            for name in source.getnames():
                original, patched = source.extractfile(name).read(), target.extractfile(name).read()
                if original != patched:
                    changes += 1
                    self.assertEqual(patched.replace(b'    argocd.argoproj.io/sync-options: ServerSideApply=true,Prune=false,Delete=false\n', b''), original)
            self.assertEqual(changes, 8)

    def test_api_noauth_is_rejected(self):
        access = copy.deepcopy(self.access)
        next(x for x in access if x['kind'] == 'ProxyGroup' and x['metadata']['name'] == 'cloudlab-api')['spec']['kubeAPIServer']['mode'] = 'noauth'
        with self.assertRaises(ValueError):
            chart.validate(self.operator, access)

    def test_proxyclass_cannot_invent_unsupported_probe_fields(self):
        access = copy.deepcopy(self.access)
        next(x for x in access if x['kind'] == 'ProxyClass')['spec']['statefulSet']['pod']['readinessProbe'] = {}
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            chart.validate(self.operator, access)

    def test_public_nodeport_is_rejected(self):
        access = copy.deepcopy(self.access)
        next(x for x in access if x['kind'] == 'Service')['spec']['allocateLoadBalancerNodePorts'] = True
        with self.assertRaises(ValueError):
            chart.validate(self.operator, access)

    def test_connector_cannot_reach_private_gateway_through_declared_policy(self):
        boundary = next(x for x in self.access if x['kind'] == 'NetworkPolicy')
        namespaces = [peer.get('namespaceSelector', {}).get('matchLabels', {}).get('kubernetes.io/metadata.name')
                      for rule in boundary['spec']['egress'] for peer in rule.get('to', [])]
        self.assertIn('cloudlab-gateway-public', namespaces)
        self.assertNotIn('cloudlab-gateway-private', namespaces)
        external = next(peer['ipBlock'] for rule in boundary['spec']['egress'] for peer in rule.get('to', [])
                        if peer.get('ipBlock', {}).get('cidr') == '0.0.0.0/0')
        self.assertIn('10.0.0.0/8', external['except'])
        self.assertIn('100.64.0.0/10', external['except'])

    def test_cannot_add_second_owner_for_generated_workload(self):
        with self.assertRaisesRegex(ValueError, 'competing'):
            chart.validate(self.operator, self.access + [copy.deepcopy(self.access[0])])


if __name__ == '__main__':
    unittest.main()
