"""Reject DNS injection and forwarding loops before host changes."""
import unittest
from automation.connectivity.dns import configuration
from automation.connectivity.dns_tailnet import dns_policy


class DNSTests(unittest.TestCase):
    def test_tailnet_alias_repeat_preserves_unrelated_dns_and_access_policy(self):
        import copy
        from unittest.mock import Mock, patch
        from automation.connectivity import dns_tailnet
        servers = ['100.64.0.1', '100.64.0.2']
        dns = {'internal.example.invalid': servers, 'unrelated.invalid': ['1.1.1.1']}
        policy = dns_policy({}, 'admin@example.invalid', servers)
        writes = []
        def request(method, path, data=None, *args):
            if path.endswith('/dns/split-dns'):
                if method == 'PATCH': dns.update(data); writes.append(copy.deepcopy(data))
                return copy.deepcopy(dns), None
            if path.endswith('/acl/validate'): return [], None
            if path.endswith('/acl'):
                self.assertEqual(method, 'GET')
                return copy.deepcopy(policy), 'fixture-etag'
            if path.endswith('/devices'): return {'devices': []}, None
            raise AssertionError('Unexpected API operation')
        payload = {'zone': 'internal.example.invalid', 'identity_host': 'login.example.invalid', 'nameservers': servers}
        with patch.object(dns_tailnet, 'API', return_value=Mock(request=Mock(side_effect=request))), \
                patch.dict('os.environ', {'TAILSCALE_ADMIN_LOGIN': 'admin@example.invalid'}), patch('builtins.print'):
            dns_tailnet.run(payload)
            dns_tailnet.run(payload)
        self.assertEqual(len(writes), 1)
        self.assertEqual(set(writes[0]), {'internal.example.invalid', 'login.example.invalid'})
        self.assertEqual(dns['unrelated.invalid'], ['1.1.1.1'])

    def test_public_peer_lookup_rejects_split_dns_and_uses_independent_resolvers(self):
        from unittest.mock import patch
        from automation.connectivity import dns_wire
        with patch.object(dns_wire, 'query', return_value={'rcode': 0, 'addresses': ['10.43.0.10']}) as query:
            with self.assertRaises(RuntimeError): dns_wire.public_address('login.example.invalid')
            query.assert_called_once_with('1.1.1.1', 'login.example.invalid', tcp=True)
        with patch.object(dns_wire, 'query', side_effect=[TimeoutError(), {'rcode': 0, 'addresses': ['1.1.1.1']}]):
            self.assertEqual(dns_wire.public_address('login.example.invalid'), '1.1.1.1')

    def test_identity_alias_is_exact_private_and_keeps_public_recursion_separate(self):
        files = configuration(dict(self.payload, identity_host='login.example.invalid'))
        self.assertIn('10.43.0.10 login.example.invalid', files['Corefile'])
        self.assertIn('100.100.0.1 login.example.invalid', files['Corefile'])
        self.assertEqual(files['Corefile'].count('login.example.invalid:53'), 2)
        self.assertNotIn('fallthrough', files['Corefile'])
        with self.assertRaises(ValueError): configuration(dict(self.payload, identity_host='other.example.invalid'))

    def setUp(self):
        self.payload = dict(zone='internal.example.invalid', names=['app'], tailnet_address='100.64.0.1',
                            host_address='10.44.0.1', cluster_gateway='10.43.0.10', tailnet_gateway='100.100.0.1',
                            nameservers=['100.64.0.1', '100.64.0.2'], upstreams=['1.1.1.1'])

    def test_repeat_is_deterministic_with_distinct_routable_answers(self):
        files = configuration(self.payload)
        self.assertEqual(files, configuration(self.payload))
        self.assertIn('app IN A 100.100.0.1', files['tailnet.zone'])
        self.assertIn('app IN A 10.43.0.10', files['internal.zone'])
        self.assertNotIn('fallthrough', files['Corefile'])
        self.assertNotIn('forward', files['Corefile'].split('.:53')[0])

    def test_labels_cannot_inject_records_or_use_reserved_names(self):
        for name in ['app\nother IN A 1.1.1.1', '*.app', 'ns1', 'app.internal']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                configuration(dict(self.payload, names=[name]))

    def test_local_and_tailnet_upstreams_cannot_create_forwarding_loops(self):
        for upstream in ['127.0.0.1', '100.100.100.100', '10.44.0.2', '10.43.0.10']:
            with self.subTest(upstream=upstream), self.assertRaises(ValueError):
                configuration(dict(self.payload, upstreams=[upstream]))

    def test_public_listener_or_public_gateway_is_rejected(self):
        for key in ['tailnet_address', 'host_address', 'cluster_gateway', 'tailnet_gateway']:
            with self.subTest(key=key), self.assertRaises(ValueError):
                configuration(dict(self.payload, **{key: '1.1.1.1'}))

    def test_both_hosts_publish_identical_zone_records(self):
        other = dict(self.payload, host_address='10.44.0.2', tailnet_address='100.64.0.2')
        for view in ('tailnet.zone', 'internal.zone'):
            self.assertEqual(configuration(other)[view], configuration(self.payload)[view])

    def test_dns_grants_preserve_host_ssh_and_deny_other_users(self):
        ssh = {'src': ['admin@example.invalid'], 'dst': ['tag:cloudlab-host'], 'ip': ['tcp:22']}
        current = {'grants': [ssh]}
        desired = dns_policy(current, 'admin@example.invalid', self.payload['nameservers'], ['other@example.invalid'])
        self.assertEqual(desired['grants'][0], ssh)
        self.assertEqual(len(desired['grants']), 2)
        self.assertEqual(len([t for t in desired['tests'] if t['src'] == 'other@example.invalid' and 'deny' in t]), 2)
        self.assertEqual(dns_policy(desired, 'admin@example.invalid', self.payload['nameservers'], ['other@example.invalid']), desired)


if __name__ == '__main__':
    unittest.main()
