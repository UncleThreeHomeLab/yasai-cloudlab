"""Fail-closed input, credential separation and external policy contracts."""
import base64
import copy
import json
import unittest
from unittest.mock import Mock, patch

from automation.connectivity import cloudflare, contract, tailnet
from automation.connectivity import provider_http


class ContractTests(unittest.TestCase):
    def test_provider_inventory_honors_pagination_even_when_pages_are_small(self):
        api = cloudflare.API('fixture-token')
        with patch.object(api, 'request', side_effect=[([{'id': 'first'}], {'total_pages': 2}),
                                                      ([{'id': 'second'}], {'total_pages': 2})]) as request:
            self.assertEqual(len(api.collection('accounts/fixture/access/apps')), 2)
            self.assertEqual(request.call_count, 2)

    def test_credential_tag_preparation_preserves_all_access_rules(self):
        current = {'grants': [{'src': ['existing'], 'dst': ['existing'], 'ip': ['*']}],
                   'tagOwners': {'tag:unrelated': ['existing']}, 'autoApprovers': {'routes': {}}}
        desired = tailnet.tag_owners(current, 'admin@example.invalid')
        self.assertEqual(desired['grants'], current['grants'])
        self.assertEqual(desired['autoApprovers'], current['autoApprovers'])
        self.assertEqual(desired['tagOwners']['tag:unrelated'], ['existing'])
        self.assertEqual(tailnet.tag_owners(desired, 'admin@example.invalid'), desired)

    def test_public_hostnames_never_include_private_names_wildcards_or_paths(self):
        for name in ('internal', '*.internal', 'app.internal', 'app/path', '-app', 'APP'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                contract.host_rules([{'name': name, 'access': 'public'}], 'example.invalid')

    def test_hostname_classification_requires_explicit_rule_and_unique_name(self):
        for rules in ([], [{'name': 'app'}], [{'name': 'app', 'access': 'bypass'}],
                      [{'name': 'app', 'access': 'human'}, {'name': 'app', 'access': 'public'}]):
            with self.subTest(rules=rules), self.assertRaises(ValueError):
                contract.host_rules(rules, 'example.invalid')

    def test_hostnames_sort_without_changing_classification(self):
        actual = contract.host_rules([{'name': 'z', 'access': 'machine'}, {'name': 'a', 'access': 'human'}], 'example.invalid')
        self.assertEqual(actual, [{'hostname': 'a.example.invalid', 'access': 'human'}, {'hostname': 'z.example.invalid', 'access': 'machine'}])

    def test_private_names_reject_duplicate_or_nested_names(self):
        for names in ([], ['app', 'app'], ['nested.app']):
            with self.assertRaises(ValueError):
                contract.private_names(names)

    def test_tunnel_selection_rejects_account_and_identity_mismatch(self):
        token = base64.b64encode(json.dumps({'a': 'account', 't': 'tunnel', 's': 'secret'}).encode()).decode()
        contract.tunnel_identity(token, 'account', 'tunnel')
        for account, tunnel in (('other', 'tunnel'), ('account', 'other')):
            with self.assertRaises(ValueError):
                contract.tunnel_identity(token, account, tunnel)

    def test_invalid_tunnel_credential_errors_do_not_include_credential(self):
        with self.assertRaises(ValueError) as failure:
            contract.tunnel_identity('not-a-valid-secret-token', 'account', 'tunnel')
        self.assertNotIn('not-a-valid-secret-token', str(failure.exception))

    def test_gateway_addresses_cannot_select_public_or_wrong_network(self):
        contract.gateway_address('100.64.1.2', tailnet=True)
        contract.gateway_address('10.43.1.2', tailnet=False)
        for address, is_tailnet in [('192.0.2.1', True), ('10.43.1.2', True), ('100.64.1.2', False)]:
            with self.assertRaises(ValueError):
                contract.gateway_address(address, tailnet=is_tailnet)

    def test_transport_configuration_requires_access_audience_for_protected_hosts(self):
        with self.assertRaises(ValueError):
            cloudflare.tunnel_config([{'hostname': 'human.example.invalid', 'access': 'human'}], {}, 'team')

    def test_verified_origin_https_and_unknown_host_catchall(self):
        result = cloudflare.tunnel_config([{'hostname': 'human.example.invalid', 'access': 'human'}],
                                         {'human.example.invalid': 'audience'}, 'team')
        rules = result['config']['ingress']
        self.assertEqual(rules[-1], {'service': 'http_status:404'})
        self.assertTrue(rules[0]['service'].startswith('https://'))
        origin = rules[0]['originRequest']
        self.assertIs(origin['noTLSVerify'], False)
        self.assertEqual(origin['originServerName'], 'human.example.invalid')
        self.assertEqual(origin['httpHostHeader'], origin['originServerName'])
        self.assertTrue(origin['access']['required'])

    def test_human_machine_rules_cannot_bypass_each_other(self):
        human = cloudflare.access_application({'hostname': 'human.example.invalid', 'access': 'human'},
                human_email='admin@example.invalid', identity_provider='otp')
        machine = cloudflare.access_application({'hostname': 'machine.example.invalid', 'access': 'machine'},
                service_token_id='token')
        self.assertEqual(human['allowed_idps'], ['otp'])
        self.assertEqual(human['policies'][0]['include'], [{'email': {'email': 'admin@example.invalid'}}])
        self.assertEqual(human['policies'][0]['decision'], 'allow')
        self.assertEqual(machine['policies'][0]['decision'], 'non_identity')
        self.assertEqual(machine['policies'][0]['include'], [{'service_token': {'token_id': 'token'}}])
        self.assertNotIn('allowed_idps', machine)

    def test_machine_identity_requires_persisted_service_token(self):
        with self.assertRaises(ValueError):
            cloudflare.access_application({'hostname': 'machine.example.invalid', 'access': 'machine'})

    def test_tunnel_builder_rejects_private_hosts_even_without_input_parser(self):
        for name in ('app.internal.example.invalid', '*.example.invalid', 'app.example.invalid/path'):
            with self.assertRaises(ValueError):
                cloudflare.tunnel_config([{'hostname': name, 'access': 'public'}], {}, None)

    def test_tunnel_builder_rejects_duplicate_and_unknown_classifications(self):
        for rules in ([], [{'hostname': 'app.example.invalid', 'access': 'bypass'}],
                      [{'hostname': 'app.example.invalid', 'access': 'public'}] * 2):
            with self.assertRaises(ValueError):
                cloudflare.tunnel_config(rules, {}, None)

    def test_public_hosts_do_not_receive_fake_authentication(self):
        with self.assertRaises(ValueError):
            cloudflare.access_application({'hostname': 'public.example.invalid', 'access': 'public'})
        result = cloudflare.tunnel_config([{'hostname': 'public.example.invalid', 'access': 'public'}], {}, None)
        self.assertNotIn('access', result['config']['ingress'][0]['originRequest'])

    def test_policy_preserves_unrelated_access_and_is_idempotent(self):
        current = {'tagOwners': {'tag:other': ['other@example.invalid']},
                   'grants': [{'src': ['other@example.invalid'], 'dst': ['tag:other'], 'ip': ['*']}],
                   'autoApprovers': {'routes': {'10.0.0.0/24': ['tag:other']}}}
        before = copy.deepcopy(current)
        desired = tailnet.candidate(current, 'admin@example.invalid', ['other@example.invalid'])
        self.assertEqual(current, before)
        self.assertEqual(desired['grants'][0], current['grants'][0])
        self.assertEqual(desired['autoApprovers']['routes'], current['autoApprovers']['routes'])
        self.assertEqual(tailnet.candidate(desired, 'admin@example.invalid', ['other@example.invalid']), desired)
        self.assertIn({'src': 'other@example.invalid', 'deny': ['tag:cloudlab-private:443', 'tag:cloudlab-api-proxy:443']}, desired['tests'])

    def test_policy_refuses_implicit_allow_all_and_foreign_owners(self):
        with self.assertRaises(ValueError):
            tailnet.candidate({}, 'admin@example.invalid')
        with self.assertRaises(ValueError):
            tailnet.candidate({'grants': [], 'tagOwners': {'tag:cloudlab-operator': ['other@example.invalid']}}, 'admin@example.invalid')

    def test_policy_refuses_broader_existing_own_grant(self):
        current = {'grants': [{'src': ['*'], 'dst': ['tag:cloudlab-private'], 'ip': ['*']}]}
        with self.assertRaises(ValueError):
            tailnet.candidate(current, 'admin@example.invalid')

    def test_split_dns_preserves_other_domains_and_refuses_silent_takeover(self):
        current = {'other.invalid': ['100.64.2.1']}
        desired = tailnet.split_dns(current, 'internal.example.invalid', ['100.64.1.2', '100.64.1.1'])
        self.assertEqual(desired['other.invalid'], current['other.invalid'])
        self.assertEqual(tailnet.split_dns(desired, 'internal.example.invalid', ['100.64.1.1', '100.64.1.2']), desired)
        with self.assertRaises(ValueError):
            tailnet.split_dns(desired, 'internal.example.invalid', ['100.64.1.3', '100.64.1.2'])

    def test_split_dns_cannot_publish_public_resolver_or_single_host(self):
        for addresses in (['1.1.1.1', '100.64.1.1'], ['100.64.1.1'], ['100.64.1.1', '100.64.1.1']):
            with self.assertRaises(ValueError):
                tailnet.split_dns({}, 'internal.example.invalid', addresses)

    def test_permission_probe_never_adopts_or_deletes_existing_app(self):
        api = Mock()
        api.request.return_value = [{'domain': 'access-permission-probe.example.invalid'}]
        with self.assertRaises(RuntimeError):
            cloudflare.permission_probe(api, 'account', 'example.invalid')
        self.assertEqual([call.args[0] for call in api.request.call_args_list], ['GET'])

    def test_permission_probe_denies_everyone_and_removes_only_created_app(self):
        api = Mock()
        api.request.side_effect = [[], {'id': 'fixture'}, {'domain': 'access-permission-probe.example.invalid'}, {}, []]
        result = cloudflare.permission_probe(api, 'account', 'example.invalid')
        self.assertTrue(result['deny_all_fixture_removed'])
        calls = api.request.call_args_list
        self.assertEqual(calls[1].args[2]['policies'][0]['decision'], 'deny')
        self.assertEqual(calls[3].args, ('DELETE', 'accounts/account/access/apps/fixture'))

    def test_permission_probe_cleanup_runs_after_verification_error(self):
        api = Mock()
        api.request.side_effect = [[], {'id': 'fixture'}, RuntimeError('read failed'), {}]
        with self.assertRaises(RuntimeError):
            cloudflare.permission_probe(api, 'account', 'example.invalid')
        self.assertEqual(api.request.call_args_list[-1].args, ('DELETE', 'accounts/account/access/apps/fixture'))

    def test_api_rejects_invalid_paths_before_network(self):
        api = cloudflare.API('token')
        for path in ('https://other.invalid', '../accounts', '/accounts', 'accounts/secret#fragment'):
            with self.assertRaises(ValueError):
                api.request('GET', path)

    def test_provider_credentials_cannot_follow_http_redirects(self):
        import urllib.request
        request = urllib.request.Request('https://api.cloudflare.com/client/v4/accounts', headers={'Authorization': 'Bearer private-token'})
        self.assertIsNone(provider_http.RejectRedirect().redirect_request(request, None, 302, 'Found', {}, 'https://other.invalid'))

    def test_api_errors_do_not_include_private_provider_responses(self):
        import urllib.error
        import io
        error = urllib.error.HTTPError('https://private.invalid', 403, 'private-error', {}, io.BytesIO(b'private-token'))
        with patch.object(cloudflare, 'open_request', side_effect=error), self.assertRaises(RuntimeError) as failure:
            cloudflare.API('private-token').request('GET', 'accounts')
        self.assertEqual(str(failure.exception), 'Cloudflare API GET failed: HTTP 403')


if __name__ == '__main__':
    unittest.main()
