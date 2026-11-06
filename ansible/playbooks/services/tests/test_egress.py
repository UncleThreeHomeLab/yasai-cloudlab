"""Native administrator egress validation, exact peers and retained deny policy."""
import copy
import json
import subprocess
import unittest

import yaml

from playbooks.services.files.contract import ROOT
from playbooks.services.tests.fixtures import approval, definition, composition_approval, composition_definition


class EgressTests(unittest.TestCase):
    def render(self, allowed=None, *, publication='ready', value=None):
        return subprocess.run(['helm', 'template', 'services', str(ROOT / 'platform/delivery/services'), '-f', '-'],
            input=json.dumps({'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
                              'catalog': [{'definition': value or definition(),
                                           'approval': approval() if allowed is None else allowed,
                                           'publication': publication}]}),
            capture_output=True, text=True, timeout=30)

    def objects(self, allowed=None, **kwargs):
        result = self.render(allowed, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        return [row for row in yaml.safe_load_all(result.stdout) if row]

    def policy(self, allowed=None, **kwargs):
        rows = [row for row in self.objects(allowed, **kwargs)
                if row['kind'] == 'NetworkPolicy' and row['metadata']['name'] == 'platform-egress']
        self.assertEqual(len(rows), 1)
        return rows[0]

    def rule(self):
        return {'namespace': 'kube-system', 'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}},
                'ports': [{'port': 53, 'protocol': 'TCP'}, {'port': 53, 'protocol': 'UDP'}]}

    def external(self, cidr='192.0.2.0/24', **kwargs):
        return {'ipBlock': dict(cidr=cidr, **kwargs), 'ports': [{'port': 443, 'protocol': 'TCP'}]}

    def test_mixed_external_and_namespace_peers_preserve_exact_native_fields(self):
        external = self.external(**{'except': ['192.0.2.128/25', '192.0.2.4/32']})
        policy = self.policy(dict(approval(), egress=[self.rule(), external]))
        self.assertEqual(policy['spec']['egress'][1], {'to': [{'ipBlock': external['ipBlock']}],
                                                      'ports': external['ports']})
        for cidr in ('0.0.0.0/0', '255.255.255.255/32', '128.0.0.0/1'):
            with self.subTest(cidr=cidr):
                self.assertEqual(self.policy(dict(approval(), egress=[self.external(cidr)]))['spec']['egress'][0]['to'],
                                 [{'ipBlock': {'cidr': cidr}}])

    def test_external_invalid_cidrs_exceptions_and_peer_types_fail_even_when_retired(self):
        invalid = [self.external(cidr) for cidr in ('::/0', '2001:db8::/32', '::ffff:192.0.2.1/128',
            '192.0.2.1/24', '256.0.0.0/8', '192.00.2.0/24', '192.0.2.0/024', '192.0.2.0/33',
            '192.0.2.0', 'example.invalid/24', ' 192.0.2.0/24', '192.0.2.0/24\n', None, 24)]
        invalid += [self.external(**{'except': value}) for value in
            (['192.0.2.0/24'], ['192.0.0.0/16'], ['198.51.100.0/24'], ['192.0.2.1/25'], ['::/1'],
             ['192.0.2.0/25'] * 2, [f'192.0.2.{n}/32' for n in range(33)], None, '192.0.2.0/25')]
        invalid += [{'ipBlock': {}, 'ports': self.external()['ports']},
                    dict(self.external(), namespace='peer'), dict(self.external(), podSelector={'matchLabels': {'app': 'x'}}),
                    dict(self.external(), ports=[{'port': 'https', 'protocol': 'TCP'}]),
                    dict(self.external(), ports=[{'port': 443, 'protocol': 'SCTP'}]),
                    dict(self.external(), ipBlock={'cidr': '192.0.2.0/24', 'unknown': True})]
        for rule in invalid:
            for publication in ('ready', 'retired'):
                with self.subTest(rule=rule, publication=publication):
                    self.assertNotEqual(self.render(dict(approval(), egress=[rule]), publication=publication).returncode, 0)

    def test_external_withdrawal_and_retirement_retain_deny_policy(self):
        allowed = dict(approval(), egress=[self.external()])
        active = self.policy(allowed)
        for policy in (self.policy(dict(allowed, egress=[])), self.policy(allowed, publication='retired')):
            self.assertEqual(policy['metadata'], active['metadata'])
            self.assertEqual(policy['spec'], dict(active['spec'], egress=[]))

    def test_required_empty_egress_denies_every_pod_without_implicit_allow(self):
        allowed = approval()
        allowed.pop('egress')
        self.assertNotEqual(self.render(allowed).returncode, 0)
        policy = self.policy()
        self.assertEqual(policy['spec'], {'podSelector': {}, 'policyTypes': ['Egress'], 'egress': []})
        self.assertEqual(policy['metadata'], {'name': 'platform-egress', 'namespace': 'cloudlab-app-synthetic',
                                             'annotations': {'argocd.argoproj.io/sync-wave': '-1'}})
        project = next(row for row in self.objects() if row['kind'] == 'AppProject')
        self.assertNotIn('NetworkPolicy', {row['kind'] for row in project['spec']['namespaceResourceWhitelist']})

    def test_exact_destination_selectors_share_one_peer_and_ports_are_explicit(self):
        rule = self.rule()
        rule['podSelector']['matchLabels']['app.kubernetes.io/name'] = 'resolver'
        policy = self.policy(dict(approval(), egress=[rule]))
        self.assertEqual(policy['spec']['egress'], [{'to': [{
            'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': rule['namespace']}},
            'podSelector': rule['podSelector']}], 'ports': rule['ports']}])

    def test_rule_removal_and_retirement_keep_policy_identity_and_withdraw_allows(self):
        allowed = dict(approval(), egress=[self.rule()])
        active = self.policy(allowed)
        removed = self.policy(dict(allowed, egress=[]))
        retired = self.policy(allowed, publication='retired')
        self.assertTrue(active['spec']['egress'])
        for policy in (removed, retired):
            self.assertEqual(policy['metadata'], active['metadata'])
            self.assertEqual(policy['spec']['egress'], [])
            self.assertEqual(policy['spec']['podSelector'], {})

    def test_broad_malformed_and_unsupported_connections_fail_native_validation(self):
        valid = self.rule()
        invalid = [None, {}, [{}], [dict(valid, namespace='')], [dict(valid, namespace='*')],
                   [dict(valid, namespace='a' * 64)], [dict(valid, namespace='UPPER')],
                   [dict(valid, namespaceSelector={})], [dict(valid, ipBlock={'cidr': '0.0.0.0/0'})],
                   [dict(valid, fqdn='example.invalid')], [dict(valid, podSelector={})],
                   [dict(valid, podSelector={'matchLabels': {}})],
                   [dict(valid, podSelector={'matchExpressions': []})],
                   [dict(valid, podSelector={'matchLabels': {'bad/key/more': 'value'}})],
                   [dict(valid, podSelector={'matchLabels': {'a' * 64: 'value'}})],
                   [dict(valid, podSelector={'matchLabels': {'UPPER.example/key': 'value'}})],
                   [dict(valid, podSelector={'matchLabels': {'key': ''}})],
                   [dict(valid, podSelector={'matchLabels': {'key': 'bad value'}})],
                   [dict(valid, podSelector={'matchLabels': {'key': True}})],
                   [dict(valid, podSelector={'matchLabels': {'key-' + str(index): 'value' for index in range(17)}})],
                   [dict(valid, ports=[])], [dict(valid, ports=[{'port': 53}])],
                   [dict(valid, ports=[{'port': 53, 'protocol': 'SCTP'}])],
                   [dict(valid, ports=[{'port': 'dns', 'protocol': 'TCP'}])],
                   [dict(valid, ports=[{'port': 0, 'protocol': 'TCP'}])],
                   [dict(valid, ports=[{'port': 65536, 'protocol': 'TCP'}])],
                   [dict(valid, ports=[{'port': 53.5, 'protocol': 'TCP'}])],
                   [dict(valid, ports=[{'port': True, 'protocol': 'TCP'}])],
                   [dict(valid, ports=[{'port': 53, 'endPort': 54, 'protocol': 'TCP'}])],
                   [dict(valid, ports=[{'port': 53, 'protocol': 'TCP'}] * 2)],
                   [dict(valid, ports=[{'port': port, 'protocol': 'TCP'} for port in range(1, 18)])],
                   [dict(valid, namespace='peer-' + str(index)) for index in range(33)]]
        for rules in invalid:
            with self.subTest(rules=rules):
                self.assertNotEqual(self.render(dict(approval(), egress=rules)).returncode, 0)

    def test_excluded_notes_and_composition_paths_reject_egress_and_keep_existing_behavior(self):
        notes = dict(approval(), chartPath='apps/notes', repository='https://github.com/example/platform.git')
        composed = composition_approval()
        for allowed, value in ((notes, definition()), (composed, composition_definition())):
            with self.subTest(path=allowed.get('chartPath', 'composition')):
                self.assertNotEqual(self.render(dict(allowed, egress=[]), value=value).returncode, 0)
                allowed = copy.deepcopy(allowed)
                allowed.pop('egress', None)
                self.assertFalse(any(row['kind'] == 'NetworkPolicy' and row['metadata']['name'] == 'platform-egress'
                                     for row in self.objects(allowed, value=value)))
