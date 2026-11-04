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
