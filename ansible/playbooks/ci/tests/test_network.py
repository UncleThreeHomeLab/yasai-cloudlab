"""Shared CI policies keep only bounded, explicit internal exceptions."""
import copy
import unittest
from unittest.mock import patch

from playbooks.ci.files.chart import render
from playbooks.ci.files.network import configuration
from playbooks.ci.files import network_verify


class NetworkTests(unittest.TestCase):
    def inputs(self):
        return {'apiServiceCIDRs': ['10.43.0.1'], 'apiEndpointCIDRs': ['100.64.0.2'],
                'registryCIDRs': ['100.64.0.3']}

    def test_only_unique_bounded_private_hosts_can_be_exceptions(self):
        self.assertEqual(configuration(self.inputs())['registryCIDRs'], ['100.64.0.3/32'])
        for value in ([], ['0.0.0.0'], ['8.8.8.8'], ['127.0.0.1'], ['169.254.0.1'],
                      ['10.0.0.0/8'], ['::1'], ['10.0.0.1'] * 2, ['10.0.0.1'] * 5):
            document = self.inputs()
            document['registryCIDRs'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                configuration(document)
        with self.assertRaises(ValueError): configuration(dict(self.inputs(), extra=[]))

    def test_every_namespace_gets_default_deny_and_exact_egress_exceptions(self):
        image = {'repository': 'registry.example.invalid/cloudlab-public/ci-controller',
                 'tag': '0.15.0@sha256:' + 'a' * 64}
        values = {'network': configuration(self.inputs()), 'arc': {'image': image}}
        policies = [row for row in render(values) if row['kind'] == 'NetworkPolicy']
        self.assertEqual({row['metadata']['namespace'] for row in policies},
                         {'cloudlab-ci-system', 'cloudlab-ci-private'})
        for policy in policies:
            spec = policy['spec']
            self.assertEqual(spec['podSelector'], {})
            self.assertEqual(spec['policyTypes'], ['Ingress', 'Egress'])
            self.assertEqual(spec['ingress'], [])
            dns, public = spec['egress'][:2]
            self.assertEqual(dns['to'], [{'namespaceSelector': {'matchLabels': {
                'kubernetes.io/metadata.name': 'kube-system'}}, 'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}])
            self.assertEqual(dns['ports'], [{'protocol': 'UDP', 'port': 53}, {'protocol': 'TCP', 'port': 53}])
            self.assertEqual(public['ports'], [{'protocol': 'TCP', 'port': 443}])
            self.assertTrue({'10.0.0.0/8', '100.64.0.0/10', '172.16.0.0/12', '192.168.0.0/16',
                             '169.254.0.0/16', '127.0.0.0/8'} <= set(public['to'][0]['ipBlock']['except']))
            internal = {(peer['ipBlock']['cidr'], port['port']) for rule in spec['egress'][2:]
                        for peer in rule['to'] if 'ipBlock' in peer for port in rule['ports']}
            expected = {('10.43.0.1/32', 443), ('100.64.0.2/32', 6443)}
            if policy['metadata']['namespace'] != 'cloudlab-ci-system': expected.add(('100.64.0.3/32', 443))
            self.assertEqual(internal, expected)
        values['manageSystemNamespace'] = False
        values['arc']['flags'] = {'watchSingleNamespace': 'cloudlab-ci-public-another'}
        policies = [row for row in render(values) if row['kind'] == 'NetworkPolicy']
        self.assertEqual([row['metadata']['namespace'] for row in policies], ['cloudlab-ci-public-another'])

    def test_enforcement_refuses_missing_or_broad_exceptions(self):
        values = {'network': configuration(self.inputs()), 'arc': {'image': {
            'repository': 'registry.example.invalid/cloudlab-public/ci-controller',
            'tag': '0.15.0@sha256:' + 'a' * 64}}}
        import subprocess
        with self.assertRaises(subprocess.CalledProcessError): render({'arc': values['arc']})
        for replacement in ([], ['0.0.0.0/0'], ['10.0.0.0/8']):
            bad = copy.deepcopy(values)
            bad['network']['registryCIDRs'] = replacement
            with self.assertRaises(subprocess.CalledProcessError): render(bad)

    def test_live_verifier_rejects_added_ingress_private_networks_or_ports(self):
        image = {'repository': 'registry.example.invalid/cloudlab-public/ci-controller',
                 'tag': '0.15.0@sha256:' + 'a' * 64}
        policy = next(row for row in render({'network': configuration(self.inputs()), 'arc': {'image': image}})
                      if row['kind'] == 'NetworkPolicy')
        network_verify.validate(policy)
        canonical = copy.deepcopy(policy)
        del canonical['spec']['ingress']
        network_verify.validate(canonical)
        for defect in ('ingress', 'selector', 'public-port', 'private-range', 'missing-exclusion'):
            changed = copy.deepcopy(policy)
            spec = changed['spec']
            if defect == 'ingress': spec['ingress'] = [{}]
            elif defect == 'selector': spec['podSelector'] = {'matchLabels': {'skip': 'others'}}
            elif defect == 'public-port': spec['egress'][1]['ports'][0]['port'] = 80
            elif defect == 'private-range': spec['egress'][2]['to'][0]['ipBlock']['cidr'] = '10.0.0.0/8'
            else: spec['egress'][1]['to'][0]['ipBlock']['except'].remove('10.0.0.0/8')
            with self.subTest(defect=defect), self.assertRaises(ValueError): network_verify.validate(changed)

    def test_fixture_receives_no_identity_or_write_credentials_and_cleanup_checks_uid(self):
        secret = {'spec': {'dataFrom': [{'extract': {'key': 'harbor-cloudlab-public-pull'}}]}}
        namespace = 'cloudlab-ci-proof-' + 'a' * 12
        resources = network_verify.fixture(namespace, 'node', 'registry.example.invalid/cloudlab-public/ci-runner@sha256:' + 'a' * 64, secret)
        quota, delivery, pod = resources
        self.assertEqual(quota['spec']['hard']['pods'], '1')
        self.assertEqual(delivery['spec'], secret['spec'])
        self.assertFalse(pod['spec']['automountServiceAccountToken'])
        self.assertFalse(pod['spec']['hostUsers'])
        self.assertEqual(pod['spec']['activeDeadlineSeconds'], 600)
        self.assertEqual(pod['spec']['volumes'], [{'name': 'ca', 'configMap': {'name': 'kube-root-ca.crt'}}])
        with patch.object(network_verify, 'get', return_value={'metadata': {'uid': 'original', 'labels': network_verify.LABELS}}), \
                patch.object(network_verify, 'kubectl', return_value='') as command:
            with self.assertRaises(ValueError): network_verify.retire(namespace, 'changed')
            with self.assertRaises(ValueError): network_verify.retire('production', 'original')
            command.assert_not_called()
            network_verify.retire(namespace, 'original')
            deletion = command.call_args_list[0]
            self.assertEqual(deletion.args[:3], ('delete', '--raw', '/api/v1/namespaces/' + namespace))
            self.assertEqual(deletion.kwargs['document']['preconditions'], {'uid': 'original'})
