"""Native DNS gates reject foreign resources before configuration writes."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

BASE = Path(__file__).resolve().parents[1]


class ClusterDNSTests(unittest.TestCase):
    def setUp(self):
        self.values = {
            'access_dns_core': {'data': {'Corefile': 'import /etc/coredns/custom/*.server'}},
            'access_dns_application': {'metadata': {'uid': 'retained-app', 'resourceVersion': '12', 'labels': {
                'cloudlab.io/owner': 'cloudlab-private-dns-bootstrap'}}},
            'access_dns_custom': {'metadata': {'uid': 'retained-configmap'}},
            'access_dns_retained': {'application.argoproj.io': 'retained-app', 'configmap': 'retained-configmap'},
            'access_dns_source': {'repository': 'https://github.com/example/platform.git', 'branch': 'main'},
            'access_dns_inputs': {'zone': 'internal.example.invalid'},
            'ansible_python_interpreter': sys.executable,
        }

    def run_native(self, values):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / 'accepted.json'
            play = [{'hosts': 'localhost', 'connection': 'local', 'gather_facts': False,
                'vars': values, 'tasks': [
                    {'ansible.builtin.import_tasks': str(BASE / 'tasks/cluster-dns-check.yml')},
                    {'ansible.builtin.copy': {
                        'content': "{{ lookup('ansible.builtin.template', '" +
                            str(BASE / 'templates/cluster-dns-application.yml.j2') + "') | from_yaml | to_json }}",
                        'dest': str(marker), 'mode': '0600'}},
                ]}]
            path = root / 'play.yml'
            path.write_text(yaml.safe_dump(play, sort_keys=False))
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', str(path)],
                capture_output=True, text=True, timeout=60)
            return result, json.loads(marker.read_text()) if marker.exists() else None

    def test_retained_application_renders_only_custom_dns_owner(self):
        result, document = self.run_native(self.values)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(document['kind'], 'Application')
        self.assertEqual(document['metadata']['name'], 'cloudlab-private-dns')
        self.assertEqual(document['metadata']['uid'], 'retained-app')
        self.assertNotIn('resourceVersion', document['metadata'])
        self.assertEqual(document['spec']['source']['path'], 'platform/connectivity/private-dns')
        self.assertEqual(document['spec']['source']['helm']['valuesObject'], {'zone': 'internal.example.invalid'})
        self.assertEqual(document['spec']['syncPolicy']['automated'], {
            'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False})

    def test_empty_resources_allow_first_declaration(self):
        result, document = self.run_native(dict(self.values,
            access_dns_application={}, access_dns_custom={}, access_dns_retained={}))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIsNotNone(document)

    def test_conflicting_owner_or_metadata_refuses_before_write(self):
        for metadata in ({'labels': {'cloudlab.io/owner': 'another-owner'}},
                         {'finalizers': ['foreign']}, {'ownerReferences': [{'uid': 'foreign'}]}):
            with self.subTest(metadata=metadata):
                values = copy.deepcopy(self.values)
                values['access_dns_application']['metadata'].update(metadata)
                result, document = self.run_native(values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(document)
                self.assertIn('ownership conflict', result.stdout)

    def test_replaced_or_missing_resources_refuse_retained_receipt(self):
        for key, value in (('access_dns_custom', {}), ('access_dns_application', {}),
                           ('access_dns_custom', {'metadata': {'uid': 'replaced'}})):
            with self.subTest(resource=key, value=value):
                result, document = self.run_native(dict(self.values, **{key: value}))
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(document)

    def test_existing_custom_configmap_cannot_be_adopted_without_application(self):
        result, document = self.run_native(dict(self.values, access_dns_application={}, access_dns_retained={}))
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(document)

    def test_missing_native_coredns_interface_refuses_before_write(self):
        result, document = self.run_native(dict(self.values, access_dns_core={'data': {'Corefile': '.:53 {}'}}))
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(document)
        self.assertIn('custom forwarding interface', result.stdout)


if __name__ == '__main__':
    unittest.main()
