import unittest
from unittest.mock import patch

from automation.services.transport import policy
from automation.services.tests.fixtures import definition, approval


class TransportTests(unittest.TestCase):
    def test_workload_policy_rejects_extra_principals_or_an_author_owner(self):
        entry = {'definition': definition(), 'approval': approval()}
        obj = {'metadata': {'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-services:owned'}},
               'spec': {'selector': {}, 'action': 'ALLOW', 'rules': [{'from': [{'source': {
                   'principals': ['cluster.local/ns/cloudlab-app-synthetic/sa/synthetic']}}]}]}}
        with patch('automation.services.transport.get', return_value=obj):
            self.assertEqual(policy(entry), 'synthetic')
            obj['spec']['rules'][0]['from'][0]['source']['principals'].append('*')
            with self.assertRaises(RuntimeError): policy(entry)
            obj['spec']['rules'][0]['from'][0]['source']['principals'].pop()
            obj['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'synthetic-synthetic:owned'
            with self.assertRaises(RuntimeError): policy(entry)
