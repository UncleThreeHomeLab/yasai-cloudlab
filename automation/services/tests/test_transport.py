import unittest
import copy
from unittest.mock import patch

from automation.services.transport import policy, run
from automation.services.tests.fixtures import definition, approval


class TransportTests(unittest.TestCase):
    def test_rendered_platform_policy_selects_the_owned_workload_labels(self):
        from automation.services.gitops import resources
        value, allowed = definition(), approval()
        objects = resources(value, allowed, 'https://github.com/example/platform.git', 'a' * 40)
        selected = next(obj for obj in objects if obj['kind'] == 'AuthorizationPolicy')
        self.assertEqual(selected['spec']['selector'], {'matchLabels': {'cloudlab.io/owner': value['owner']}})

    def test_live_capture_precedes_allowed_and_denied_probes_and_cleanup(self):
        entry = {'definition': definition(), 'approval': approval()}
        namespace = entry['approval']['namespace']
        ready = [{'type': 'Ready', 'status': 'True'}]
        backend = {'metadata': {'labels': {'app.kubernetes.io/name': 'synthetic'}},
                   'spec': {'nodeName': 'main'}, 'status': {'conditions': ready, 'podIP': '10.42.0.8'}}
        pods, created, probes, deleted = {}, [], [], []
        def get(kind, name=None, namespace=None):
            if kind == 'pods': return {'items': [backend]}
            if kind == 'nodes': return {'items': [{'metadata': {'name': 'worker'}, 'status': {'conditions': ready}}]}
            if kind == 'pod': return pods[name]
            raise AssertionError(kind)
        def kube(*arguments, document=None):
            if arguments[0] == 'create':
                pod = copy.deepcopy(document)
                pod['metadata'].update(uid=pod['metadata']['name'], annotations={'ambient.istio.io/redirection': 'enabled'})
                pod['status'] = {'phase': 'Running', 'conditions': ready}
                pods[pod['metadata']['name']] = pod
                created.append(pod)
            elif arguments[0] == 'exec':
                pod = pods[arguments[3]]
                self.assertEqual(pod['spec']['containers'][0]['command'], ['sleep', '3600'])
                self.assertEqual(pod['status']['phase'], 'Running')
                probes.append(pod['spec']['serviceAccountName'])
                return 'allowed' if probes[-1] == 'synthetic' else 'denied'
            elif arguments[:2] == ('delete', 'pod'): deleted.append(arguments[2])
            else: raise AssertionError(arguments)
            return ''
        def wait(predicate, label, timeout): self.assertTrue(predicate())
        with patch('automation.services.transport.policy', return_value='synthetic'), \
                patch('automation.services.transport.get', side_effect=get), \
                patch('automation.services.transport.kube', side_effect=kube), \
                patch('automation.services.transport.wait', side_effect=wait):
            result = run(entry, 'pinned-fixture-image')
        self.assertTrue(result['cross_node_workload_identity'])
        self.assertEqual(probes, ['synthetic', 'default'])
        self.assertEqual(len(created), 2)
        self.assertEqual(deleted, [pod['metadata']['name'] for pod in created])
        self.assertTrue(all(pod['metadata']['namespace'] == namespace and
                            pod['spec']['nodeSelector'] == {'kubernetes.io/hostname': 'worker'} for pod in created))

    def test_workload_policy_rejects_extra_principals_or_an_author_owner(self):
        entry = {'definition': definition(), 'approval': approval()}
        obj = {'metadata': {'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-services:owned'}},
               'spec': {'selector': {'matchLabels': {'cloudlab.io/owner': entry['definition']['owner']}}, 'action': 'ALLOW', 'rules': [{'from': [{'source': {
                   'principals': ['cluster.local/ns/cloudlab-app-synthetic/sa/synthetic']}}]}]}}
        with patch('automation.services.transport.get', return_value=obj):
            self.assertEqual(policy(entry), 'synthetic')
            obj['spec']['rules'][0]['from'][0]['source']['principals'].append('*')
            with self.assertRaises(RuntimeError): policy(entry)
            obj['spec']['rules'][0]['from'][0]['source']['principals'].pop()
            obj['spec']['selector'] = {}
            with self.assertRaises(RuntimeError): policy(entry)
            obj['spec']['selector'] = {'matchLabels': {'cloudlab.io/owner': entry['definition']['owner']}}
            obj['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'synthetic-synthetic:owned'
            with self.assertRaises(RuntimeError): policy(entry)
