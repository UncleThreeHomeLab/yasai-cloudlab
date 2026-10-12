import copy
import unittest
from unittest.mock import patch

from automation.services.remote import inspect
from automation.services.tests.fixtures import definition, approval


class ReadinessTests(unittest.TestCase):
    def test_private_host_denial_uses_verified_public_tls_and_requires_http_404(self):
        value = definition()
        value['exposure'] = {'class': 'private', 'hostname': 'service.internal.example.invalid',
                             'access': 'tailnet', 'path': '/', 'port': 8080}
        def get(kind, name=None, namespace=None):
            if kind.startswith('httproute.'):
                return {'spec': {'hostnames': ['cd.example.invalid']}}
            if name == 'cloudlab-istio': return {'spec': {'clusterIP': '10.43.0.1'}}
            if name == 'cloudlab-tailnet':
                return {'status': {'loadBalancer': {'ingress': [{'ip': '100.64.0.1'}]}}}
            raise AssertionError((kind, name))
        request = {'action': 'private-boundary', 'definition': value, 'approval': approval()}
        with patch('automation.services.remote.get', side_effect=get), \
                patch('automation.services.remote.direct_https', return_value=(404, b'')) as https:
            self.assertEqual(inspect(request), {'privatePeer': '100.64.0.1'})
            self.assertEqual(https.call_args.args[0], 'https://cd.example.invalid/')
            self.assertEqual(https.call_args.args[2]['Host'], value['exposure']['hostname'])
            for status in (200, 401, 403):
                https.return_value = (status, b'')
                with self.assertRaisesRegex(RuntimeError, 'reachable'): inspect(request)

    def test_pinned_parent_source_and_exact_external_source_are_required(self):
        value, allowed = definition(), approval()
        platform = {'repoURL': 'https://github.com/example/platform.git', 'targetRevision': 'b' * 40}
        source = dict(platform, path='charts/service', helm={'valuesObject': value})
        application = {'spec': {'project': allowed['name'], 'destination': {
            'server': 'https://kubernetes.default.svc', 'namespace': allowed['namespace']},
            'sources': [source, {'repoURL': allowed['repository'], 'targetRevision': allowed['revision'], 'ref': 'values'}]},
            'status': {'health': {'status': 'Healthy'}, 'sync': {'status': 'Synced'}}}
        deployment = {'metadata': {'generation': 1}, 'status': {'observedGeneration': 1, 'availableReplicas': value['replicas']},
                      'spec': {'template': {'spec': {'containers': [{'image': value['image']}]}}}}
        def get(kind, name=None, namespace=None):
            if kind.startswith('application.'):
                return {'spec': {'source': platform}} if name == 'cloudlab-services' else application
            if kind == 'deployment': return deployment
            if kind == 'resourcequota': return {'spec': {'hard': {'requests.cpu': '1'}}}
            raise AssertionError(kind)
        request = {'action': 'backend', 'definition': value, 'approval': allowed}
        with patch('automation.services.remote.get', side_effect=get):
            inspect(request)
            original = copy.deepcopy(application)
            for index, field, wrong in ((0, 'targetRevision', 'c' * 40), (0, 'path', 'unapproved'),
                                        (1, 'targetRevision', 'd' * 40), (1, 'repoURL', platform['repoURL'])):
                application['spec']['sources'][index][field] = wrong
                with self.assertRaises(RuntimeError): inspect(request)
                application = copy.deepcopy(original)
            allowed['repository'] = platform['repoURL']
            application['spec'].pop('sources')
            application['spec']['source'] = copy.deepcopy(original['spec']['sources'][0])
            inspect(request)
