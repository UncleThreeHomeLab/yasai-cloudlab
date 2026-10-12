import copy
import unittest
from unittest.mock import patch

from automation.services.remote import inspect
from automation.services.tests.fixtures import definition, approval


class ReadinessTests(unittest.TestCase):
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
