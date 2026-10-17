import unittest
from unittest.mock import Mock, patch
from playbooks.argocd.files import private_publish


class PrivatePublicationTests(unittest.TestCase):
    def test_stale_validated_base_refuses_before_writes(self):
        api = Mock()
        api.request.return_value = {'object': {'sha': 'b' * 40}}
        with patch.object(private_publish, 'inspect', return_value={'size': 1}):
            with self.assertRaisesRegex(RuntimeError, 'advanced after validation'):
                private_publish.publish(api, {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'},
                    {'services/catalog.json': '{}'}, scope='services', expected_base='a' * 40)
        self.assertEqual([call.args[0] for call in api.request.call_args_list], ['GET'])

    def test_disappeared_validated_base_cannot_seed_an_empty_repository(self):
        api = Mock()
        api.request.side_effect = RuntimeError('GitHub repository operation failed: HTTP 409')
        with patch.object(private_publish, 'inspect', return_value={'size': 0}):
            with self.assertRaisesRegex(RuntimeError, 'unavailable after validation'):
                private_publish.publish(api, {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'},
                    {'services/catalog.json': '{}'}, scope='services', expected_base='a' * 40)
        self.assertEqual([call.args[0] for call in api.request.call_args_list], ['GET'])
