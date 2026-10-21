import base64
import copy
import json
import unittest
from unittest.mock import Mock, patch
from playbooks.services.files import source
from playbooks.services.tests.fixtures import definition, approval


class PublicationTests(unittest.TestCase):
    def test_catalog_publication_cannot_drop_retained_data_scope(self):
        before = {'catalog': [], 'dataApprovals': {}, 'retainedDataRequests': [{'service': 'retained'}]}
        api = Mock()
        api.request.side_effect = [{'object': {'sha': 'a' * 40}},
                                   {'content': base64.b64encode(json.dumps(before).encode()).decode()}]
        with patch.object(source, 'WRITER', ({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}, api)), \
                patch('playbooks.argocd.files.private_publish.publish') as publish, self.assertRaises(ValueError):
            source.publish({'catalog': [], 'dataApprovals': {}})
        publish.assert_not_called()

    def test_validation_and_publisher_use_one_immutable_base(self):
        value = {'catalog': [], 'dataApprovals': {}}
        api = Mock()
        api.request.side_effect = [{'object': {'sha': 'a' * 40}},
                                   {'content': base64.b64encode(json.dumps(value).encode()).decode()}]
        environment = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        with patch.object(source, 'WRITER', (environment, api)), \
                patch('playbooks.argocd.files.private_publish.publish', return_value={'private_source_changed': False}) as publish:
            source.publish(value, expected=value)
        self.assertEqual(api.request.call_args_list[1].args[1].split('?ref=')[1], 'a' * 40)
        self.assertEqual(publish.call_args.kwargs['expected_base'], 'a' * 40)
