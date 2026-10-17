import base64
import copy
import json
import unittest
from unittest.mock import Mock, patch
from playbooks.services.files import source
from playbooks.services.tests.direct_git import restored_catalog
from playbooks.services.tests.fixtures import definition, approval


class PublicationTests(unittest.TestCase):
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

    def test_fixture_restoration_preserves_unrelated_current_records_and_approvals(self):
        entry = {'definition': definition(), 'approval': approval(), 'publication': 'retired'}
        active = copy.deepcopy(entry)
        active['definition']['environment']['DIRECT_GIT_PROOF'] = 'approved-declaration'
        unrelated = {'definition': {'owner': 'new independent intent'}, 'approval': {'name': 'unrelated'}}
        current = {'catalog': [active, unrelated], 'dataApprovals': {'unrelated': 'current approval'}}
        before = copy.deepcopy(current)
        restored = restored_catalog(current, entry)
        self.assertEqual(restored['catalog'], [entry, unrelated])
        self.assertEqual(restored['dataApprovals'], current['dataApprovals'])
        self.assertEqual(current, before)
        active['definition']['environment']['OTHER_OWNER_FIELD'] = 'independent edit'
        with self.assertRaisesRegex(RuntimeError, 'changed independently'):
            restored_catalog(current, entry)
