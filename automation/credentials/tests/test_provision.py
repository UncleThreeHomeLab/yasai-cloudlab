import json
import os
import unittest
from unittest.mock import Mock, patch

from automation.credentials import provision


class ProvisionTests(unittest.TestCase):
    def definitions(self):
        return {'test-item': {'password': ('CONCEALED', Mock(return_value='synthetic-secret'))}}

    def test_existing_is_preserved_without_generating_password(self):
        definitions = self.definitions()
        with patch.object(provision, 'command', side_effect=[
                [{'id': 'item-id', 'title': 'test-item'}],
                {'fields': [{'label': 'password', 'type': 'CONCEALED', 'value': 'existing'}]}]) as call:
            self.assertEqual(provision.ensure_items('token', definitions),
                             {'created': [], 'preserved': ['test-item']})
        definitions['test-item']['password'][1].assert_not_called()
        self.assertEqual(call.call_count, 2)

    def test_create_uses_stdin_and_only_child_writer_environment(self):
        with patch.dict(os.environ, {'OP_SERVICE_ACCOUNT_TOKEN': 'reader',
                                    'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'writer'}), \
                patch.object(provision.subprocess, 'run', return_value=Mock(
                    returncode=0, stdout='{"id":"item-id"}')) as run:
            provision.command(['item', 'create', '-', '--vault', 'CloudLab'], 'writer',
                              {'password': 'synthetic-secret'})
            arguments, keywords = run.call_args
            self.assertNotIn('synthetic-secret', str(arguments))
            self.assertNotIn('writer', str(arguments))
            self.assertEqual(json.loads(keywords['input'])['password'], 'synthetic-secret')
            self.assertEqual(keywords['env']['OP_SERVICE_ACCOUNT_TOKEN'], 'writer')
            self.assertNotIn('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', keywords['env'])
            self.assertEqual(os.environ['OP_SERVICE_ACCOUNT_TOKEN'], 'reader')

    def test_duplicates_and_invalid_fields_fail_before_creating(self):
        for responses in ([ [{'id': 'one', 'title': 'test-item'}, {'id': 'two', 'title': 'test-item'}] ],
                          [ [{'id': 'one', 'title': 'test-item'}], {'fields': []} ]):
            with self.subTest(responses=responses), patch.object(provision, 'command', side_effect=responses) as call:
                with self.assertRaises(RuntimeError):
                    provision.ensure_items('token', self.definitions())
                self.assertFalse(any('create' in args.args[0] for args in call.call_args_list))

    def test_read_failure_never_creates(self):
        with patch.object(provision, 'command', side_effect=RuntimeError('unavailable')) as call:
            with self.assertRaises(RuntimeError):
                provision.ensure_items('token', self.definitions())
        self.assertEqual(call.call_count, 1)

    def test_interrupted_create_is_not_retried(self):
        with patch.object(provision, 'command', side_effect=[[], [], RuntimeError('timed out')]) as call:
            with self.assertRaises(RuntimeError):
                provision.ensure_items('token', self.definitions())
        self.assertEqual(sum('create' in args.args[0] for args in call.call_args_list), 1)

    def test_missing_token_never_contacts_vault(self):
        with patch.object(provision, 'command') as call:
            with self.assertRaises(RuntimeError):
                provision.ensure_items('', self.definitions())
        call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
