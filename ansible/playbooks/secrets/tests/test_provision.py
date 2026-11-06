import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.secrets.files import provision
from playbooks.secrets.files import vault


class ProvisionTests(unittest.TestCase):
    def test_quota_failure_is_sanitized_and_never_misreported_as_permissions(self):
        for action in (lambda: provision.command(['item', 'list'], 'fixture'),
                       lambda: vault.fields('fixture', ['password'])):
            with patch.object(provision.subprocess, 'run', return_value=Mock(
                    returncode=1, stderr='too many requests: private diagnostic value')):
                with self.assertRaisesRegex(RuntimeError, 'quota exhausted') as error: action()
                self.assertNotIn('private diagnostic', str(error.exception))

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

    def test_placeholders_create_empty_stdin_fields_and_reject_generators(self):
        definitions = {'test-item': {'password': ('CONCEALED', None), 'username': ('STRING', None)}}
        with patch.object(provision.subprocess, 'run', side_effect=[
                Mock(returncode=0, stdout='[]'), Mock(returncode=0, stdout='[]'),
                Mock(returncode=0, stdout='{"id":"item-id","title":"test-item"}')]) as run:
            self.assertEqual(provision.ensure_items('writer', definitions, placeholders=True),
                             {'created': ['test-item'], 'preserved': [],
                              'pending': {'test-item': ['password', 'username']}})
        arguments, keywords = run.call_args
        self.assertEqual(arguments[0], ['op', 'item', 'create', '-', '--vault', 'CloudLab', '--format', 'json'])
        self.assertNotIn('writer', str(arguments))
        self.assertEqual(json.loads(keywords['input']), {
            'title': 'test-item', 'category': 'SECURE_NOTE', 'tags': ['cloudlab-managed'],
            'fields': [{'id': label, 'label': label, 'type': kind, 'value': ''}
                       for label, (kind, _) in definitions['test-item'].items()]})
        generated = self.definitions()
        with patch.object(provision, 'command') as call:
            with self.assertRaises(ValueError):
                provision.ensure_items('writer', generated, placeholders=True)
        call.assert_not_called()
        generated['test-item']['password'][1].assert_not_called()

    def test_placeholders_preserve_empty_partial_and_complete_items_on_repeat(self):
        definitions = {'test-item': {'password': ('CONCEALED', None), 'username': ('STRING', None)}}
        for password, username in ((None, None), ('', ''), ('', 'existing-user'),
                                   ('existing-secret', 'existing-user')):
            current = {'id': 'item-id', 'title': 'test-item', 'category': 'SECURE_NOTE',
                       'tags': ['human-tag'], 'fields': [
                           {'id': 'kept-id', 'label': 'password', 'type': 'CONCEALED', 'value': password},
                           {'label': 'username', 'type': 'STRING', 'value': username},
                           {'label': 'extra', 'type': 'STRING', 'value': 'kept'}]}
            if password is None:
                del current['fields'][0]['value']
            before = copy.deepcopy(current)
            missing = [label for label, value in [('password', password), ('username', username)] if not value]
            for _ in range(2):
                with self.subTest(password=password, username=username), patch.object(
                        provision, 'command', side_effect=[
                            [{'id': 'item-id', 'title': 'test-item'}], current]) as call:
                    self.assertEqual(provision.ensure_items('writer', definitions, placeholders=True), {
                        'created': [], 'preserved': ['test-item'],
                        'pending': {'test-item': missing} if missing else {}})
                self.assertEqual(call.call_count, 2)
                self.assertEqual(current, before)

    def test_placeholders_refuse_incompatible_or_unreadable_batch_before_create(self):
        definitions = {'new-item': {'password': ('CONCEALED', None)},
                       'test-item': {'password': ('CONCEALED', None)}}
        inventory = [{'id': 'item-id', 'title': 'test-item'}]
        current = {'id': 'item-id', 'title': 'test-item', 'category': 'SECURE_NOTE',
                   'fields': [{'label': 'password', 'type': 'CONCEALED', 'value': ''}]}
        incompatible = [dict(current, id='changed'), dict(current, title='changed'),
                        dict(current, category='LOGIN'), dict(current, fields=[]),
                        dict(current, fields=current['fields'] * 2),
                        dict(current, fields=[{'label': 'password', 'type': 'STRING', 'value': ''}]),
                        dict(current, fields=[{'label': 'password', 'type': 'CONCEALED', 'value': 42}]),
                        dict(current, fields={}), dict(current, fields=[None]), None,
                        RuntimeError('read unavailable')]
        responses = [[inventory, item] for item in incompatible]
        responses += [[invalid] for invalid in (None, {}, [None], [{'title': 'test-item'}],
                                                [{'id': 'item-id'}], inventory * 2)]
        responses += [[[], invalid] for invalid in (None, {}, [None])]
        for response in responses:
            with self.subTest(response=response), patch.object(provision, 'command', side_effect=response) as call:
                with self.assertRaises(RuntimeError):
                    provision.ensure_items('writer', definitions, placeholders=True)
                self.assertFalse(any('create' in args.args[0] for args in call.call_args_list))

    def test_placeholder_uncertain_create_requires_inspection_without_retry(self):
        definitions = {'test-item': {'password': ('CONCEALED', None)}}
        for response in (None, {}, {'id': 'item-id', 'title': 'changed'},
                         {'id': 42, 'title': 'test-item'}):
            with self.subTest(response=response), patch.object(
                    provision, 'command', side_effect=[[], [], response]) as call:
                with self.assertRaisesRegex(RuntimeError, 'inspect existence before retrying'):
                    provision.ensure_items('writer', definitions, placeholders=True)
            self.assertEqual(sum('create' in args.args[0] for args in call.call_args_list), 1)
        with patch.object(provision.subprocess, 'run', side_effect=[
                Mock(returncode=0, stdout='[]'), Mock(returncode=0, stdout='[]'),
                subprocess.TimeoutExpired('op', 60)]) as run:
            with self.assertRaisesRegex(RuntimeError, 'inspect item existence before retrying'):
                provision.ensure_items('writer', definitions, placeholders=True)
        self.assertEqual(run.call_count, 3)
        with patch.object(provision.subprocess, 'run', side_effect=[
                Mock(returncode=0, stdout='[]'), Mock(returncode=0, stdout='[]'),
                Mock(returncode=0, stdout='invalid private response')]) as run:
            with self.assertRaisesRegex(RuntimeError, 'inspect item existence before retrying') as error:
                provision.ensure_items('writer', definitions, placeholders=True)
        self.assertNotIn('private response', str(error.exception))
        self.assertEqual(run.call_count, 3)

    def test_generated_mode_validates_definitions_and_values_without_changing_result(self):
        invalid = {'new-item': {'password': ('CONCEALED', Mock())},
                   'test-item': {'password': ('CONCEALED', None)}}
        with patch.object(provision, 'command') as call:
            with self.assertRaises(ValueError):
                provision.ensure_items('token', invalid)
        call.assert_not_called()
        invalid['new-item']['password'][1].assert_not_called()
        for value in ('', None, 42):
            definitions = {'test-item': {'password': ('CONCEALED', Mock(return_value=value))}}
            with self.subTest(value=value), patch.object(provision, 'command', side_effect=[[], []]) as call:
                with self.assertRaises(ValueError):
                    provision.ensure_items('token', definitions)
                self.assertFalse(any('create' in args.args[0] for args in call.call_args_list))
            with patch.object(provision, 'command', side_effect=[
                    [{'id': 'item-id', 'title': 'test-item'}],
                    {'fields': [{'label': 'password', 'type': 'CONCEALED', 'value': value}]}]):
                with self.assertRaises(RuntimeError):
                    provision.ensure_items('token', definitions)
        definitions = self.definitions()
        with patch.object(provision, 'command', side_effect=[
                [], [], {'id': 'item-id', 'title': 'test-item'}]) as call:
            self.assertEqual(provision.ensure_items('token', definitions),
                             {'created': ['test-item'], 'preserved': []})
        definitions['test-item']['password'][1].assert_called_once_with()
        self.assertEqual(call.call_args.args[2]['fields'][0]['value'], 'synthetic-secret')


class ReconcilerReportTests(unittest.TestCase):
    def test_reports_persist_with_monotonic_cycle_counter(self):
        from playbooks.secrets.files import reconcile
        with tempfile.TemporaryDirectory() as directory:
            first = reconcile.persist_report(directory, {'created': []})
            self.assertEqual(first['cycles'], 1)
            self.assertRegex(first['completedAt'], r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$')
            second = reconcile.persist_report(directory, {'created': ['synthetic']})
            self.assertEqual(second['cycles'], 2)
            self.assertEqual(json.loads((Path(directory) / 'report.json').read_text()), second)
            (Path(directory) / 'report.json').write_text('corrupt')
            self.assertEqual(reconcile.persist_report(directory, {'created': []})['cycles'], 1)


if __name__ == '__main__':
    unittest.main()
