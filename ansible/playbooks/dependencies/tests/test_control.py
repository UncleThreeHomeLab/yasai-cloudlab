"""Credential lifetime and initial ownership stay outside candidate execution."""
import os
from unittest.mock import Mock, patch
import unittest
from contextlib import nullcontext
import tempfile
from pathlib import Path

from playbooks.dependencies.files import control


class ControlTests(unittest.TestCase):
    def test_actions_owner_is_rejected_before_source_preflight_or_secret_lookup(self):
        owner = {'updater': 'actions', 'writePaths': ['.github/workflows/application-test.yaml']}
        with patch.object(control, 'selected', return_value={'actions': owner}), \
                patch.object(control, 'committed_payload') as source, patch.object(control, 'dotenv_values') as lookup:
            with self.assertRaises(ValueError):
                control.run('export', {'base': 'main', 'number': 7, 'owners': ['actions']})
            source.assert_not_called()
            lookup.assert_not_called()
    def test_proposal_failure_always_revokes_lease_and_clears_driver_token(self):
        lease = {'token': 'synthetic-token', 'repository': 'example/platform', 'repositoryId': 1,
                 'requester': 'release[bot]'}
        with patch('playbooks.dependencies.files.toolchain.embedded'), \
                patch.object(control, 'committed_payload', return_value={'branch': 'main', 'repository': 'https://github.com/example/platform.git'}), \
                patch.object(control, 'writer_lock', return_value=nullcontext()), \
                patch.object(control, 'dotenv_values', return_value={'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic-reader'}), \
                patch.object(control.repository_tokens, 'issue', return_value=lease) as issue, \
                patch.object(control.repository_tokens, 'revoke') as revoke, \
                patch.object(control, 'GitHub'), patch.object(control, 'Gate'), \
                patch.object(control, 'propose', side_effect=RuntimeError('synthetic failure')):
            with self.assertRaises(RuntimeError):
                control.run('propose', {'base': 'main', 'owners': ['tool:tofu']})
            revoke.assert_called_once_with(lease)
            self.assertTrue(issue.call_args.kwargs['include_requester'])
        self.assertNotIn('OP_SERVICE_ACCOUNT_TOKEN', os.environ)

    def test_unpublished_or_dirty_driver_fails_before_any_secret_lookup(self):
        with patch.object(control, 'committed_payload', side_effect=RuntimeError('unreviewed source')), \
                patch.object(control, 'dotenv_values') as lookup, patch.object(control.repository_tokens, 'issue') as issue:
            with self.assertRaises(RuntimeError):
                control.run('propose', {'base': 'main', 'owners': ['tool:tofu']})
            lookup.assert_not_called()
            issue.assert_not_called()

    def test_shared_writer_lock_refuses_second_controller_before_secret_lookup(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(control, 'WRITER', Path(directory)):
            with control.writer_lock(), \
                    patch.object(control, 'committed_payload', return_value={'branch': 'main'}), \
                    patch.object(control, 'dotenv_values') as lookup, patch.object(control.repository_tokens, 'issue') as issue:
                with self.assertRaises(ValueError):
                    control.run('ready', {'base': 'main', 'number': 7})
                lookup.assert_not_called()
                issue.assert_not_called()

    def test_initial_unowned_head_is_rejected_before_snapshot_or_execution(self):
        gate = Mock()
        gate.scope = {'repository': 'example/platform'}
        gate.redraft.return_value = {'head': {'sha': 'a' * 40}, 'base': {'sha': 'b' * 40}}
        base = {'pins.json': {'sha': 'pin', 'mode': '100644'},
                'tests/test_owner.py': {'sha': 'trusted', 'mode': '100644'}}
        head = dict(base, **{'tests/test_owner.py': {'sha': 'malicious', 'mode': '100644'}})
        owner = {'updater': 'tool', 'writePaths': ['pins.json']}
        with patch.object(control, 'selected', return_value={'tool': owner}), \
                patch.object(control, 'remote_tree', side_effect=[base, head]), \
                patch.object(control, 'snapshot') as snapshot, patch.object(control, 'export') as export:
            with self.assertRaises(ValueError):
                control.export_pr(gate, 7, ['tool'])
            snapshot.assert_not_called()
            export.assert_not_called()
