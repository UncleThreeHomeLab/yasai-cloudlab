"""Ownership transitions fence both writers and resume interrupted checkpoints."""
from contextlib import nullcontext
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from automation.infra import cloudflare_adoption as subject
from automation.infra.tests.fixtures import cloudflare_owner


class HandoffTests(unittest.TestCase):
    def test_handoff_directory_cannot_escape_protected_recovery_root(self):
        for directory in ('../handoff-' + 'a' * 32, '/tmp/handoff-' + 'a' * 32):
            with self.assertRaisesRegex(ValueError, 'Invalid protected handoff directory'):
                subject.maintained_root(Path('/inputs'), {'directory': directory}, {})

    def test_reverse_withdraws_acceptance_before_state_removal_and_never_deletes_remote_objects(self):
        snapshot, bundle = cloudflare_owner()
        _, imports = subject.declarations(snapshot, bundle)
        binding = {'revision': 'synthetic', 'source_hash': 'synthetic'}
        checkpoint = {'phase': 'accepted', 'snapshot': snapshot, 'imports': imports,
                      'binding': binding, 'directory': 'handoff-' + 'b' * 32}
        state = copy.deepcopy(snapshot['owner'])
        state['infra_owner'] = {'phase': 'accepted', 'source': binding, 'operation': checkpoint['directory']}
        resources = []
        for address, value in imports.items():
            kind, tail = address.split('.', 1)
            name = tail.split('[', 1)[0]
            attributes = {key: value for key, value in value.items() if key not in ('import_id', 'policies')}
            if 'policies' in value:
                attributes['policies'] = [{'id': key, 'reusable': flag} for key, flag in value['policies'].items()]
            instance = {'attributes': attributes}
            if '[' in address:
                instance['index_key'] = json.loads(address[address.index('[')+1:-1])
            resources.append({'type': kind, 'name': name, 'instances': [instance]})
        receipts = Mock()
        receipts.load.side_effect = lambda name: copy.deepcopy(state)
        def save(name, value):
            state.clear(); state.update(copy.deepcopy(value))
        receipts.save.side_effect = save
        with tempfile.TemporaryDirectory() as temporary:
            inputs = Path(temporary) / 'inputs'; inputs.mkdir()
            directory = Path(temporary) / 'protected'; directory.mkdir()
            subject.write_json(inputs / 'handoff.json', checkpoint)
            pulled = False
            def native(folder, env, *args):
                nonlocal pulled
                if args[:2] == ('state', 'pull'):
                    payload = {} if pulled else {'resources': resources}
                    pulled = True
                    return Mock(returncode=0, stdout=json.dumps(payload).encode())
                if args[:2] == ('state', 'rm'):
                    self.assertEqual(json.loads((inputs / 'acceptance.json').read_text())['status'], 'reversing')
                    self.assertEqual(state['infra_owner']['phase'], 'reversing')
                self.assertNotIn('destroy', args)
                self.assertNotIn('apply', args)
                return Mock(returncode=0)
            with patch.object(subject, 'maintained_root', return_value=(directory, {})), \
                    patch.object(subject, 'current_scope'), \
                    patch('automation.infra.snapshot.credentials', return_value=bundle), \
                    patch('automation.connectivity.checkpoint.transaction', return_value=nullcontext(receipts)), \
                    patch('automation.infra.cloudflare_qualification.native', side_effect=native), \
                    patch('automation.infra.retention.ciphertext', return_value=b'{"encrypted_data":"retained"}'):
                subject.reverse(inputs)
            self.assertNotIn('infra_owner', state)
            self.assertEqual(json.loads((inputs / 'handoff.json').read_text())['phase'], 'reversed')
            self.assertEqual(len(list(directory.glob('reverse-*.encrypted'))), 1)

    def test_access_prerequisite_requires_accepted_integration_and_current_repair_gate(self):
        snapshot, _ = cloudflare_owner()
        state = copy.deepcopy(snapshot['owner'])
        with patch('automation.identity.access_cutover.browser_gate') as gate:
            subject.prerequisites(state, snapshot)
            gate.assert_called_once_with('synthetic', None)
            state['identity_cutover']['phase'] = 'configured'
            with self.assertRaisesRegex(ValueError, 'Accepted central Access'):
                subject.prerequisites(state, snapshot)
            self.assertEqual(gate.call_count, 1)

    def test_import_and_access_failure_keep_old_writer_suspended_then_resume(self):
        snapshot, bundle = cloudflare_owner()
        desired, imports = subject.declarations(snapshot, bundle)
        binding = {'revision': 'synthetic', 'source_hash': 'synthetic'}
        checkpoint = {'phase': 'prepared', 'snapshot': snapshot, 'imports': imports,
                      'binding': binding, 'directory': 'handoff-' + 'a' * 32}
        state = copy.deepcopy(snapshot['owner'])
        receipts = Mock()
        receipts.load.side_effect = lambda name: copy.deepcopy(state)
        def save(name, value):
            state.clear()
            state.update(copy.deepcopy(value))
        receipts.save.side_effect = save
        resources = []
        for address, value in imports.items():
            after = {key: value for key, value in value.items() if key not in ('import_id', 'policies')}
            if 'policies' in value:
                after['policies'] = [{'id': key, 'reusable': flag} for key, flag in value['policies'].items()]
            resources.append({'address': address, 'type': address.split('.')[0], 'mode': 'managed',
                              'change': {'actions': ['no-op'], 'after': after}})
        with tempfile.TemporaryDirectory() as temporary:
            inputs = Path(temporary) / 'inputs'
            directory = Path(temporary) / 'protected'
            inputs.mkdir(); directory.mkdir()
            subject.write_json(inputs / 'handoff.json', checkpoint)
            subject.write_json(inputs / 'desired.tfvars.json', desired)
            with patch.object(subject, 'source_binding', return_value=binding), \
                    patch.object(subject, 'prerequisites'), \
                    patch.object(subject, 'maintained_root', return_value=(directory, {})), \
                    patch.object(subject, 'current_scope'), \
                    patch('automation.infra.snapshot.credentials', return_value=bundle), \
                    patch('automation.connectivity.checkpoint.transaction', return_value=nullcontext(receipts)), \
                    patch('automation.infra.cloudflare_qualification.native', return_value=Mock(returncode=0)) as native, \
                    patch('automation.infra.cloudflare_qualification.document_plan', return_value=(0, {'resource_changes': resources})), \
                    patch('automation.connectivity.verify.run', side_effect=RuntimeError('access fixture interrupted')):
                with self.assertRaisesRegex(RuntimeError, 'access fixture interrupted'):
                    subject.advance(inputs)
            self.assertEqual(state['infra_owner']['phase'], 'suspended')
            self.assertEqual(json.loads((inputs / 'handoff.json').read_text())['phase'], 'imported')
            self.assertFalse((inputs / 'acceptance.json').exists())
            self.assertEqual(sum(call.args[2] == 'apply' for call in native.call_args_list), 1)
            with patch.object(subject, 'source_binding', return_value=binding), \
                    patch.object(subject, 'prerequisites'), \
                    patch.object(subject, 'maintained_root', return_value=(directory, {})), \
                    patch.object(subject, 'current_scope'), \
                    patch('automation.infra.snapshot.credentials', return_value=bundle), \
                    patch('automation.connectivity.checkpoint.transaction', return_value=nullcontext(receipts)), \
                    patch('automation.infra.cloudflare_qualification.native', return_value=Mock(returncode=0)) as native, \
                    patch('automation.infra.cloudflare_qualification.document_plan', return_value=(0, {'resource_changes': resources})), \
                    patch('automation.connectivity.verify.run', return_value={'existing_access': True}) as access:
                subject.advance(inputs)
            self.assertEqual(state['infra_owner']['phase'], 'accepted')
            self.assertEqual(json.loads((inputs / 'acceptance.json').read_text()), {'root': 'cloudflare', 'status': 'accepted'})
            self.assertFalse(any(call.args[2] == 'apply' for call in native.call_args_list))
            access.assert_called_once_with(failures=False, reconcile=False)

    def test_changed_preparation_source_rejected_before_vault_or_provider(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs = Path(temporary)
            subject.write_json(inputs / 'handoff.json', {'binding': {'revision': 'old'}, 'phase': 'prepared'})
            with patch.object(subject, 'source_binding', return_value={'revision': 'new'}), \
                    patch('automation.infra.snapshot.credentials') as credentials:
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    subject.advance(inputs)
                credentials.assert_not_called()
