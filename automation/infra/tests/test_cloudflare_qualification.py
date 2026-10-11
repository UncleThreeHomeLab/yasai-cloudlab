"""Disposable provider certification cannot approve unintended import mutations."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from automation.infra import cloudflare_qualification as subject
from automation.infra.cloudflare_qualification import fixture_scope, preserved, review_import, state_identities


class CloudflareQualificationTests(unittest.TestCase):
    def test_capability_uses_current_result_and_does_not_hide_other_failures(self):
        self.assertFalse(subject.policy_update_unsupported(Mock(returncode=0)))
        self.assertTrue(subject.policy_update_unsupported(Mock(returncode=1,
            stdout=b'', stderr=b'PUT /access/policies/existing HTTP404 code12135')))
        for diagnostics in (b'HTTP401', b'HTTP404', b'12135 /access/apps/existing'):
            with self.assertRaises(RuntimeError):
                subject.policy_update_unsupported(Mock(returncode=1, stdout=b'', stderr=diagnostics))

    def test_resume_rejects_unrelated_directory_before_reads_or_provider_calls(self):
        with patch.object(subject, 'API') as api:
            with self.assertRaises(ValueError):
                subject.exercise(Path('a' * 32), {})
        api.assert_not_called()

    def test_update_must_be_visible_remotely_even_if_native_apply_succeeded(self):
        desired = {'applications': {'human': {'session_duration': '2h',
            'policies': {'primary': {'name': 'updated'}, 'unrelated': {'name': 'retained'}}}},
            'routes': {'human': {'hostname': 'fixture.example.invalid', 'dns_comment': 'updated',
                                 'service': 'https://localhost:9444'}}}
        after = {'app': {'session_duration': '2h', 'policies': [
            {'id': 'primary', 'name': 'updated'}, {'id': 'unrelated', 'name': 'retained'}]},
            'dns': {'comment': 'updated'}, 'config': {'config': {'ingress': [
                {'hostname': 'fixture.example.invalid', 'service': 'https://localhost:9444'}]}}}
        subject.updated(after, desired, {'primary': 'primary', 'unrelated': 'unrelated'})
        after['app']['policies'][0]['name'] = 'not-updated'
        with self.assertRaises(ValueError):
            subject.updated(after, desired, {'primary': 'primary', 'unrelated': 'unrelated'})

    def test_repeated_cleanup_does_not_delete_absent_provider_objects(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / ('qualification-' + 'a' * 32)
            directory.mkdir()
            documents = {
                'result.json': {'provider_success_failed_upload_recovery': True, 'repeat_plan_empty': True},
                'credentials.json': {'management': {'API_TOKEN': 'synthetic', 'ACCOUNT_ID': 'account'},
                                     'dns': {'API_TOKEN': 'synthetic-dns', 'ZONE_ID': 'zone'},
                                     'backend': {'PROJECT_ID': '123', 'USERNAME': 'fixture', 'TOKEN': 'synthetic'}},
                'identities.json': {'app': 'app', 'dns': 'record', 'tunnel': 'tunnel'},
                'before.json': {'app': {'id': 'app', 'name': directory.name,
                                       'domain': directory.name + '.example.invalid'},
                                'dns': {'id': 'record', 'name': directory.name + '.example.invalid',
                                        'content': 'tunnel.cfargotunnel.com'}}}
            for name, value in documents.items():
                (directory / name).write_text(json.dumps(value))
            client = Mock()
            client.request.side_effect = RuntimeError('Cloudflare API GET failed: HTTP 404')
            with patch.object(subject, 'API', return_value=client), \
                    patch.object(subject, 'delete_state', return_value=True) as delete:
                subject.cleanup(directory, documents['credentials.json'])
            self.assertTrue(all(call.args[0] == 'GET' for call in client.request.call_args_list))
            self.assertEqual(delete.call_count, 1)
            self.assertTrue(json.loads((directory / 'result.json').read_text())['disposable_resources_removed'])

    def test_native_pull_and_show_do_not_persist_decrypted_stdout(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(subject.subprocess, 'run',
                return_value=Mock(returncode=0, stdout=b'private-state', stderr=b'redacted-error')):
            directory = Path(temporary)
            subject.native(directory, {}, 'state', 'pull')
            subject.native(directory, {}, 'show', '-json', 'encrypted.tfplan')
            self.assertEqual((directory / 'diagnostics.txt').read_bytes(), b'redacted-error' * 2)

    def test_cleanup_refuses_unrelated_hostnames_or_connected_tunnel(self):
        name = 'qualification-' + 'a' * 32
        identities = {'app': 'app', 'dns': 'record', 'tunnel': 'tunnel'}
        observed = {'app': {'name': name, 'id': 'app', 'domain': name + '.example.invalid'},
                    'dns': {'id': 'record', 'name': name + '.example.invalid', 'content': 'tunnel.cfargotunnel.com'}}
        tunnel = {'name': name, 'id': 'tunnel', 'connections': []}
        fixture_scope(name, identities, observed, tunnel)
        with self.assertRaises(ValueError):
            fixture_scope('a' * 32, identities, observed, tunnel)
        for changed in (dict(tunnel, connections=[{}]), dict(tunnel, name='production')):
            with self.assertRaises(ValueError):
                fixture_scope(name, identities, observed, changed)
        observed['dns']['name'] = 'existing.example.invalid'
        with self.assertRaises(ValueError):
            fixture_scope(name, identities, observed, tunnel)

    def test_recovery_inventory_preserves_index_keys_and_exact_ids(self):
        document = {'resources': [{'type': 'cloudflare_dns_record', 'name': 'publication',
                                  'instances': [{'index_key': 'human', 'attributes': {'id': 'original'}}]}]}
        self.assertEqual(state_identities(document), {'cloudflare_dns_record.publication["human"]': 'original'})

    def test_import_requires_exact_addresses_identity_and_no_remote_change(self):
        document = {'resource_changes': [{'address': 'fixture', 'change': {
            'actions': ['no-op'], 'after': {'id': 'existing'}}}]}
        review_import(document, {'fixture': 'existing'})
        for actions, identity in ((['update'], 'existing'), (['create'], 'existing'), (['no-op'], 'replacement')):
            bad = copy.deepcopy(document)
            bad['resource_changes'][0]['change'].update(actions=actions, after={'id': identity})
            with self.assertRaises(ValueError):
                review_import(bad, {'fixture': 'existing'})
        with self.assertRaises(ValueError):
            review_import(document, {'another': 'existing'})

    def test_policy_conversion_audience_or_routing_change_rejected(self):
        before = {'app': {'id': 'app', 'aud': 'audience', 'policies': [{
            'id': 'policy', 'reusable': False, 'include': [], 'exclude': [], 'require': [], 'decision': 'deny'}]},
            'config': {'config': {'warp-routing': {'enabled': False}}}, 'dns': {'id': 'record'}}
        preserved(before, before)
        for field in ('aud', 'reusable', 'routing', 'allowed_idps', 'domain', 'dns_content', 'precedence'):
            after = copy.deepcopy(before)
            if field == 'aud':
                after['app']['aud'] = 'replacement'
            elif field == 'reusable':
                after['app']['policies'][0]['reusable'] = True
            elif field == 'allowed_idps':
                after['app']['allowed_idps'] = ['replacement']
            elif field == 'domain':
                after['app']['domain'] = 'unrelated.example.invalid'
            elif field == 'dns_content':
                after['dns']['content'] = 'unrelated.cfargotunnel.com'
            elif field == 'precedence':
                after['app']['policies'][0]['precedence'] = 9
            else:
                after['config']['config']['warp-routing']['enabled'] = True
            with self.assertRaises(ValueError):
                preserved(before, after)
