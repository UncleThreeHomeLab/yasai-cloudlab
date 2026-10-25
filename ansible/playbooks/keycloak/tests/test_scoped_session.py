import copy
import json
import os
import unittest
from unittest.mock import Mock, patch

import yaml

from playbooks.keycloak.tests import scoped_session as session


class ScopedSessionTests(unittest.TestCase):
    def setUp(self):
        self.request = {'nonce': 'a' * 32, 'realm': 'applications'}
        self.values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git', 'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic-reader'}
        self.source = {'realms': {'platform': {'memberships': [{'username': 'existing-platform'}]},
                                  'applications': {'memberships': [{'username': 'existing-app'}]}}}
        self.revoked = {'realms': {'platform': {'users': ['keep-disabled'], 'clients': ['retained']},
                                   'applications': {'users': [], 'clients': [], 'removed_clients': ['removed']}}}
        self.manifest = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': 'identity-private-state', 'namespace': 'cloudlab-identity', 'annotations': {'retained': 'value'}},
            'data': {'desired_state': json.dumps(self.source), 'revocations': json.dumps(self.revoked)}}
        self.snapshot = {'revision': 'b' * 40, 'manifest': self.manifest,
                         'files': {session.PATH: yaml.safe_dump(self.manifest), session.OVERLAY: 'retained: overlay\n'}}
        self.credentials = {'username': 'proof-' + 'a' * 32, 'password': 'x' * 48,
                            'ownership_id': 'a' * 32, 'email': 'fixture@example.invalid'}

    def fields(self, title, fields):
        return self.credentials if title.startswith('keycloak-proof-') else {'client_secrets': '{}'}

    def test_explicit_context_uses_only_private_app_and_revokes_on_failure(self):
        lease = {'token': 'synthetic-app-token'}
        with patch.object(session.repository_tokens, 'issue', return_value=lease) as issue, \
                patch.object(session.repository_tokens, 'revoke') as revoke, patch.object(session, 'GitHub') as api, \
                patch.dict(os.environ, {'OP_SERVICE_ACCOUNT_TOKEN': 'previous'}), \
                patch('playbooks.keycloak.files.owner_enrollment.inputs', side_effect=AssertionError('legacy PAT path')):
            with self.assertRaises(RuntimeError), session.private_context(self.values, write=True):
                raise RuntimeError('fixture failure')
            issue.assert_called_once_with(self.values, 'private-config', {'contents': 'write', 'pull_requests': 'write'})
            api.assert_called_once_with(lease['token'])
            revoke.assert_called_once_with(lease)
            self.assertEqual(os.environ['OP_SERVICE_ACCOUNT_TOKEN'], 'previous')

    def test_membership_and_tombstone_preserve_other_source_metadata_overlay_and_revocations(self):
        with patch.object(session, 'fields', side_effect=self.fields), patch.object(session, 'private_files'):
            prepared = session.prepare(self.snapshot, self.request)
            manifest = yaml.safe_load(prepared[session.PATH])
            self.assertEqual(manifest['metadata'], self.manifest['metadata'])
            source = json.loads(manifest['data']['desired_state'])
            self.assertEqual(source['realms']['platform'], self.source['realms']['platform'])
            self.assertEqual(source['realms']['applications']['memberships'][0], {'username': 'existing-app'})
            self.assertEqual(json.loads(manifest['data']['revocations']), self.revoked)
            self.assertEqual(set(prepared), {session.PATH})
            self.assertEqual(self.snapshot['files'][session.OVERLAY], 'retained: overlay\n')
            snapshot = dict(self.snapshot, manifest=manifest)
            offboard = yaml.safe_load(session.prepare(snapshot, self.request, offboard=True)[session.PATH])
            self.assertEqual(json.loads(offboard['data']['desired_state']), source)
            revoked = json.loads(offboard['data']['revocations'])
            self.assertEqual(revoked['realms']['platform'], self.revoked['realms']['platform'])
            self.assertEqual(revoked['realms']['applications']['removed_clients'], ['removed'])
            self.assertEqual(revoked['realms']['applications']['users'], [self.credentials['username']])
            with self.assertRaises(ValueError): session.prepare(dict(snapshot, manifest=offboard), self.request)

    def test_proposal_threads_inspected_base_and_does_not_write_argo_overlay(self):
        prepared = {session.PATH: 'private fixture'}
        with patch.object(session.private_publish, 'publish', return_value={}) as publish:
            session.propose('api', self.values, self.snapshot, prepared)
        publish.assert_called_once_with('api', self.values, prepared, scope='identity', expected_base='b' * 40)

    def test_review_refuses_extra_files_stale_base_changed_head_or_overlay_before_merge(self):
        prepared = {session.PATH: 'new membership\n'}
        proposed = dict(self.snapshot, files={session.PATH: prepared[session.PATH], session.OVERLAY: self.snapshot['files'][session.OVERLAY]})
        pull = {'state': 'open', 'draft': False, 'base': {'sha': 'b' * 40},
                'head': {'sha': 'c' * 40, 'repo': {'full_name': 'example/private'}}}
        for change in ('none', 'files', 'base', 'head', 'overlay'):
            current, candidate, observed = copy.deepcopy(self.snapshot), copy.deepcopy(proposed), copy.deepcopy(pull)
            files = [{'filename': session.PATH, 'status': 'modified'}]
            if change == 'files': files.append({'filename': 'foreign', 'status': 'modified'})
            if change == 'base': current['revision'] = 'd' * 40
            if change == 'head': observed['head']['sha'] = 'd' * 40
            if change == 'overlay': candidate['files'][session.OVERLAY] = 'changed'
            def request(method, path, body=None):
                self.assertEqual(method, 'GET')
                return files if '/files?' in path else {'object': {'sha': 'b' * 40}} if '/git/ref/' in path else observed
            with patch.object(session, 'inspect', side_effect=[current, candidate]):
                api = Mock(request=Mock(side_effect=request))
                if change == 'none': session.review(api, self.values, self.snapshot, prepared, 1, 'c' * 40)
                else:
                    with self.assertRaises(RuntimeError): session.review(api, self.values, self.snapshot, prepared, 1, 'c' * 40)

    def test_lost_merge_response_resumes_exact_head_and_bytes_without_another_merge(self):
        prepared = {session.PATH: 'new membership\n'}
        merged = dict(self.snapshot, revision='d' * 40, files={session.PATH: prepared[session.PATH], session.OVERLAY: self.snapshot['files'][session.OVERLAY]})
        api = Mock(request=Mock(return_value={'merged': True, 'merge_commit_sha': 'd' * 40,
            'head': {'sha': 'c' * 40, 'repo': {'full_name': 'example/private'}}, 'base': {'repo': {'full_name': 'example/private'}}}))
        with patch.object(session, 'inspect', side_effect=[merged, merged]):
            self.assertEqual(session.merge(api, self.values, self.snapshot, prepared, 1, 'c' * 40), 'd' * 40)
        self.assertEqual([call.args[0] for call in api.request.call_args_list], ['GET'])
