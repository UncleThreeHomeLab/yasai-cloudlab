"""Bound private reads and retire their scoped credential on every known-token path."""
import base64
from contextlib import ExitStack
import io
import json
import os
import traceback
import unittest
from unittest.mock import Mock, patch

from playbooks.argocd.files import github_setup
from playbooks.services.files import inputs, source


class Response(io.BytesIO):
    def __init__(self, value=None, *, raw=None, status=200):
        super().__init__(raw if raw is not None else json.dumps(value).encode())
        self.status = status

    def read1(self, size=-1):
        return self.read(size)


class SourceReadTests(unittest.TestCase):
    def fixture(self, stack, *, content=None, effect=None, fields_effect=None):
        clock = [100.0]
        calls, clients = [], []
        content = content if content is not None else b'catalog: []\ndataApprovals: {}\n'
        def open_request(request, timeout):
            method, url = request.get_method(), request.full_url
            calls.append((method, url, request.data, timeout))
            if effect:
                result = effect(method, url, clock)
                if result is not None: return result
            if method == 'DELETE': return Response(status=204)
            if method == 'POST': return Response({'token': 'synthetic-read-token'})
            if '/app/installations/' in url:
                return Response({'app_id': 1, 'repository_selection': 'selected', 'suspended_at': None,
                                 'permissions': {'contents': 'read', 'metadata': 'read'}})
            if '/git/ref/heads/main' in url: return Response({'object': {'sha': 'a' * 40}})
            return Response({'content': base64.b64encode(content).decode()})
        opener = Mock()
        opener.open.side_effect = open_request
        def client(token, **options):
            result = github_setup.GitHub(token, **options)
            clients.append(result)
            return result
        stack.enter_context(patch.object(source.time, 'monotonic', side_effect=lambda: clock[0]))
        fields = stack.enter_context(patch.object(source, 'fields', side_effect=fields_effect,
                    return_value={'APP_ID': '1', 'INSTALLATION_ID': '17', 'PRIVATE_KEY': 'synthetic'}))
        stack.enter_context(patch.object(source, 'app_token', return_value='synthetic-app-token'))
        stack.enter_context(patch('playbooks.services.files.owner.configuration',
                                 return_value={'catalogPath': 'services/catalog-v2.yaml'}))
        stack.enter_context(patch.object(source, 'GitHub', side_effect=client))
        stack.enter_context(patch.object(github_setup.urllib.request, 'build_opener', return_value=opener))
        return clock, calls, clients, fields

    def read(self, **options):
        return source.read({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}, **options)

    def test_real_bounded_transport_preserves_selected_path_revision_scope_and_caller(self):
        with ExitStack() as stack:
            _, calls, clients, fields = self.fixture(stack)
            expected = {'catalog': [], 'dataApprovals': {}}
            self.assertEqual(self.read(include_revision=True), (expected, 'a' * 40))
            self.assertEqual(self.read(), expected)
            for call in (row for row in calls if row[0] == 'POST'):
                self.assertEqual(json.loads(call[2]), {'repositories': ['private'], 'permissions': {'contents': 'read'}})
            self.assertEqual(sum(row[0] == 'DELETE' for row in calls), 2)
            self.assertTrue(any('/contents/services/catalog-v2.yaml?ref=' + 'a' * 40 in row[1] for row in calls))
            self.assertTrue(all(row[3] <= 15 for row in calls))
            self.assertTrue(all(client.deadline is not None and client.max_response in (65536, 2097152)
                                for client in clients))
            fields.assert_called_with('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
            with patch.object(inputs, 'dotenv_values', return_value={
                    'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git',
                    'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic'}), \
                    patch.dict(os.environ, {'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic-before'}), \
                    patch.object(inputs, 'validate_catalog', side_effect=lambda value, public: value):
                self.assertEqual(inputs.catalog(required=True, coordinates=True), (expected, 'a' * 40))

    def test_response_overflow_is_refused_before_decode_and_known_token_is_revoked(self):
        for target, size in (('/app/installations/17', 65537), ('/contents/', 2097153)):
            def overflow(method, url, clock):
                if method == 'GET' and target in url: return Response(raw=b'x' * size)
            with self.subTest(target=target), ExitStack() as stack:
                _, calls, _, _ = self.fixture(stack, effect=overflow)
                with patch.object(source, 'decode_contents') as decode, self.assertRaises(RuntimeError):
                    self.read()
                decode.assert_not_called()
                self.assertEqual(sum(row[0] == 'DELETE' for row in calls), int(target == '/contents/'))

    def test_expired_work_still_uses_reserved_fresh_cleanup_client(self):
        def expire(method, url, clock):
            if '/contents/' in url: clock[0] = 251
        with ExitStack() as stack:
            _, calls, clients, _ = self.fixture(stack, effect=expire)
            with self.assertRaisesRegex(RuntimeError, 'catalog; token cleanup: revoked'):
                self.read()
            self.assertEqual(calls[-1][0], 'DELETE')
            self.assertEqual(clients[-1].deadline, 280)
            self.assertEqual(clients[-2].deadline, 250)
            self.assertIsNot(clients[-1], clients[-2])

    def test_parse_and_decoded_limit_failures_are_sanitized_and_revoke(self):
        for content in (b'private-secret-sentinel: [\n', b'x' * (1048576 + 1)):
            with self.subTest(size=len(content)), ExitStack() as stack:
                _, calls, _, _ = self.fixture(stack, content=content)
                with self.assertRaises(RuntimeError) as caught: self.read()
                self.assertIn('catalog; token cleanup: revoked', str(caught.exception))
                self.assertNotIn('private-secret-sentinel', ''.join(traceback.format_exception(caught.exception)))
                self.assertEqual(sum(row[0] == 'DELETE' for row in calls), 1)

    def test_cleanup_failure_prevents_success_and_preserves_safe_read_category(self):
        def fail_cleanup(method, url, clock):
            if method == 'DELETE': raise RuntimeError('private-cleanup-sentinel')
        for content, stage in ((None, 'complete'), (b'private-read-sentinel: [', 'catalog')):
            with self.subTest(stage=stage), ExitStack() as stack:
                self.fixture(stack, content=content, effect=fail_cleanup)
                with self.assertRaisesRegex(RuntimeError, stage + '; token cleanup: unconfirmed') as caught:
                    self.read()
                self.assertNotIn('sentinel', ''.join(traceback.format_exception(caught.exception)))

    def test_non_204_cleanup_response_never_confirms_revocation_or_returns_catalog(self):
        for status in (200, 202):
            def pending(method, url, clock):
                if method == 'DELETE':
                    return Response({'private-cleanup-sentinel': 'pending'}, status=status)
            with self.subTest(status=status), ExitStack() as stack:
                _, calls, _, _ = self.fixture(stack, effect=pending)
                with self.assertRaisesRegex(RuntimeError, 'complete; token cleanup: unconfirmed') as caught:
                    self.read()
                self.assertNotIn('sentinel', ''.join(traceback.format_exception(caught.exception)))
                self.assertEqual(sum(row[0] == 'DELETE' for row in calls), 1)

    def test_no_token_is_issued_after_credentials_exhaust_work_budget(self):
        with ExitStack() as stack:
            clock, calls, _, _ = self.fixture(stack)
            stack.enter_context(patch.object(source, 'fields', side_effect=lambda *args: clock.__setitem__(0, 251)))
            with self.assertRaisesRegex(RuntimeError, 'credentials; token cleanup: not-issued'): self.read()
            self.assertEqual(calls, [])

    def test_lost_issuance_response_is_not_retried_or_claimed_revoked(self):
        def lose(method, url, clock):
            if method == 'POST': raise RuntimeError('private-issuance-sentinel')
        with ExitStack() as stack:
            _, calls, _, _ = self.fixture(stack, effect=lose)
            with self.assertRaisesRegex(RuntimeError, 'issuance; token cleanup: issuance-unconfirmed') as caught:
                self.read()
            self.assertEqual(sum(row[0] == 'POST' for row in calls), 1)
            self.assertFalse(any(row[0] == 'DELETE' for row in calls))
            self.assertNotIn('sentinel', ''.join(traceback.format_exception(caught.exception)))

    def test_overall_budget_cannot_return_success_after_slow_cleanup(self):
        def late_cleanup(method, url, clock):
            if method == 'DELETE': clock[0] = 281
        with ExitStack() as stack:
            self.fixture(stack, effect=late_cleanup)
            with self.assertRaisesRegex(RuntimeError, 'deadline; token cleanup: revoked'): self.read()
