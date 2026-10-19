import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from playbooks.harbor.files.registry import Registry


class RegistryTests(unittest.TestCase):
    def test_immutability_requires_explicit_registry_rejection_and_reason(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = Registry('harbor.internal.example.invalid', {}, Path(temporary) / 'diagnostics')
            for code, message, accepted in ((1, b'DENIED: artifact is immutable', True),
                    (1, b'PRECONDITION: immutable tag', True), (1, b'UNAUTHORIZED', False),
                    (1, b'context deadline exceeded', False), (1, b'immutable', False),
                    (0, b'DENIED: immutable', False)):
                with self.subTest(message=message), patch('playbooks.harbor.files.registry.subprocess.run',
                        return_value=subprocess.CompletedProcess([], code, b'', message)):
                    if accepted:
                        client.command('tag', 'synthetic', immutable=True)
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'immutability was not proven'):
                            client.command('tag', 'synthetic', immutable=True)

    def test_auth_is_temporary_and_password_only_enters_standard_input(self):
        environment = {'PATH': '/usr/bin', 'HOME': '/root', 'HTTPS_PROXY': 'socks5://127.0.0.1:1',
                       'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'synthetic-writer', 'TF_HTTP_PASSWORD': 'synthetic-backend'}
        credential = {'username': 'robot$cloudlab-public+push', 'password': 'synthetic-registry-password'}
        with tempfile.TemporaryDirectory() as temporary:
            client = Registry('harbor.internal.example.invalid', environment, Path(temporary) / 'diagnostics')
            locations = []
            def command(arguments, **kwargs):
                self.assertNotIn(credential['password'], arguments)
                self.assertEqual(kwargs['input'], credential['password'].encode())
                self.assertEqual(set(kwargs['env']), {'PATH', 'HOME', 'HTTPS_PROXY', 'DOCKER_CONFIG'})
                directory = Path(kwargs['env']['DOCKER_CONFIG'])
                (directory / 'config.json').write_text(json.dumps({'auths': {client.host: {'auth': 'synthetic'}}}))
                locations.append(directory)
                return subprocess.CompletedProcess(arguments, 0, b'', b'')
            with patch('playbooks.harbor.files.registry.subprocess.run', side_effect=command):
                with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                    with client.identity(credential):
                        self.assertEqual((locations[0] / 'config.json').stat().st_mode & 0o777, 0o600)
                        raise RuntimeError('interrupted')
            self.assertFalse(locations[0].exists())
            self.assertNotIn('DOCKER_CONFIG', client.environment)

    def test_access_failure_must_be_denial_and_not_network_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = Registry('harbor.internal.example.invalid', {}, Path(temporary) / 'diagnostics')
            for code, message, accepted in ((1, b'UNAUTHORIZED', True), (1, b'context deadline exceeded', False),
                                             (1, b'no such host', False), (0, b'', False)):
                with self.subTest(message=message), patch('playbooks.harbor.files.registry.subprocess.run',
                        return_value=subprocess.CompletedProcess([], code, b'', message)):
                    if accepted:
                        client.command('manifest', 'synthetic', denied=True)
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'denial was not proven'):
                            client.command('manifest', 'synthetic', denied=True)

    def test_cross_project_or_tag_reference_cannot_replace_a_digest(self):
        client = Registry('harbor.internal.example.invalid', {}, None)
        with self.assertRaises(ValueError): client.reference('other-project')
        for digest in ('latest', 'sha256:wrong', 'sha256:' + 'a' * 64 + '/other'):
            with self.assertRaises(ValueError): client.reference('cloudlab-public', digest)
        self.assertTrue(client.reference('cloudlab-public', 'sha256:' + 'a' * 64).endswith('@sha256:' + 'a' * 64))

    def test_only_registry_manifest_absence_can_be_reported_as_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = Registry('harbor.internal.example.invalid', {}, Path(temporary) / 'diagnostics')
            for message in (b'UNAUTHORIZED', b'unexpected status code 404', b'context deadline exceeded', b'MANIFEST_UNKNOWN'):
                with self.subTest(message=message), patch('playbooks.harbor.files.registry.subprocess.run',
                        return_value=subprocess.CompletedProcess([], 1, b'', message)):
                    if message == b'MANIFEST_UNKNOWN':
                        self.assertIsNone(client.digest('synthetic', missing=True))
                    else:
                        with self.assertRaises(RuntimeError): client.digest('synthetic', missing=True)

    def test_harbor_not_found_is_scoped_to_known_registry_manifest_requests(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = Registry('harbor.internal.example.invalid', {}, Path(temporary) / 'diagnostics')
            for url, missing in (('https://harbor.internal.example.invalid/v2/cloudlab-public/bootstrap/manifests/deploy-bootstrap', True),
                    ('https://harbor.internal.example.invalid/service/token', False),
                    ('https://other.example.invalid/v2/cloudlab-public/bootstrap/manifests/deploy-bootstrap', False),
                    ('https://harbor.internal.example.invalid/v2/other-project/bootstrap/manifests/deploy-bootstrap', False)):
                message = ('GET ' + url + ': NOT_FOUND: repository not found').encode()
                with self.subTest(url=url), patch('playbooks.harbor.files.registry.subprocess.run',
                        return_value=subprocess.CompletedProcess([], 1, b'', message)):
                    if missing:
                        self.assertIsNone(client.digest(client.reference('cloudlab-public'), missing=True))
                    else:
                        with self.assertRaises(RuntimeError): client.digest(client.reference('cloudlab-public'), missing=True)

    def test_tool_references_and_absence_stay_inside_public_bootstrap_repositories(self):
        with tempfile.TemporaryDirectory() as temporary:
            client = Registry('harbor.internal.example.invalid', {}, Path(temporary) / 'diagnostics')
            for repository in ('ci-controller', 'ci-runner', 'ci-builder'):
                self.assertIn('/cloudlab-public/' + repository + '@sha256:',
                              client.reference('cloudlab-public', 'sha256:' + 'a' * 64, repository=repository))
                with self.assertRaises(ValueError):
                    client.reference('cloudlab-private', repository=repository)
                message = ('HEAD https://' + client.host + '/v2/cloudlab-public/' + repository +
                           '/manifests/release-test: NOT_FOUND: repository not found').encode()
                with patch('playbooks.harbor.files.registry.subprocess.run',
                           return_value=subprocess.CompletedProcess([], 1, b'', message)):
                    self.assertIsNone(client.digest(client.reference('cloudlab-public', repository=repository), missing=True))
            for repository in ('other', '../bootstrap', 'ci-runner/other'):
                with self.assertRaises(ValueError):
                    client.reference('cloudlab-public', repository=repository)
            with self.assertRaises(ValueError):
                client.reference('cloudlab-public', tag='release-test/other')
