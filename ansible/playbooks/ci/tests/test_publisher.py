"""Publication ordering, repository boundaries and credential separation without service access."""
from contextlib import contextmanager
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from playbooks.ci.files import publisher


class PublisherTests(unittest.TestCase):
    def test_component_inputs_are_bounded_and_cannot_escape_the_source_or_choose_commands(self):
        document, environment = self.inputs()
        document.update(components={'agent': {'dockerfile': 'deploy/agent.Dockerfile'}}, primary_component='agent',
                        release_visibility='private')
        self.assertEqual(publisher.configuration(document, environment), document)
        for components, primary in (({}, 'agent'), ({str(n): {'dockerfile': 'Dockerfile'} for n in range(9)}, '0'),
                ({'agent-': {'dockerfile': 'Dockerfile'}}, 'agent-'),
                ({'Agent': {'dockerfile': 'Dockerfile'}}, 'Agent'), ({'agent': {'dockerfile': '../Dockerfile'}}, 'agent'),
                ({'agent': {'dockerfile': '/Dockerfile'}}, 'agent'), ({'agent': {'dockerfile': './Dockerfile'}}, 'agent'),
                ({'agent': {'dockerfile': 'x/../Dockerfile'}}, 'agent'), ({'agent': {'dockerfile': 'x//Dockerfile'}}, 'agent'),
                ({'agent': {'dockerfile': 'Dockerfile', 'target': '--command'}}, 'agent'),
                ({'agent': {'dockerfile': 'Dockerfile', 'command': 'bad'}}, 'agent'), (document['components'], 'missing')):
            with self.subTest(components=components), self.assertRaises(ValueError):
                publisher.configuration(dict(document, components=components, primary_component=primary), environment)

    def test_component_build_uses_reviewed_filename_optional_target_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'; source.mkdir()
            (source / 'deploy').mkdir()
            (source / 'deploy/agent.Dockerfile').write_text('FROM scratch')
            output = Path(temporary) / 'output'; output.mkdir()
            calls = []
            digest = 'sha256:' + 'a' * 64
            def execute(arguments, environment, **kwargs):
                calls.append(arguments)
                if arguments[0] == 'buildctl': (output / 'image.tar').write_bytes(b'archive')
                if arguments[0] == 'crane': return digest.encode()
                if arguments[0] == 'trivy':
                    (output / 'scan.json').write_text(json.dumps({'SchemaVersion': 2,
                        'ArtifactType': 'container_image', 'Results': [{'Vulnerabilities': [], 'Secrets': []}]}))
                return b''
            with patch.object(publisher, 'execute', side_effect=execute):
                for target in (None, 'runtime'):
                    build = {'dockerfile': 'deploy/agent.Dockerfile'}
                    if target: build['target'] = target
                    publisher.build_and_scan(source, output, {}, build)
                    command = next(c for c in calls if c[0] == 'buildctl')
                    self.assertIn('filename=deploy/agent.Dockerfile', command)
                    self.assertEqual('target=runtime' in command, target is not None)
                    calls.clear()
            (source / 'deploy/agent.Dockerfile').unlink()
            (source / 'deploy/agent.Dockerfile').symlink_to(source / 'outside')
            with patch.object(publisher, 'execute') as native, self.assertRaises(ValueError):
                publisher.build_and_scan(source, output, {}, {'dockerfile': 'deploy/agent.Dockerfile'})
            native.assert_not_called()

    def test_component_publication_is_repeat_safe_and_proposes_only_after_every_signature(self):
        document, environment = self.inputs()
        document.update(components={name: {'dockerfile': name + '.Dockerfile'} for name in ('agent', 'pull', 'push', 'worker')},
                        primary_component='worker', release_visibility='private')
        digests = {name: 'sha256:' + digit * 64 for name, digit in zip(('agent', 'pull', 'push', 'worker'), 'cdf0')}
        for failure in (None, 'scan', 'sign', 'collision'):
            events = []
            def credentials(directory, registry, project, role, native):
                self.assertEqual(set(native), {'PATH', 'HOME'})
                self.assertEqual(project, 'cloudlab-public')
                events.append(role)
                return dict(native, DOCKER_CONFIG=role)
            def scan(source, directory, native, component):
                name = directory.name
                events.append('scan-' + name)
                if failure == 'scan' and name == 'worker': raise RuntimeError('scan refused')
                archive = directory / 'image.tar'; archive.write_bytes(b'scanned')
                return archive, digests[name]
            def native(arguments, native, **options):
                self.assertNotIn('GH_TOKEN', native)
                if options.get('missing'):
                    self.assertTrue(arguments[-1].startswith('registry.example.invalid/cloudlab-public/example:release-'))
                    if failure == 'collision': return ('sha256:' + 'e' * 64).encode()
                    return digests[arguments[-1].rsplit('-', 1)[-1]].encode()
                if arguments[0] == 'buildctl': return b''
                self.assertNotEqual(arguments[1], 'push', 'Matching immutable artifacts must not be pushed again')
                return arguments[-1].rsplit('@', 1)[-1].encode()
            def sign(reference, document, directory, native, source, identity):
                events.append('sign-' + directory.name)
                if failure == 'sign' and directory.name == 'worker': raise RuntimeError('signature refused')
            @contextmanager
            def token(document, native):
                events.append('token'); yield 'synthetic'; events.append('revoke')
            def propose(repository, path, desired):
                events.append('proposal')
                self.assertEqual(desired, {'digest': digests['worker'], 'components': digests, 'primary_component': 'worker',
                    'source_revision': environment['GITHUB_SHA'], 'workflow_run_id': '123'})
                return {'release_changed': True}
            with self.subTest(failure=failure), patch.object(publisher, 'registry_environment', side_effect=credentials), \
                    patch.object(publisher, 'build_and_scan', side_effect=scan), \
                    patch.object(publisher, 'execute', side_effect=native), patch.object(publisher, 'sign', side_effect=sign), \
                    patch.object(publisher, 'release_token', side_effect=token) as release_token, \
                    patch.object(publisher.release, 'propose', side_effect=propose) as proposal:
                if failure:
                    with self.assertRaises((RuntimeError, ValueError)):
                        publisher.publish(document, Path('/source'), environment)
                    release_token.assert_not_called(); proposal.assert_not_called()
                else:
                    publisher.publish(document, Path('/source'), environment)
                    self.assertEqual(events, ['pull', 'scan-agent', 'push', 'sign-agent', 'scan-pull', 'sign-pull',
                                              'scan-push', 'sign-push', 'scan-worker', 'sign-worker',
                                              'token', 'proposal', 'revoke'])

    def test_release_token_uses_native_rsa_jwt_one_repository_permissions_and_revocation_on_interruption(self):
        document, environment = self.inputs()
        document['release_visibility'] = 'private'
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        calls = []
        def api(method, path, data=None, *, token=None):
            calls.append((method, path))
            if method == 'POST':
                self.assertEqual(path, 'app/installations/9/access_tokens')
                self.assertEqual(data, {'repository_ids': [456], 'permissions': {'contents': 'write', 'pull_requests': 'write'}})
                header, payload, signature = token.split('.')
                decode = lambda value: base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
                self.assertEqual(json.loads(decode(header)), {'alg': 'RS256', 'typ': 'JWT'})
                claims = json.loads(decode(payload))
                self.assertEqual(claims['iss'], '7')
                self.assertLessEqual(claims['exp'] - claims['iat'], 600)
                key.public_key().verify(decode(signature), (header + '.' + payload).encode(), padding.PKCS1v15(), hashes.SHA256())
                return {'token': 'synthetic-one-repository-token'}
            self.assertEqual(token, 'synthetic-one-repository-token')
            if method == 'GET':
                return {'id': 456, 'fork': False, 'archived': False, 'private': True,
                        'full_name': 'example/gitops', 'default_branch': 'main'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'github').mkdir()
            (root / 'github/app_id').write_text('7')
            (root / 'github/installation_id').write_text('9')
            (root / 'github/private_key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            with patch.object(publisher, 'SECRETS', root), patch.object(publisher.release, 'api', side_effect=api):
                with self.assertRaisesRegex(RuntimeError, 'interrupted'):
                    with publisher.release_token(document, {'PATH': os.environ['PATH'], 'HOME': temporary}) as token:
                        self.assertEqual(token, 'synthetic-one-repository-token')
                        raise RuntimeError('interrupted')
        self.assertEqual(calls[-1], ('DELETE', 'installation/token'))

    def test_public_signing_requires_exact_issuer_workflow_repository_main_and_source_without_private_key(self):
        document, identity = self.inputs()
        identity.update(ACTIONS_ID_TOKEN_REQUEST_TOKEN='synthetic-oidc-request',
                        ACTIONS_ID_TOKEN_REQUEST_URL='https://oidc.example.invalid/request')
        native = {'PATH': '/usr/bin', 'HOME': '/tmp', 'DOCKER_CONFIG': '/tmp/push'}
        calls = []
        def execute(arguments, environment, **kwargs):
            calls.append((arguments, environment))
            self.assertNotIn('GH_TOKEN', environment)
            self.assertNotIn('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', environment)
            return b''
        with patch.object(publisher, 'execute', side_effect=execute), \
                patch.object(publisher, 'credential', side_effect=AssertionError('Public signing must not read private key credentials')):
            publisher.sign('registry.example.invalid/cloudlab-public/example@sha256:' + 'a' * 64,
                           document, Path('/tmp'), native, identity['GITHUB_SHA'], identity)
        sign, verify = calls
        self.assertEqual(sign[0][:3], ['cosign', 'sign', '--yes'])
        self.assertIn('--new-bundle-format=false', sign[0])
        self.assertIn('--use-signing-config=false', sign[0])
        self.assertIn('--sign-container-identity=https://github.com/example/app', sign[0])
        self.assertNotIn('registry.example.invalid', ' '.join(sign[0][:-1]))
        self.assertEqual(sign[1]['ACTIONS_ID_TOKEN_REQUEST_TOKEN'], 'synthetic-oidc-request')
        self.assertNotIn('ACTIONS_ID_TOKEN_REQUEST_TOKEN', verify[1])
        expected = {'--certificate-identity': document['workflow_identity'],
                    '--certificate-oidc-issuer': 'https://token.actions.githubusercontent.com',
                    '--certificate-github-workflow-repository': 'example/app',
                    '--certificate-github-workflow-ref': 'refs/heads/main',
                    '--certificate-github-workflow-sha': identity['GITHUB_SHA']}
        for argument, value in expected.items():
            self.assertEqual(verify[0][verify[0].index(argument) + 1], value)
        self.assertNotIn('--insecure-ignore-tlog', ' '.join(verify[0]))

    def inputs(self):
        document = {'application': 'example', 'source_repository': 'example/app', 'source_repository_id': '123',
                    'visibility': 'public', 'registry': 'registry.example.invalid', 'project': 'cloudlab-public',
                    'release_repository': 'example/gitops', 'release_repository_id': 456,
                    'workflow_identity': 'https://github.com/example/platform/.github/workflows/application-publish.yaml@' + 'a' * 40}
        environment = {'PATH': '/usr/bin', 'HOME': '/tmp', 'RUNNER_ENVIRONMENT': 'self-hosted',
                       'GITHUB_REPOSITORY': 'example/app', 'GITHUB_REPOSITORY_ID': '123',
                       'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'push',
                       'GITHUB_SHA': 'b' * 40, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                       'OP_PROVISION_SERVICE_ACCOUNT_TOKEN': 'never-pass-writer', 'GH_TOKEN': 'never-pass-caller'}
        return document, environment

    def test_only_approved_local_main_can_use_the_matching_project_and_gitops_repository(self):
        document, environment = self.inputs()
        self.assertEqual(publisher.configuration(document, environment), document)
        for key, value in (('project', 'cloudlab-private'), ('release_repository', 'foreign/gitops'),
                           ('registry', 'https://untrusted.invalid'), ('workflow_identity', 'https://github.com/example/main')):
            with self.subTest(field=key), self.assertRaises(ValueError):
                publisher.configuration(dict(document, **{key: value}), environment)
        for key, value in (('RUNNER_ENVIRONMENT', 'github-hosted'), ('GITHUB_REF', 'refs/pull/1/merge'),
                           ('GITHUB_EVENT_NAME', 'pull_request_target'), ('GITHUB_REPOSITORY_ID', '999'),
                           ('GITHUB_REPOSITORY', 'foreign/app'), ('GITHUB_SHA', 'main')):
            with self.subTest(field=key), self.assertRaises(ValueError):
                publisher.configuration(document, dict(environment, **{key: value}))

    def test_scan_failure_cannot_load_push_or_release_credentials_or_change_artifacts(self):
        document, environment = self.inputs()
        with patch.object(publisher, 'registry_environment', return_value={'PATH': '/usr/bin'}) as credentials, \
                patch.object(publisher, 'build_and_scan', side_effect=RuntimeError('scan refused')), \
                patch.object(publisher, 'execute') as native, patch.object(publisher, 'sign') as sign, \
                patch.object(publisher, 'release_token') as token, self.assertRaises(RuntimeError):
            publisher.publish(document, Path('/application'), environment)
        self.assertEqual(credentials.call_count, 1)
        self.assertEqual(credentials.call_args.args[3], 'pull')
        self.assertNotIn('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', credentials.call_args.args[4])
        self.assertNotIn('GH_TOKEN', credentials.call_args.args[4])
        native.assert_not_called()
        sign.assert_not_called()
        token.assert_not_called()

    def test_success_pushes_the_scanned_digest_signs_then_proposes_one_file_and_revokes_token(self):
        document, environment = self.inputs()
        digest = 'sha256:' + 'c' * 64
        events = []
        def credentials(directory, registry, project, role, native):
            self.assertEqual(set(native), {'PATH', 'HOME'})
            self.assertEqual(project, 'cloudlab-public')
            events.append(role)
            return dict(native, DOCKER_CONFIG=role)
        def scan(source, directory, native):
            self.assertEqual(native['DOCKER_CONFIG'], 'pull')
            events.append('scan')
            return directory / 'image.tar', digest
        def native(arguments, native, **options):
            self.assertNotIn('GH_TOKEN', native)
            if options.get('missing'):
                return None
            if arguments[1] == 'push':
                self.assertEqual(native['DOCKER_CONFIG'], 'push')
                events.append('push-image')
                return b''
            self.assertEqual(native['DOCKER_CONFIG'], 'pull')
            self.assertTrue(arguments[-1].endswith('@' + digest))
            return digest.encode()
        @contextmanager
        def token(document, native):
            events.append('token')
            try:
                yield 'synthetic-scoped-writer'
            finally:
                events.append('revoke')
        def propose(repository, path, desired):
            self.assertEqual(repository, 'example/gitops')
            self.assertEqual(path, 'apps/releases/example.json')
            self.assertEqual(desired, {'digest': digest, 'source_revision': 'b' * 40, 'workflow_run_id': '123'})
            self.assertEqual(os.environ['GH_TOKEN'], 'synthetic-scoped-writer')
            self.assertNotIn('OP_PROVISION_SERVICE_ACCOUNT_TOKEN', os.environ)
            events.append('proposal')
            return {'release_changed': True, 'pull_request_only': True}
        original = dict(os.environ)
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(publisher, 'registry_environment', side_effect=credentials), \
                patch.object(publisher, 'build_and_scan', side_effect=scan), \
                patch.object(publisher, 'execute', side_effect=native), \
                patch.object(publisher, 'sign', side_effect=lambda *args: events.append('sign')), \
                patch.object(publisher, 'release_token', side_effect=token), \
                patch.object(publisher.release, 'propose', side_effect=propose):
            result = publisher.publish(document, Path('/application'), os.environ)
            self.assertEqual(dict(os.environ), environment)
        self.assertEqual(events, ['pull', 'scan', 'push', 'push-image', 'sign', 'token', 'proposal', 'revoke'])
        self.assertEqual(result['digest'], digest)
        self.assertEqual(dict(os.environ), original)

    def test_registry_authentication_is_scoped_to_one_robot_and_never_printed_or_passed_in_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secrets = root / 'secrets/pull'
            secrets.mkdir(parents=True)
            for field, value in {'username': 'robot$cloudlab-public+pull', 'password': 'synthetic',
                                 'secret_version': '1'}.items():
                (secrets / field).write_text(value)
            with patch.object(publisher, 'SECRETS', root / 'secrets'):
                environment = publisher.registry_environment(root, 'registry.example.invalid', 'cloudlab-public',
                                                             'pull', {'PATH': '/usr/bin'})
                path = Path(environment['DOCKER_CONFIG']) / 'config.json'
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                auth = json.loads(path.read_text())['auths']
                self.assertEqual(set(auth), {'registry.example.invalid'})
                self.assertEqual(base64.b64decode(auth['registry.example.invalid']['auth']),
                                 b'robot$cloudlab-public+pull:synthetic')
                other = root / 'other'
                other.mkdir()
                with self.assertRaises(ValueError):
                    publisher.registry_environment(other, 'registry.example.invalid', 'cloudlab-private', 'pull', {})
