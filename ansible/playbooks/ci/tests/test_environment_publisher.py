"""Keep dependency-environment publication main-bound, scanned and resumable."""
from contextlib import nullcontext
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from playbooks.ci.files import bootstrap
from playbooks.harbor.files.registry import Registry


class EnvironmentPublisherTests(unittest.TestCase):
    def test_extended_application_inputs_preserve_environment_source_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'application.json'
            application = dict(self.application, components={'agent': {'dockerfile': 'deploy/agent.Dockerfile'}},
                               primaryComponent='agent', releaseRepository='UncleThreeHomeLab/private-config', releaseMode='manual')
            path.write_text(json.dumps(application))
            self.assertEqual(bootstrap.environment_application(path), application)
            for change in ({'primaryComponent': 'missing'}, {'releaseRepository': 'foreign/private'},
                           {'components': {'agent': {'dockerfile': '../Dockerfile'}}}):
                path.write_text(json.dumps(dict(application, **change)))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    bootstrap.environment_application(path)

    application = {'name': 'example-app', 'repository': 'https://github.com/UncleThreeHomeLab/example-app.git',
                   'visibility': 'public'}
    digest = 'sha256:' + 'a' * 64

    def archive(self, path, revision='b' * 40, *, source=None, config_name=None, duplicate=False):
        config = json.dumps({'os': 'linux', 'architecture': 'amd64', 'config': {'Labels': {
            'org.opencontainers.image.source': source or self.application['repository'].removesuffix('.git'),
            'org.opencontainers.image.revision': revision}}}).encode()
        name = config_name or hashlib.sha256(config).hexdigest() + '.json'
        with tarfile.open(path, 'w') as output:
            for filename, content in [('manifest.json', json.dumps([{'Config': name, 'Layers': []}]).encode()),
                                      (name, config)] + ([(name, config)] if duplicate else []):
                member = tarfile.TarInfo(filename)
                member.size = len(content)
                output.addfile(member, io.BytesIO(content))
        return path

    def checkout(self, directory):
        directory.mkdir()
        def git(*arguments):
            return subprocess.check_output(['git', *arguments], cwd=directory, stderr=subprocess.DEVNULL,
                                           encoding='utf-8').strip()
        git('init', '--quiet', '-b', 'main')
        git('config', 'user.name', 'Synthetic owner')
        git('config', 'user.email', 'owner@example.invalid')
        git('remote', 'add', 'origin', self.application['repository'])
        (directory / 'requirements.txt').write_text('synthetic==1\n')
        git('add', 'requirements.txt')
        git('commit', '--quiet', '-m', 'Synthetic main')
        revision = git('rev-parse', 'HEAD')
        current = {'full_name': 'UncleThreeHomeLab/example-app', 'visibility': 'public', 'private': False,
                   'fork': False, 'archived': False, 'disabled': False, 'default_branch': 'main'}
        branch = {'protected': True, 'commit': {'sha': revision}}
        github = SimpleNamespace(request=Mock(side_effect=lambda method, path: branch if path.endswith('/branches/main') else current))
        return revision, github, branch

    def client(self, directory):
        return SimpleNamespace(path=directory, revision='c' * 40, env={}, plan=Mock(return_value={'changes': 0}),
            private={'host': 'harbor.internal.example.invalid', 'robots': {
                bootstrap.PROJECT + '-push': {'username': 'synthetic-push'},
                bootstrap.PROJECT + '-pull': {'username': 'synthetic-pull'}}})

    def test_archive_identity_and_metadata_paths_are_checked_without_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = self.archive(root / 'environment.tar')
            self.assertEqual(bootstrap.environment_metadata(archive, self.application),
                             {'source_repository': self.application['repository'], 'source_revision': 'b' * 40})
            for options in ({'source': 'https://github.com/other/repo'}, {'revision': 'not-a-sha'},
                            {'config_name': '../outside.json'}, {'config_name': '0' * 64 + '.json'},
                            {'duplicate': True}):
                with self.subTest(options=options):
                    self.archive(archive, **options)
                    with self.assertRaises(ValueError):
                        bootstrap.environment_metadata(archive, self.application)
            self.assertFalse((root.parent / 'outside.json').exists())

    def test_application_and_output_cannot_expand_publication_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = root / 'application.json'
            for change in ({'visibility': 'private'}, {'name': '../other'}, {'name': 3},
                           {'repository': 'https://other.invalid/owner/repo.git'}, {'unknown': True}):
                application.write_text(json.dumps(dict(self.application, **change)))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    bootstrap.environment_application(application)
            application.write_text(json.dumps(self.application))
            self.assertEqual(bootstrap.environment_application(application), self.application)
            linked = root / 'application-link.json'
            linked.symlink_to(application)
            with self.assertRaises(ValueError):
                bootstrap.environment_application(linked)
            with patch.object(bootstrap.api, 'WORK', root / 'protected'):
                with self.assertRaises(ValueError):
                    bootstrap.environment_output(root / 'public.json')
                target = root / 'protected/reference.json'
                self.assertEqual(bootstrap.environment_output(target), target)
                target.parent.mkdir()
                target.with_suffix('.tmp').symlink_to(root / 'outside')
                with self.assertRaises(ValueError):
                    bootstrap.environment_output(target)

    def test_archive_metadata_count_and_size_are_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'environment.tar'
            with tarfile.open(archive, 'w') as output:
                for index in range(4097):
                    output.addfile(tarfile.TarInfo(str(index)))
            with self.assertRaisesRegex(ValueError, 'too many metadata'):
                bootstrap.environment_metadata(archive, self.application)
            with tarfile.open(archive, 'w') as output:
                content = b' ' * (1024 * 1024 + 1)
                member = tarfile.TarInfo('manifest.json')
                member.size = len(content)
                output.addfile(member, io.BytesIO(content))
            with self.assertRaisesRegex(ValueError, 'oversized'):
                bootstrap.environment_metadata(archive, self.application)

    def test_output_parent_traversal_is_rejected_before_credentials_or_filesystem_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, work = directory / 'checkout', directory / 'protected/state'
            root.mkdir()
            (root / '.infra-private').mkdir()
            for output in (root / '.infra-private/../leak.json', work / '../../outside.json',
                           root / '.infra-private/../leak.tmp'):
                arguments = ['bootstrap', '--test-environment-archive', str(directory / 'archive.tar'),
                             '--application-file', str(directory / 'application.json'),
                             '--source-checkout', str(directory / 'source'), '--output', str(output)]
                with self.subTest(output=output), patch.object(bootstrap, 'ROOT', root), \
                        patch.object(bootstrap.api, 'WORK', work), \
                        patch.object(bootstrap, 'scan_archive', side_effect=AssertionError('Scanner called')), \
                        patch.object(bootstrap, 'atomic', side_effect=AssertionError('Publication record written')), \
                        patch.object(bootstrap.api, 'Client', side_effect=AssertionError('Credentials loaded')), \
                        patch('playbooks.argocd.files.github_setup.inputs',
                              side_effect=AssertionError('GitHub token read')), patch('sys.argv', arguments):
                    with self.assertRaisesRegex(ValueError, 'parent traversal'):
                        bootstrap.main()
                self.assertFalse(work.exists())
                self.assertFalse((root / 'leak.json').exists())
                self.assertFalse((root / 'leak.tmp').exists())
                self.assertFalse((directory / 'outside.json').exists())

    def test_normal_absolute_and_relative_output_paths_resolve_inside_accepted_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / '.infra-private'
            private.mkdir()
            with patch.object(bootstrap, 'ROOT', root), patch.object(bootstrap.api, 'WORK', root / 'state'), \
                    patch('os.getcwd', return_value=str(root)):
                target = private / 'reference.json'
                self.assertEqual(bootstrap.environment_output(target), target.resolve())
                self.assertEqual(bootstrap.environment_output(Path('.infra-private/reference.json')), target.resolve())
                with self.assertRaisesRegex(ValueError, 'parent traversal'):
                    bootstrap.local_path(Path('.infra-private/../reference.json'))

    def test_current_clean_protected_main_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'
            revision, github, branch = self.checkout(source)
            metadata = {'source_repository': self.application['repository'], 'source_revision': revision}
            bootstrap.environment_source(source, self.application, metadata, github)
            branch['protected'] = False
            with self.assertRaisesRegex(ValueError, 'protected public main'):
                bootstrap.environment_source(source, self.application, metadata, github)
            branch['protected'] = True
            branch['commit']['sha'] = 'd' * 40
            with self.assertRaises(ValueError):
                bootstrap.environment_source(source, self.application, metadata, github)
            branch['commit']['sha'] = revision
            (source / 'requirements.txt').write_text('changed==2\n')
            github.request.reset_mock()
            with self.assertRaisesRegex(ValueError, 'clean declared main'):
                bootstrap.environment_source(source, self.application, metadata, github)
            github.request.assert_not_called()
            (source / 'requirements.txt').write_text('synthetic==1\n')
            subprocess.run(['git', 'checkout', '-b', 'dev'], cwd=source, check=True, capture_output=True)
            with self.assertRaises(ValueError):
                bootstrap.environment_source(source, self.application, metadata, github)

    def test_scan_only_and_scan_failure_never_load_service_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = root / 'application.json'
            application.write_text(json.dumps(self.application))
            archive = self.archive(root / 'environment.tar')
            arguments = ['bootstrap', '--test-environment-archive', str(archive), '--application-file',
                         str(application), '--scan-only']
            with patch.object(bootstrap.api, 'WORK', root / 'protected'), \
                    patch.object(bootstrap, 'scan_archive', return_value=self.digest), \
                    patch.object(bootstrap.api, 'Client', side_effect=AssertionError('Credentials loaded')), \
                    patch('playbooks.argocd.files.github_setup.inputs', side_effect=AssertionError('GitHub token read')), \
                    patch('sys.argv', arguments), patch('sys.stdout', new_callable=io.StringIO) as output:
                bootstrap.main()
                self.assertEqual(json.loads(output.getvalue()),
                                 {'scanned_environments': 1, 'service_credentials_used': False})
            with patch.object(bootstrap.api, 'WORK', root / 'protected'), \
                    patch.object(bootstrap, 'scan_archive', side_effect=RuntimeError('Scan rejected')), \
                    patch.object(bootstrap.api, 'Client', side_effect=AssertionError('Credentials loaded')), \
                    patch('playbooks.argocd.files.github_setup.inputs', side_effect=AssertionError('GitHub token read')), \
                    patch('sys.argv', arguments):
                with self.assertRaisesRegex(RuntimeError, 'Scan rejected'):
                    bootstrap.main()

    def test_invalid_source_stops_before_native_client_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = root / 'application.json'
            application.write_text(json.dumps(self.application))
            archive = self.archive(root / 'environment.tar')
            arguments = ['bootstrap', '--test-environment-archive', str(archive), '--application-file',
                         str(application), '--source-checkout', str(root)]
            with patch.object(bootstrap.api, 'WORK', root / 'protected'), \
                    patch.object(bootstrap, 'scan_archive', return_value=self.digest), \
                    patch('playbooks.argocd.files.github_setup.inputs', return_value=({}, Mock())) as github, \
                    patch.object(bootstrap.api, 'Client', side_effect=AssertionError('Credentials loaded')), \
                    patch('sys.argv', arguments):
                with self.assertRaisesRegex(ValueError, 'normal Git checkout'):
                    bootstrap.main()
                github.assert_called_once()

    def test_publication_repeats_without_overwriting_original_reference_or_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = {'source_repository': self.application['repository'], 'source_revision': 'b' * 40}
            client = self.client(root)
            archive = self.archive(root / 'environment.tar')
            registry = Registry(client.private['host'], {}, root / 'diagnostics')
            stored, pushes = {}, []
            def command(*arguments):
                if arguments[0] == 'digest':
                    return self.digest.encode()
                self.assertEqual(arguments[0], 'push')
                stored[arguments[2]] = self.digest
                pushes.append(arguments[2])
            def digest(reference, missing=False):
                return stored.get(reference) if missing else (self.digest if '@' in reference else stored[reference])
            with patch.object(bootstrap.api, 'WORK', root), patch.object(bootstrap, 'Registry', return_value=registry), \
                    patch.object(registry, 'identity', return_value=nullcontext()) as identity, \
                    patch.object(registry, 'command', side_effect=command), patch.object(registry, 'digest', side_effect=digest):
                result = bootstrap.publish_environment(client, archive, self.application, metadata, self.digest)
                self.assertEqual(result['published_environments'], 1)
                self.assertNotIn(client.private['host'], json.dumps(result))
                directory = root / 'ci/environments/example-app' / ('b' * 40)
                reference, receipt = directory / 'reference.json', directory / 'receipt.json'
                original = reference.read_bytes(), receipt.read_bytes()
                bootstrap.publish_environment(client, archive, self.application, metadata, self.digest)
                self.assertEqual(len(pushes), 1)
                self.assertEqual((reference.read_bytes(), receipt.read_bytes()), original)
                self.assertEqual({call.args[0]['username'] for call in identity.call_args_list},
                                 {'synthetic-push', 'synthetic-pull'})
                with self.assertRaisesRegex(ValueError, 'Preserve original'):
                    bootstrap.publish_environment(client, archive, self.application, metadata, 'sha256:' + 'f' * 64)

    def test_drift_changed_archive_and_conflicting_tag_stop_before_push(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            client = self.client(root)
            metadata = {'source_repository': self.application['repository'], 'source_revision': 'b' * 40}
            archive = self.archive(root / 'environment.tar')
            client.plan.return_value = {'changes': 1}
            with patch.object(bootstrap, 'Registry', side_effect=AssertionError('Registry accessed')):
                with self.assertRaisesRegex(ValueError, 'API drift'):
                    bootstrap.publish_environment(client, archive, self.application, metadata, self.digest)
            client.plan.return_value = {'changes': 0}
            registry = Registry(client.private['host'], {}, root / 'diagnostics')
            with patch.object(bootstrap.api, 'WORK', root), patch.object(bootstrap, 'Registry', return_value=registry), \
                    patch.object(registry, 'command', return_value=('sha256:' + 'c' * 64).encode()) as command, \
                    patch.object(registry, 'identity', return_value=nullcontext()) as identity:
                with self.assertRaisesRegex(ValueError, 'changed after scanning'):
                    bootstrap.publish_environment(client, archive, self.application, metadata, self.digest)
                identity.assert_not_called()
                self.assertEqual(command.call_count, 1)
            with patch.object(bootstrap.api, 'WORK', root), patch.object(bootstrap, 'Registry', return_value=registry), \
                    patch.object(registry, 'command', return_value=self.digest.encode()) as command, \
                    patch.object(registry, 'identity', return_value=nullcontext()), \
                    patch.object(registry, 'digest', return_value='sha256:' + 'c' * 64):
                with self.assertRaisesRegex(ValueError, 'immutable environment tag differs'):
                    bootstrap.publish_environment(client, archive, self.application, metadata, self.digest)
                self.assertEqual(command.call_count, 1)
