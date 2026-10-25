"""Standalone Actions staging cannot copy untracked inputs or dirty public source."""
from pathlib import Path
import hashlib
import io
import tarfile
import tempfile
import os
import subprocess
import unittest
from unittest.mock import Mock, patch

from playbooks.dependencies.files import local
from playbooks.dependencies.tests.fixtures import actions_source


class LocalSourceTests(unittest.TestCase):
    def test_clean_source_seed_preserves_all_owned_files_and_ignored_tracked_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'source', Path(directory) / 'target'
            source.mkdir()
            environment = {'PATH': os.environ['PATH'], 'HOME': '/tmp/home', 'GIT_CONFIG_NOSYSTEM': '1',
                           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
            subprocess.run(['git', 'init', '--template='], cwd=source, env=environment, capture_output=True, check=True)
            tracked = ['.gitignore', 'ansible/runner/README.md', 'platform/example/README.md',
                       'apps/example/README.md', 'charts/example/README.md']
            for relative in tracked:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('*.md\n__pycache__/\n.env\n' if relative == '.gitignore' else 'Public owner\n')
            subprocess.run(['git', 'add', '--force', '--', *tracked], cwd=source, env=environment,
                           capture_output=True, check=True)
            added = ['ansible/playbooks/dependencies/tests/fixtures/native/ansible/runner/Dockerfile',
                     'ansible/playbooks/dependencies/tests/fixtures/native/infra/github/versions.tf',
                     'ansible/playbooks/dependencies/tests/fixtures/native/ansible/runner/requirements.txt',
                     'ansible/playbooks/dependencies/README.md']
            metadata = source / 'platform/delivery/dependencies/owners.json'
            metadata.parent.mkdir(parents=True)
            import json
            metadata.write_text(json.dumps({'owners': {'native-extraction-fixture': {
                'sources': added[:3], 'companions': []}}}))
            added.append('platform/delivery/dependencies/owners.json')
            excluded = ['ansible/playbooks/dependencies/tests/__pycache__/old.py',
                        'ansible/playbooks/dependencies/.env', 'apps/private-bootstrap.json',
                        'ansible/playbooks/dependencies/.npmrc', 'ansible/playbooks/dependencies/private-input.txt']
            for relative in added + excluded:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                if path != metadata:
                    path.write_text('Public fixture\n' if relative in added else 'Synthetic private input\n')
            result = actions_source(source, target)
            actual = set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=target, env=environment).decode().strip('\0').split('\0'))
            self.assertEqual(actual, set(tracked + added))
            self.assertEqual(result['publicFiles'], len(actual))
            for relative in added + tracked:
                self.assertEqual((source / relative).read_bytes(), (target / relative).read_bytes())
            self.assertFalse(any((target / relative).exists() for relative in excluded))
    def test_dirty_source_fails_before_any_lookup_or_candidate_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate, control = root / 'candidate', root / 'control'
            with patch.object(local, 'ROOT', root), patch.object(local, 'CANDIDATE', candidate), \
                    patch.object(local, 'CONTROL', control), \
                    patch.object(local.subprocess, 'run', return_value=Mock(returncode=1)), \
                    patch.object(local.actions, 'official') as official:
                with self.assertRaises(ValueError):
                    local.stage('a' * 40)
                official.assert_not_called()
                self.assertEqual(list(candidate.iterdir()), [])

    def test_only_index_tracked_public_paths_are_copied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'apps').mkdir()
            (root / 'apps/public.json').write_text('{}')
            (root / 'apps/private-bootstrap.json').write_text('synthetic private input')
            candidate, control = root / 'candidate', root / 'control'
            owner = {'checks': ['existing-check'], 'writePaths': []}
            blob = hashlib.sha1(b'blob 2\0{}').hexdigest()
            archived = io.BytesIO()
            with tarfile.open(fileobj=archived, mode='w') as archive:
                member = tarfile.TarInfo('apps/public.json')
                member.size = 2
                archive.addfile(member, io.BytesIO(b'{}'))
            results = [Mock(returncode=0), Mock(returncode=0, stdout=('100644 ' + blob + ' 0\tapps/public.json\0').encode()),
                       Mock(returncode=0, stdout=archived.getvalue())]
            with patch.object(local, 'ROOT', root), patch.object(local, 'CANDIDATE', candidate), \
                    patch.object(local, 'CONTROL', control), patch.object(local, 'selected', return_value={'actions': owner}), \
                    patch.object(local.subprocess, 'run', side_effect=results) as run, \
                    patch.object(local.actions, 'official'), patch.object(local.actions, 'update'), \
                    patch.object(local, 'save'):
                local.stage('a' * 40)
            self.assertTrue((candidate / 'apps/public.json').is_file())
            self.assertFalse((candidate / 'apps/private-bootstrap.json').exists())
            self.assertNotIn('--others', run.call_args_list[1].args[0])
