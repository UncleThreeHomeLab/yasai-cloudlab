"""Credential lifetime and initial ownership stay outside candidate execution."""
import os
from unittest.mock import Mock, patch
import unittest
from contextlib import nullcontext
import tempfile
import shutil
import subprocess
import yaml
from pathlib import Path

from playbooks.dependencies.files import control


class ControlTests(unittest.TestCase):
    def test_declared_control_inputs_preserve_actual_public_source_guard(self):
        from playbooks.argocd.files import render
        recipe = control.ROOT / 'ansible/playbooks/dependencies/compose.yaml'
        bindings = yaml.safe_load(recipe.read_text())['services']['control']['volumes']
        targets = {value.split(':')[1]: value.split(':') for value in bindings if value.endswith(':ro')}
        required = ('ansible', 'platform', 'apps', 'gitops', 'charts', 'verification/integration',
                    'compose.yaml', '.env.example', '.gitignore')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in required:
                source = control.ROOT / name
                target = root / name
                if source.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    (target / 'tracked.txt').write_text('public input\n')
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, target)
            values = root / 'gitops/roots/public/values.yaml'
            values.parent.mkdir(parents=True, exist_ok=True)
            values.write_text('repository: https://github.com/example/platform.git\nrevision: main\n')
            def git(*args):
                return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.DEVNULL).decode().strip()
            git('init', '-q'); git('add', '.')
            git('-c', 'user.name=Synthetic', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'Synthetic public inputs')
            revision = git('rev-parse', 'HEAD')
            real_run = subprocess.run
            def run(args, **kwargs):
                if 'ls-remote' in args:
                    return subprocess.CompletedProcess(args, 0, revision+'\trefs/heads/main\n', '')
                return real_run(args, **kwargs)
            missing = []
            for name in required:
                destination = '/workspace/'+name
                covering = [key for key in targets if destination == key or destination.startswith(key+'/')]
                if not covering:
                    missing.append(name)
                    path = root/name
                    if path.is_dir(): shutil.rmtree(path)
                    else: path.unlink()
            with patch.object(render, 'ROOT', root), patch.object(render, 'PUBLIC', values.parent), \
                    patch.object(render, 'payload', return_value={}), patch.object(render.subprocess, 'run', side_effect=run):
                self.assertEqual(render.committed_payload()['revision'], revision, missing)
                cache = root/'ansible/__pycache__'
                cache.mkdir(); (cache/'synthetic.pyc').write_bytes(b'public runtime cache')
                self.assertEqual(render.committed_payload()['revision'], revision)
                for name in ('.gitignore',):
                    path=root/name; original=path.read_bytes();path.unlink()
                    with self.assertRaises(RuntimeError):render.committed_payload()
                    path.write_bytes(original)
                (root/'.env.example').write_text('changed public input\n')
                with self.assertRaises(RuntimeError): render.committed_payload()
                (root/'.env.example').unlink()
                with self.assertRaises(RuntimeError): render.committed_payload()
            for name in required:
                destination='/workspace/'+name
                owner=next(key for key in targets if destination==key or destination.startswith(key+'/'))
                source=targets[owner][0]
                self.assertEqual((recipe.parent/source).resolve(), (control.ROOT/owner.removeprefix('/workspace/')).resolve())
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
