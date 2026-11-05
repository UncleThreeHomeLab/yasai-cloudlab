"""Offline safety checks for the disposable native controller fixture."""
import functools
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import subprocess
import sys
import time
import urllib.error
import urllib.request

import yaml

import permissions_proof as proof


class SourceBoundaryTests(unittest.TestCase):
    def test_git_http_exposes_only_bare_sources_without_write_or_path_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = proof.GitSource(root, 'public', {'chart/' + name: value for name, value in proof.catalog_files().items()})
            proof.GitSource(root, 'private', {'permissions.yaml': proof.values()})
            (root / 'private-key').write_text('synthetic-private-material')
            (root / 'public.git/escape').symlink_to(root / 'private-key')
            server = proof.GitServer(('127.0.0.1', 0),
                functools.partial(proof.ReadOnlyGit, directory=str(root)))
            server.block_private = False
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = 'http://127.0.0.1:' + str(server.server_port)
            try:
                clone = root / 'clone'
                proof.command(['git', 'clone', '--branch', 'main', url + '/public.git', str(clone)])
                self.assertEqual(proof.command(['git', 'rev-parse', 'HEAD'], clone).strip(), public.revision)
                public.commit({'new.yaml': 'synthetic: true\n'})
                proof.command(['git', 'fetch', 'origin', 'main'], clone)
                self.assertEqual(proof.command(['git', 'rev-parse', 'FETCH_HEAD'], clone).strip(), public.revision)
                for path in ('/private-key', '/public.git/../private-key', '/public.git/%2e%2e/private-key',
                             '/public.git/escape', '/public.git/', '/public.git/git-receive-pack',
                             '/public.git/info/refs?service=git-receive-pack', '/public.git/HEAD'):
                    with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError):
                        urllib.request.urlopen(url + path)
                for headers in ({'Content-Type': 'application/x-git-upload-pack-request', 'Content-Length': '1048577'},
                                {'Content-Type': 'application/x-git-upload-pack-request', 'Content-Encoding': 'gzip'},
                                {'Content-Type': 'application/x-git-upload-pack-request', 'Transfer-Encoding': 'chunked'},
                                {'Content-Type': 'application/json'}):
                    with self.subTest(headers=headers), self.assertRaises(urllib.error.HTTPError):
                        urllib.request.urlopen(urllib.request.Request(url + '/public.git/git-upload-pack',
                                                                       data=b'write', headers=headers))
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_backend_timeout_and_output_cap_kill_owned_process(self):
        popen = subprocess.Popen
        for program, timeout in [('import time; time.sleep(10)', 0.05), ('import sys; sys.stdout.buffer.write(b"x" * 5000000)', 2)]:
            created = []
            def start(*args, **kwargs):
                process = popen([sys.executable, '-c', program], **kwargs)
                created.append(process)
                return process
            with self.subTest(program=program), patch.object(proof.subprocess, 'Popen', side_effect=start):
                with self.assertRaises(RuntimeError): proof.git_backend(b'', {'PATH': '/usr/bin:/bin'}, timeout)
                self.assertIsNotNone(created[0].poll())

    def test_backend_keeps_leader_unreaped_until_owned_group_cleanup(self):
        popen = subprocess.Popen
        killpg = proof.os.killpg
        calls = []
        def start(*args, **kwargs):
            process = popen([sys.executable, '-c', 'pass'], **kwargs)
            original_wait = process.wait
            def wait(*args, **kwargs):
                calls.append('reap')
                return original_wait(*args, **kwargs)
            process.wait = wait
            return process
        def kill(*args):
            calls.append('group-cleanup')
            return killpg(*args)
        with patch.object(proof.subprocess, 'Popen', side_effect=start), patch.object(proof.os, 'killpg', side_effect=kill):
            self.assertEqual(proof.git_backend(b'', {'PATH': '/usr/bin:/bin'}), b'')
        self.assertEqual(calls, ['group-cleanup', 'reap'])

    def test_native_git_transport_reads_exact_committed_chart(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = proof.GitSource(root, 'public', {'chart/' + name: value for name, value in proof.catalog_files().items()})
            self.assertEqual(len(source.revision), 40)
            for name, value in proof.catalog_files().items():
                actual = proof.command(['git', '--git-dir', str(source.bare), 'show', source.revision + ':chart/' + name])
                self.assertEqual(actual, value)
            with self.assertRaises(RuntimeError): source.commit({'../escape': 'unsafe'})

    def test_chart_requires_explicit_complete_permission_document(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in proof.catalog_files().items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(value)
            values = root / 'input.yaml'
            for content in ('{}', 'permissions: {}', proof.values(assignments=True, state='retired')):
                values.write_text(content)
                with self.subTest(content=content), self.assertRaises(RuntimeError):
                    proof.command(['helm', 'template', 'fixture', str(root), '-f', str(values)])
            values.write_text(proof.values(assignments=False, state='retired'))
            objects = list(yaml.safe_load_all(proof.command(['helm', 'template', 'fixture', str(root), '-f', str(values)])))
            self.assertTrue(objects)
            self.assertTrue(all(obj['kind'] == 'ClusterRole' for obj in objects if obj))

    def render_catalog(self, values, files=None, success=True):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in (files or proof.catalog_files()).items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(value)
            path = root / 'input.yaml'
            path.write_text(values if isinstance(values, str) else yaml.safe_dump(values))
            if not success:
                with self.assertRaises(RuntimeError): proof.command(['helm', 'template', 'fixture', str(root), '-f', str(path)])
                return []
            return [row for row in yaml.safe_load_all(proof.command(['helm', 'template', 'fixture', str(root), '-f', str(path)])) if row]

    def test_exact_namespace_and_cluster_assignments_keep_rule_sets_separate(self):
        rows = self.render_catalog(proof.values(cluster=True))
        bindings = [row for row in rows if row['kind'].endswith('Binding')]
        self.assertEqual({row['kind'] for row in bindings}, {'RoleBinding', 'ClusterRoleBinding'})
        namespace = next(row for row in bindings if row['kind'] == 'RoleBinding')
        cluster = next(row for row in bindings if row['kind'] == 'ClusterRoleBinding')
        self.assertEqual(namespace['metadata']['namespace'], proof.NAMESPACE)
        self.assertTrue(namespace['roleRef']['name'].endswith('-namespace'))
        self.assertTrue(cluster['roleRef']['name'].endswith('-cluster'))
        self.assertNotIn('namespace', cluster['metadata'])
        roles = {row['metadata']['name']: row['rules'] for row in rows if row['kind'] == 'ClusterRole'}
        self.assertEqual(roles[cluster['roleRef']['name']], [{'apiGroups': [''], 'resources': ['nodes'], 'verbs': ['get', 'list']}])

    def test_private_inputs_cannot_override_profiles_or_add_ambiguous_authority(self):
        original = yaml.safe_load(proof.values())
        cases = []
        for change in ({'profiles': {}}, {'permissions': {}}):
            cases.append(original | change)
        import copy
        for field, value in (('profile', 'unknown'), ('scope', {'cluster': True}),
                             ('scope', {'namespace': proof.NAMESPACE, 'cluster': True}),
                             ('subject', {'kind': 'Group', 'name': 'admins'}),
                             ('subject', {'kind': 'User', 'name': 'system:masters'}),
                             ('roleRef', {'name': 'cluster-admin'})):
            changed = copy.deepcopy(original)
            changed['permissions']['assignments'][0][field] = value
            cases.append(changed)
        duplicate = copy.deepcopy(original)
        duplicate['permissions']['assignments'] *= 2
        cases.append(duplicate)
        for changed in cases:
            with self.subTest(changed=changed): self.render_catalog(changed, success=False)

    def test_presets_have_no_implicit_grants_or_sensitive_runtime_verbs(self):
        rows = self.render_catalog(proof.values(assignments=False))
        self.assertTrue(all(row['kind'] == 'ClusterRole' for row in rows))
        forbidden = {'*', 'secrets', 'configmaps', 'pods/log', 'pods/exec', 'pods/attach', 'pods/proxy'}
        for row in rows:
            for rule in row['rules']:
                self.assertEqual(rule['verbs'], ['get', 'list'])
                self.assertFalse(set(rule['resources']) & forbidden)

    def test_entire_public_profile_document_is_validated_even_if_unassigned(self):
        files = proof.catalog_files()
        profiles = yaml.safe_load(files['profiles.yaml'])
        profiles['profiles']['unassigned'] = {'namespaceRules': [{'apiGroups': [''], 'resources': ['pods'],
            'verbs': ['get'], 'aggregationRule': {}}], 'clusterRules': []}
        self.render_catalog(proof.values(assignments=False), files | {'profiles.yaml': yaml.safe_dump(profiles)}, success=False)

    def test_stale_failure_and_uncleared_comparison_cannot_qualify_current_revision(self):
        revisions = ['public-current', 'private-current']
        status = {'sync': {'status': 'Synced', 'revisions': revisions},
                  'operationState': {'phase': 'Succeeded'}}
        self.assertTrue(proof.current_sync(status, revisions))
        status['conditions'] = [{'type': 'ComparisonError', 'message': 'old failure'}]
        self.assertFalse(proof.current_sync(status, revisions))
        status['operationState'] = {'phase': 'Failed', 'syncResult': {'revisions': ['public-old', 'private-old']}}
        self.assertFalse(proof.current_project_rejection(status, revisions))
        status['operationState']['syncResult']['revisions'] = revisions
        self.assertEqual(proof.current_project_rejection(status, revisions), 'sync-rejected')


if __name__ == '__main__':
    unittest.main()
