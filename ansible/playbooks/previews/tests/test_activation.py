import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

from fixtures import catalog
from playbooks.previews.files import bootstrap, payload

ROOT = Path(__file__).resolve().parents[4]


class ActivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.overlay = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'a' * 40}
        cls.private = cls.chart({'repository': 'https://github.com/example/platform.git', 'previews': {'enabled': True},
                                 'identity': {'enabled': True, 'argo': cls.overlay}})

    @staticmethod
    def chart(values):
        result = subprocess.run(['helm', 'template', 'root', str(ROOT / 'gitops/roots/public'), '-f', '-'],
            input=json.dumps(values), capture_output=True, text=True, timeout=60)
        if result.returncode: raise RuntimeError('Synthetic public chart render failed')
        return [obj for obj in yaml.safe_load_all(result.stdout) if obj]

    def request(self):
        return {'repository': 'https://github.com/example/platform.git', 'branch': 'main', 'revision': 'c' * 40,
                'privateRepository': self.overlay['valuesRepository'], 'privateRevision': 'b' * 40, 'catalog': catalog([])}

    def native(self):
        project = copy.deepcopy(next(obj for obj in self.private if obj['kind'] == 'AppProject' and obj['metadata']['name'] == bootstrap.APP))
        external = copy.deepcopy(next(obj for obj in self.private if obj['kind'] == 'ExternalSecret' and obj['metadata']['name'] == bootstrap.APP + '-source'))
        for obj in (project, external):
            meta = obj['metadata']
            meta.update(uid=obj['kind'] + '-uid', resourceVersion='1', generation=1)
            meta.setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = 'cloudlab-public-root:' + (
                'argoproj.io/' if obj['kind'] == 'AppProject' else 'external-secrets.io/') + obj['kind'] + ':argocd/' + meta['name']
        external['status'] = {'conditions': [{'type': 'Ready', 'status': 'True', 'observedGeneration': 1}]}
        data = dict(external['spec']['target']['template']['data'], githubAppID='synthetic', githubAppInstallationID='synthetic', githubAppPrivateKey='synthetic')
        secret = {'metadata': {'uid': 'secret-uid', 'resourceVersion': '1', 'labels': {'argocd.argoproj.io/secret-type': 'repository'},
            'ownerReferences': [{'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'name': external['metadata']['name'],
                                 'uid': external['metadata']['uid'], 'controller': True}]},
            'type': 'Opaque', 'data': {key: base64.b64encode(value.encode()).decode() for key, value in data.items()}}
        return {'appproject.argoproj.io': project, 'externalsecret.external-secrets.io': external, 'secret': secret}

    def test_plain_enabled_render_is_public_only_and_accepted_overlay_adds_exact_private_source(self):
        for enabled in (False, True):
            objects = self.chart({'previews': {'enabled': enabled}, 'identity': {'enabled': True}})
            projects = [obj for obj in objects if obj['kind'] == 'AppProject' and obj['metadata']['name'] == bootstrap.APP]
            self.assertEqual(len(projects), int(enabled))
            self.assertFalse(any(obj['kind'] == 'ExternalSecret' and obj['metadata']['name'] == bootstrap.APP + '-source' for obj in objects))
            if enabled: self.assertEqual(projects[0]['spec']['sourceRepos'], [yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']])
            self.assertNotIn(self.overlay['valuesRepository'], json.dumps(objects))
        native = self.native()
        self.assertEqual(native['appproject.argoproj.io']['spec']['sourceRepos'], [self.request()['repository'], self.overlay['valuesRepository']])
        self.assertEqual(native['externalsecret.external-secrets.io']['spec']['target']['deletionPolicy'], 'Retain')
        self.assertEqual(native['externalsecret.external-secrets.io']['spec']['target']['template']['data']['project'], bootstrap.APP)
        with self.assertRaises(RuntimeError): self.chart({'previews': {'enabled': True}, 'identity': {'enabled': False}})

    def test_local_payload_checks_enabled_and_designated_coordinates_before_private_read(self):
        source = {'repository': self.request()['repository'], 'branch': 'main', 'revision': 'c' * 40}
        values = {'PRIVATE_CONFIG_REPOSITORY': self.overlay['valuesRepository'], 'PRIVATE_ACCESS_HOSTS': '["preview"]'}
        for public, environment in (({'previews': {'enabled': False}, 'identity': {'enabled': True}}, values),
                                    ({'previews': {'enabled': True}, 'identity': {'enabled': False}}, values),
                                    ({'previews': {'enabled': True}, 'identity': {'enabled': True}}, dict(values, PRIVATE_CONFIG_REPOSITORY=source['repository'])),
                                    ({'previews': {'enabled': True}, 'identity': {'enabled': True}}, dict(values, PRIVATE_CONFIG_REPOSITORY='https://github.com/foreign/private.git'))):
            with patch.object(payload.yaml, 'safe_load', return_value=public), patch.object(payload, 'committed_payload', return_value=source), \
                    patch.object(payload, 'dotenv_values', return_value=environment), patch.object(payload, 'read') as read:
                with self.assertRaises((ValueError, RuntimeError)): payload.payload()
                read.assert_not_called()
        with patch.object(payload, 'committed_payload', return_value=source), patch.object(payload, 'dotenv_values', return_value=values), \
                patch.object(payload, 'read', return_value=(catalog([]), 'b' * 40, values)) as read:
            self.assertEqual(payload.payload(), self.request())
            read.assert_called_once_with(values)

    def test_actual_accepted_native_context_allows_readonly_check_without_catalog_head_equality(self):
        native = self.native()
        with patch.object(bootstrap, 'accepted_identity_binding', return_value=self.overlay) as accepted, \
                patch.object(bootstrap, 'accepted_scoped_identity', return_value={'identity_ready': True}) as identity, \
                patch.object(bootstrap, 'get', side_effect=lambda kind, *args: native[kind]), \
                patch.object(bootstrap, 'kube', side_effect=AssertionError('mutation')):
            self.assertEqual(bootstrap.prerequisites(self.request()), {'prerequisites_ready': True})
        accepted.assert_called_once_with(repository=self.request()['repository'], branch='main', revision='c' * 40, private_repository=self.overlay['valuesRepository'])
        identity.assert_called_once_with(revision='c' * 40)

    def test_native_readiness_refusals_precede_controller_mutations(self):
        for change in ('binding', 'identity', 'binding-fallback', 'identity-fallback', 'project-public-only', 'project-wildcard', 'destination', 'kind', 'project-owner',
                       'source-missing', 'source-unready', 'source-stale', 'source-owner', 'source-retain', 'source-project', 'credential-owner', 'credential-project'):
            native = self.native()
            project, external, secret = (native[kind] for kind in ('appproject.argoproj.io', 'externalsecret.external-secrets.io', 'secret'))
            if change == 'project-public-only': project['spec']['sourceRepos'].pop()
            if change == 'project-wildcard': project['spec']['sourceRepos'].append('*')
            if change == 'destination': project['spec']['destinations'][0]['namespace'] = '*'
            if change == 'kind': project['spec']['namespaceResourceWhitelist'].append({'group': '', 'kind': 'Secret'})
            if change == 'project-owner': project['metadata']['annotations'] = {}
            if change == 'source-missing': native['externalsecret.external-secrets.io'] = None
            if change == 'source-unready': external['status']['conditions'][0]['status'] = 'False'
            if change == 'source-stale': external['metadata']['generation'] = 2
            if change == 'source-owner': external['metadata']['annotations'].pop('argocd.argoproj.io/tracking-id')
            if change == 'source-retain': external['spec']['target']['deletionPolicy'] = 'Delete'
            if change == 'source-project': external['spec']['target']['template']['data']['project'] = 'another'
            if change == 'credential-owner': secret['metadata']['ownerReferences'][0]['uid'] = 'replacement'
            if change == 'credential-project': secret['data']['project'] = base64.b64encode(b'another').decode()
            with self.subTest(change=change), patch.object(bootstrap, 'accepted_identity_binding', side_effect=RuntimeError('not accepted') if change == 'binding' else None,
                    return_value=None if change == 'binding-fallback' else self.overlay), patch.object(bootstrap, 'accepted_scoped_identity',
                    side_effect=RuntimeError('not ready') if change == 'identity' else None,
                    return_value=None if change == 'identity-fallback' else {'identity_ready': True}), \
                    patch.object(bootstrap, 'get', side_effect=lambda kind, *args: native[kind]), \
                    patch.object(bootstrap, 'kube', side_effect=AssertionError('controller mutation')), \
                    patch.object(bootstrap, 'native', side_effect=AssertionError('admission before prerequisite')):
                with self.assertRaises(RuntimeError): bootstrap.configure(self.request())

    def test_installed_check_import_closure_and_failure_before_discovery_task(self):
        tasks = []
        for task in yaml.safe_load((ROOT / 'ansible/playbooks/previews/tasks/bootstrap.yml').read_text()):
            if 'ansible.builtin.import_tasks' in task:
                tasks.extend(yaml.safe_load(Path(task['ansible.builtin.import_tasks']).read_text()))
            else: tasks.append(task)
        check_index = next(index for index, task in enumerate(tasks) if task.get('ansible.builtin.command', '').endswith('bootstrap.py check'))
        ensure_index = next(index for index, task in enumerate(tasks) if task.get('ansible.builtin.command', '').endswith('credentials ensure'))
        self.assertLess(check_index, ensure_index)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installed = root / 'installed'
            def rewrite(value):
                if isinstance(value, dict): return {key: rewrite(item) for key, item in value.items()}
                if isinstance(value, list): return [rewrite(item) for item in value]
                return value.replace('/opt/cloudlab', str(installed)) if isinstance(value, str) else value
            selected = [rewrite(task) for task in tasks[:check_index] if 'ansible.builtin.file' in task or 'ansible.builtin.copy' in task]
            probe = '''import sys,runpy
root=sys.argv[1]
sys.path.insert(0,root)
sys.argv=['bootstrap.py','check']
runpy.run_path(root+'/playbooks/previews/files/bootstrap.py',run_name='__main__')
'''
            selected.append({'name': 'Actual installed check mode', 'ansible.builtin.command': {'argv': [sys.executable, '-I', '-c', probe, str(installed)],
                             'stdin': json.dumps(self.request())}})
            sentinel = root / 'discovery-should-not-run'
            selected.append({'ansible.builtin.file': {'path': str(sentinel), 'state': 'touch'}})
            playbook = root / 'install.yml'
            playbook.write_text(yaml.safe_dump([{'hosts': 'all', 'gather_facts': False, 'tasks': selected}]))
            config = root / 'ansible.cfg'
            config.write_text('[defaults]\ninterpreter_python=auto_silent\n')
            environment = dict(os.environ, ANSIBLE_CONFIG=str(config))
            environment.pop('PYTHONPATH', None)
            result = subprocess.run(['ansible-playbook', '-i', 'localhost,', '-c', 'local', str(playbook)],
                cwd=root, env=environment, capture_output=True, text=True, timeout=120)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(sentinel.exists())
            self.assertIn('Preview bootstrap failed; resources and private diagnostics retained', result.stdout)
            self.assertNotIn('ModuleNotFoundError', result.stdout + result.stderr)
            result = subprocess.run([sys.executable, '-I', '-c',
                'import sys;sys.path.insert(0,sys.argv[1]);from playbooks.previews.files import bootstrap;'
                'from playbooks.argocd.files import source_transition;from playbooks.keycloak.files import maintenance;'
                'assert callable(source_transition.accepted_identity_binding);assert callable(maintenance.accepted_scoped_identity)', str(installed)],
                cwd=root, env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
