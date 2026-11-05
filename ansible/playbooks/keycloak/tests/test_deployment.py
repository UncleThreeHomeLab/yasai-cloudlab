"""Declared host assets preserve identity operations without workstation imports."""
import os
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from jinja2 import Template
import yaml

ROOT = Path(__file__).resolve().parents[4]
OWNER = ROOT / 'ansible/playbooks/keycloak'


class DeploymentTests(unittest.TestCase):
    def test_root_self_forwarding_releases_stale_identity_flag_and_preserves_binding_and_data_flags(self):
        root = ROOT / 'gitops/roots/public'
        binding = {'valuesRepository': 'https://github.com/UncleThreeHomeLab/private-fixture.git', 'valuesRevision': 'a' * 40}
        flags = {'maintenance': False, 'hibernated': False}
        stale = {'identity': {'enabled': True, 'application': {'enabled': False}, 'argo': binding},
            'data': {'configuration': flags}}
        def render(overrides):
            result = subprocess.run(['helm', 'template', 'cloudlab-public-root', str(root), '-f', '-'],
                input=json.dumps(overrides), capture_output=True, text=True, timeout=30, check=True)
            objects = [obj for obj in yaml.safe_load_all(result.stdout) if obj]
            owner = next(obj for obj in objects if obj['kind'] == 'Application' and obj['metadata']['name'] == 'cloudlab-public-root')
            return objects, owner['spec']['source']['helm']['valuesObject']
        first, forwarded = render(stale)
        self.assertFalse(any(obj['kind'] == 'ApplicationSet' and obj['metadata']['name'] == 'cloudlab-identity' for obj in first))
        self.assertEqual(forwarded['identity'], {'enabled': True, 'argo': binding})
        self.assertEqual(forwarded['data']['configuration'], flags)
        second, stable = render(forwarded)
        parent = next(obj for obj in second if obj['kind'] == 'ApplicationSet' and obj['metadata']['name'] == 'cloudlab-identity')
        self.assertEqual(stable, forwarded)
        self.assertEqual(parent['spec']['generators'][0]['merge']['generators'][1]['git']['revision'], binding['valuesRevision'])
        self.assertEqual(parent['spec']['template']['spec']['source']['targetRevision'], '526891f62eb9b9a50a0ffaf6ef020269d09e7746')

    def test_native_installation_render_and_typed_private_patch_refuse_other_pins(self):
        from playbooks.keycloak.files import ownership
        root = ROOT / 'gitops/roots/public'
        public = yaml.safe_load((root / 'values.yaml').read_text())
        def render(values):
            result = subprocess.run(['helm', 'template', 'cloudlab-public-root', str(root), '-f', '-'],
                input=json.dumps(values), capture_output=True, text=True, timeout=30, check=True)
            return [obj for obj in yaml.safe_load_all(result.stdout) if obj]
        self.assertFalse(any(obj['kind'] == 'ApplicationSet' and obj['metadata']['name'] == 'cloudlab-identity' for obj in render(public)))
        public['identity']['application']['enabled'] = True
        self.assertFalse(any(obj['kind'] == 'ApplicationSet' and obj['metadata']['name'] == 'cloudlab-identity' for obj in render(public)))
        public['identity']['argo'] = {'valuesRepository': 'https://github.com/UncleThreeHomeLab/private-fixture.git', 'valuesRevision': 'a' * 40}
        parent = next(obj for obj in render(public) if obj['kind'] == 'ApplicationSet' and obj['metadata']['name'] == 'cloudlab-identity')['spec']
        self.assertEqual(parent['template']['spec']['source']['targetRevision'], ownership.INSTALLATION_REVISION)
        self.assertNotIn('sources', parent['template']['spec'])
        self.assertEqual(parent['ignoreApplicationDifferences'], [{'jsonPointers': ['/spec/source/helm/valuesObject/' + field for field in ownership.OPERATION_FIELDS]}])
        generators = parent['generators'][0]['merge']['generators']
        self.assertEqual(generators[0]['list']['elements'], [{'installationRevision': ownership.INSTALLATION_REVISION}])
        self.assertEqual(generators[1]['git']['revision'], 'a' * 40)
        self.assertEqual(generators[1]['git']['files'], [{'path': 'identity/keycloak-values.yaml'}])
        self.assertEqual(parent['syncPolicy'], {'applicationsSync': 'create-update', 'preserveResourcesOnDeletion': True})
        invalid_binding = copy.deepcopy(public); invalid_binding['identity']['argo']['valuesRevision'] = 'main'
        with self.assertRaises(subprocess.CalledProcessError): render(invalid_binding)
        document = {'installationRevision': ownership.INSTALLATION_REVISION, 'loginHost': 'login.example.invalid',
            'adminHost': 'identity-admin.internal.example.invalid', 'database': 'keycloak', 'databaseRole': 'keycloak',
            'databaseHost': 'cloudlab-postgres-rw.cloudlab-data.svc.cluster.local', 'databasePort': 5432,
            'databaseCA': 'synthetic-ca', 'trustedProxyAddresses': ['10.42.0.0/24'], 'retiredEmergencyItem': 'keycloak-emergency-' + 'a' * 32}
        with tempfile.TemporaryDirectory() as directory:
            chart = Path(directory); (chart / 'templates').mkdir()
            (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: identity-patch-proof\nversion: 1.0.0\n')
            (chart / 'templates/patch.yaml').write_text('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: proof}\ndata:\n  patch: {{ tpl .Values.policy .Values.input | quote }}\n')
            for case in ('valid', 'missing-file', 'pin', 'metadata', 'cidr', 'port', 'reserved-database'):
                candidate = copy.deepcopy(document)
                if case == 'missing-file': candidate = generators[0]['list']['elements'][0]
                if case == 'pin': candidate['installationRevision'] = 'b' * 40
                if case == 'metadata': candidate['metadata'] = {'name': 'foreign'}
                if case == 'cidr': candidate['trustedProxyAddresses'] = ['10.42.0.1/24']
                if case == 'port': candidate['databasePort'] = '5432'
                if case == 'reserved-database': candidate['databaseRole'] = 'postgres'
                candidate['path'] = {'path': 'identity', 'filename': 'keycloak-values.yaml', 'segments': ['identity']}
                result = subprocess.run(['helm', 'template', 'proof', str(chart), '-f', '-'],
                    input=json.dumps({'policy': parent['templatePatch'], 'input': candidate}), capture_output=True, text=True, timeout=30)
                if case == 'valid':
                    self.assertEqual(result.returncode, 0, result.stderr)
                    values = yaml.safe_load(yaml.safe_load(result.stdout)['data']['patch'])['spec']['source']['helm']['valuesObject']
                    self.assertIs(type(values['databasePort']), int); self.assertIs(type(values['trustedProxyAddresses']), list)
                    self.assertEqual(values, {key: value for key, value in document.items() if key != 'installationRevision'})
                    ownership.installation_values(document)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Identity installation input refused', result.stderr)

    def test_installed_runtime_imports_without_checkout_or_pythonpath(self):
        tasks = []
        for path in (ROOT / 'ansible/playbooks/data/tasks/runtime.yml',
                     OWNER / 'tasks/runtime.yml', OWNER / 'tasks/converge.yml'):
            tasks.extend(yaml.safe_load(path.read_text()))
        tasks = [nested for task in tasks for nested in (
            yaml.safe_load((ROOT / Path(task['ansible.builtin.import_tasks']).relative_to('/workspace')).read_text())
            if 'ansible.builtin.import_tasks' in task else [task])]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            for task in tasks:
                copy = task.get('ansible.builtin.copy', {})
                if not copy.get('dest', '').startswith('/opt/cloudlab/'):
                    continue
                for item in task.get('loop', [None]):
                    source = Template(copy['src']).render(item=item)
                    if not source.startswith('/workspace/'):
                        continue
                    target = base / Path(Template(copy['dest']).render(item=item)).relative_to('/opt/cloudlab')
                    target.parent.mkdir(parents=True, exist_ok=True)
                    source = ROOT / Path(source).relative_to('/workspace')
                    if source.is_dir():
                        shutil.copytree(source, target, dirs_exist_ok=True)
                    else:
                        shutil.copyfile(source, target)
            environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
            result = subprocess.run([sys.executable, '-I', '-c',
                'import sys, runpy, pathlib; '
                'runpy.run_path(str(pathlib.Path(sys.argv[1]) / "playbooks/keycloak/files/bootstrap.py")); '
                'from playbooks.keycloak.files import bootstrap, ownership, maintenance, recovery, '
                'rotation, lifecycle, argo, verify, emergency, session_fixture, owner_enrollment, isolated_restore; '
                'from playbooks.data.files import capture, restore; '
                'from playbooks.access.files import native as access_native; '
                'assert callable(access_native.prerequisite); '
                'assert "playbooks.access.files.initial_bootstrap" not in sys.modules; '
                'assert bootstrap.ROOT == __import__("pathlib").Path(sys.argv[1]); '
                'assert isolated_restore.CONFIGURATION_SOURCE.read_bytes() == '
                '(__import__("pathlib").Path(sys.argv[1]) / "playbooks/keycloak/files/configuration.py").read_bytes(); '
                'assert callable(recovery.verify_restored); assert callable(bootstrap.run)', str(base)],
                cwd=base, env=environment, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_setup_only_imports_retained_identity_after_data(self):
        plays = yaml.safe_load((ROOT / 'ansible/playbooks/setup.yml').read_text())
        imports = [play['ansible.builtin.import_playbook'] for play in plays]
        self.assertLess(imports.index('data/020-reconcile.yml'), imports.index('keycloak/050-retained.yml'))
        self.assertLess(imports.index('keycloak/050-retained.yml'), imports.index('services/010-bootstrap.yml'))
        self.assertEqual([path for path in imports if path.startswith('keycloak/')],
                         ['keycloak/050-retained.yml', 'keycloak/060-retire-runtime.yml'])
        retained = yaml.safe_load((OWNER / '050-retained.yml').read_text())[0]
        self.assertEqual(retained['vars']['keycloak_phase'], 'retained')

    def test_named_client_operations_reject_different_actions_before_execution(self):
        for filename, action in (('provision-client.yml', 'provision-client'),
                                 ('retire-client.yml', 'retire-client'), ('rotate-client.yml', 'rotate')):
            play = yaml.safe_load((OWNER / filename).read_text())[0]
            self.assertIn(action, play['tasks'][0]['ansible.builtin.assert']['that'])
            self.assertTrue(play['tasks'][0]['no_log'])
            self.assertTrue(play['tasks'][1]['no_log'])


if __name__ == '__main__':
    unittest.main()
