import json
import subprocess
import unittest
from unittest.mock import patch

from fixtures import catalog
from playbooks.previews.files.admission import native, CONTROLLER


def object_for(kind, name):
    if kind == 'validatingadmissionpolicy':
        return {'metadata': {'generation': 1}, 'spec': {'failurePolicy': 'Fail',
                'variables': [{'name': 'authorization', 'expression': json.dumps(catalog()['ownership'])}]},
                'status': {'observedGeneration': 1, 'typeChecking': {'expressionWarnings': []}}}
    return {'spec': {'policyName': name, 'validationActions': ['Deny']}}


class AdmissionTests(unittest.TestCase):
    def test_bootstrap_obsolete_only_catalog_skips_positive_but_keeps_native_denials(self):
        import tempfile
        from pathlib import Path
        from playbooks.previews.files import bootstrap, contract
        settings = catalog()
        payload = {'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
                   'privateRepository': 'https://github.com/example/config.git', 'privateRevision': 'b' * 40,
                   'catalog': settings}
        with tempfile.TemporaryDirectory() as directory, patch.object(bootstrap, 'BASE', Path(directory)), \
                patch.object(contract, 'IMAGE', 'python:3.13-slim-bookworm@sha256:' + 'd' * 64), \
                patch.object(bootstrap, 'get', return_value=None), patch.object(bootstrap, 'wait'), \
                patch.object(bootstrap, 'kube'), patch.object(bootstrap, 'native') as native_check, \
                patch('playbooks.previews.files.resources.resources', side_effect=AssertionError('obsolete row creates no namespace')):
            self.assertTrue(bootstrap.configure(payload)['controller_enabled'])
        native_check.assert_called_once()
        self.assertIsNone(native_check.call_args.args[2])

    def test_rbac_failure_cannot_count_as_native_admission_proof(self):
        with patch('playbooks.previews.files.admission.subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'Forbidden by RBAC')):
            with self.assertRaises(RuntimeError): native(object_for, catalog())

    def test_all_mutation_probes_are_privileged_impersonated_server_dry_runs(self):
        calls = []
        def run(arguments, **kwargs):
            calls.append(arguments)
            obj = json.loads(kwargs['input']) if kwargs.get('input') else None
            suffix = 'namespaces' if obj is None or obj['kind'] == 'Namespace' else 'rolebindings' if obj['kind'] == 'RoleBinding' else 'objects'
            return subprocess.CompletedProcess(arguments, 1, '', 'Denied by ValidatingAdmissionPolicy cloudlab-preview-' + suffix)
        with patch('playbooks.previews.files.admission.subprocess.run', side_effect=run):
            result = native(object_for, catalog())
        self.assertEqual(result['native_policy_rejections'], 4)
        self.assertEqual(result['persistent_mutations'], 0)
        for arguments in calls:
            self.assertIn('--dry-run=server', arguments)
            self.assertIn('--as=' + CONTROLLER, arguments)
            self.assertIn('--as-group=system:masters', arguments)

    def test_compile_warning_stops_before_any_controller_privilege_probe(self):
        def get(kind, name):
            obj = object_for(kind, name)
            if kind == 'validatingadmissionpolicy':
                obj['status']['typeChecking']['expressionWarnings'] = [{'warning': 'unsupported field'}]
            return obj
        with patch('playbooks.previews.files.admission.subprocess.run') as run, self.assertRaises(RuntimeError):
            native(get, catalog())
        run.assert_not_called()

    def test_parameter_dependency_or_changed_authorization_stops_before_probes(self):
        for mode in ('paramKind', 'paramRef', 'authorization'):
            def get(kind, name):
                obj = object_for(kind, name)
                if mode == 'paramKind' and kind == 'validatingadmissionpolicy':
                    obj['spec']['paramKind'] = {'apiVersion': 'v1', 'kind': 'ConfigMap'}
                elif mode == 'paramRef' and kind == 'validatingadmissionpolicybinding':
                    obj['spec']['paramRef'] = {'name': 'unexpected'}
                elif mode == 'authorization' and kind == 'validatingadmissionpolicy':
                    obj['spec']['variables'][0]['expression'] = '{}'
                return obj
            with self.subTest(mode=mode), patch('playbooks.previews.files.admission.subprocess.run') as run, self.assertRaises(RuntimeError):
                native(get, catalog())
            run.assert_not_called()
