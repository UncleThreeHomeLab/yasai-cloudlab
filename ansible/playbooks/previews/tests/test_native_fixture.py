import copy
import ast
from contextlib import redirect_stderr
import io
import unittest
import json
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

from playbooks.previews.tests.native_admission import fixture, REMOTE
from playbooks.previews.tests import native_admission
from playbooks.previews.files.check import render, example


class NativeFixtureTests(unittest.TestCase):
    def test_namespace_guard_accepts_missing_subresource_and_retains_operation_limits(self):
        policy = next(obj for obj in render({'enabled': True, 'catalog': example()})
                      if obj['kind'] == 'ValidatingAdmissionPolicy' and obj['metadata']['name'] == 'cloudlab-preview-namespaces')
        expression = policy['spec']['validations'][0]['expression']
        self.assertIn("(!has(request.subResource) || request.subResource == '')", expression)
        self.assertIn("request.operation in ['CREATE', 'DELETE']", expression)

    def test_positive_probe_stderr_stays_in_private_remote_diagnostics(self):
        function = next(node for node in ast.parse(REMOTE).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'probe')
        scope = {'copy': copy, 'json': json, 'subprocess': subprocess, 'sys': sys, 'time': time,
                 'p': {'username': 'synthetic', 'nonce': 'a' * 32}, 'marker': 'cloudlab.io/admission-proof'}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<native-probe>', 'exec'), scope)
        private_error = 'synthetic API error: no such key: subResource\nsecond diagnostic line'
        stream = io.StringIO()
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', private_error)), \
                redirect_stderr(stream), self.assertRaisesRegex(RuntimeError, '^Native fixture positive admission failed$'):
            scope['probe']({'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'synthetic'}})
        self.assertEqual(stream.getvalue(), private_error + '\n')

    def test_empty_map_readiness_waits_only_for_successful_dry_runs_and_stays_bounded(self):
        function = next(node for node in ast.parse(REMOTE).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'probe')
        for mode in ('propagating', 'timeout', 'unrelated_error'):
            with self.subTest(mode=mode):
                clock = [0]
                accepted = subprocess.CompletedProcess([], 0, '', '')
                denied = subprocess.CompletedProcess([], 1, '', 'Denied by ValidatingAdmissionPolicy proof-objects')
                unrelated = subprocess.CompletedProcess([], 1, '', 'Forbidden by RBAC')
                responses = [accepted, accepted, denied] if mode == 'propagating' else [unrelated] if mode == 'unrelated_error' else [accepted] * 4
                run = unittest.mock.Mock(side_effect=responses)
                scope = {'copy': copy, 'json': json, 'sys': sys, 'prefix': 'proof',
                         'subprocess': SimpleNamespace(run=run),
                         'time': SimpleNamespace(monotonic=lambda: clock[0], sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds)),
                         'p': {'username': 'synthetic', 'nonce': 'a' * 32}, 'marker': 'cloudlab.io/admission-proof'}
                exec(compile(ast.Module(body=[function], type_ignores=[]), '<native-probe>', 'exec'), scope)
                obj = {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'synthetic'}}
                with redirect_stderr(io.StringIO()):
                    if mode == 'propagating':
                        self.assertEqual(scope['probe'](obj, denied='objects', denial_timeout=3),
                                         {'attempts': 3, 'elapsed_seconds': 2})
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'named admission denial'):
                            scope['probe'](obj, denied='objects', denial_timeout=3)
                self.assertEqual(run.call_count, 3 if mode == 'propagating' else 1 if mode == 'unrelated_error' else 4)
                self.assertLessEqual(clock[0], 3)

    def test_fixture_retains_exact_production_expressions_under_isolated_identity(self):
        value = fixture('e' * 32)
        settings = example()
        settings['ownership'] = value['authorization']
        original = {obj['metadata']['name']: obj for obj in render({'enabled': True, 'catalog': settings,
                    'platformRepository': 'https://github.com/example/platform.git'})
                    if obj['kind'] == 'ValidatingAdmissionPolicy'}
        for obj in value['objects']:
            if obj['kind'] != 'ValidatingAdmissionPolicy': continue
            expected_name = obj['metadata']['name'].replace(value['control'], 'cloudlab-preview', 1)
            actual = copy.deepcopy(obj['spec'])
            self.assertEqual(actual['matchConstraints'].pop('objectSelector'),
                             {'matchLabels': {'cloudlab.io/admission-proof': 'e' * 32}})
            for condition in actual['matchConditions']:
                condition['expression'] = condition['expression'].replace(value['username'], 'system:serviceaccount:argocd:cloudlab-previews')
            self.assertEqual(actual, original[expected_name]['spec'])
        self.assertEqual({obj['kind'] for obj in value['objects']},
                         {'ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding'})
        self.assertTrue(all(obj['metadata']['name'].startswith(value['control']) or obj['metadata'].get('namespace') == value['control']
                            for obj in value['objects']))
        compile(REMOTE, '<native-preview-fixture>', 'exec')
        self.assertEqual(len(value['authorization']), 256)
        for obj in value['objects']:
            if obj['kind'] == 'ValidatingAdmissionPolicyBinding':
                self.assertNotIn('paramRef', obj['spec'])
                self.assertEqual(obj['spec']['matchResources']['objectSelector'],
                                 {'matchLabels': {'cloudlab.io/admission-proof': 'e' * 32}})

    def test_retained_cleanup_requires_exact_fixture_name_uid_and_marker(self):
        marker, uid = 'd' * 32, '855a4813-0734-4d87-ac86-016bd3a644f5'
        name = 'cloudlab-preview-proof-' + marker[:16]
        values = {'VM_HOST': 'synthetic', 'VM_USER': 'synthetic', 'VM_PASSWORD': 'synthetic'}
        with patch.object(native_admission, 'dotenv_values', return_value=values), \
                patch('playbooks.access.files.preflight.ssh', return_value='{"owned_fixture_cleanup": true}') as ssh:
            self.assertTrue(native_admission.run(name, uid, marker)['owned_fixture_cleanup'])
            payload = json.loads(ssh.call_args.kwargs['input'])
            self.assertEqual((payload['cleanupNamespace'], payload['cleanupUID'], payload['nonce']), (name, uid, marker))
            ssh.reset_mock()
            with self.assertRaises(ValueError): native_admission.run('argocd', uid, marker)
            ssh.assert_not_called()

    def test_empty_authorization_has_no_parameter_dependency(self):
        settings = example()
        settings.update(approvals=[], ownership={})
        objects = render({'enabled': True, 'catalog': settings})
        self.assertFalse(any(obj['kind'] == 'ConfigMap' and obj['metadata']['name'] == 'cloudlab-preview-authorization'
                             for obj in objects))
        for obj in objects:
            if obj['kind'] == 'ValidatingAdmissionPolicy':
                self.assertNotIn('paramKind', obj['spec'])
                variable = next(row for row in obj['spec']['variables'] if row['name'] == 'authorization')
                self.assertEqual(json.loads(variable['expression']), {})
                self.assertEqual(obj['spec']['failurePolicy'], 'Fail')
            if obj['kind'] == 'ValidatingAdmissionPolicyBinding':
                self.assertNotIn('paramRef', obj['spec'])
                self.assertEqual(obj['spec']['validationActions'], ['Deny'])
