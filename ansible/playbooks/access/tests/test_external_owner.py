import copy
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.access.files import external
from playbooks.access.files.external import accepted


class ExternalOwnerTests(unittest.TestCase):
    def test_native_events_preserve_single_deployment_result_and_fail_closed(self):
        @contextmanager
        def transaction():
            yield Mock()

        for code in (0, 2):
            def native(arguments):
                self.assertEqual(arguments, ['verify', 'cloudflare'])
                print(json.dumps({'root': 'cloudflare', 'changes': code}))
                return code

            output, diagnostics = io.StringIO(), io.StringIO()
            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory, \
                    patch.object(external, 'Path', return_value=Path(directory)), \
                    patch.object(external, 'audit', return_value={'ready': True}), \
                    patch.object(external, 'ssh', return_value='ready'), \
                    patch.object(external, 'transaction', transaction), \
                    patch.object(external, 'accepted'), \
                    patch('playbooks.infrastructure.files.command.main', side_effect=native), \
                    patch.dict(os.environ, {'VM_HOST': 'fixture.invalid'}), \
                    redirect_stdout(output), redirect_stderr(diagnostics):
                if code:
                    with self.assertRaises(RuntimeError):
                        external.run()
                    self.assertEqual(output.getvalue(), '')
                else:
                    external.run()
                    self.assertEqual(json.loads(output.getvalue()), {
                        'changed': False, 'configured': True, 'infra_owner': 'cloudflare'})
            self.assertEqual(json.loads(diagnostics.getvalue())['changes'], code)

    def test_only_accepted_exact_scope_can_run_native_verification(self):
        objects = {'app:fixture.example.invalid': {'id': 'retained'}}
        state = {'binding': 'fixture', 'objects': objects, 'infra_owner': {
            'phase': 'accepted', 'binding': 'fixture', 'objects': copy.deepcopy(objects)}}
        accepted(state)
        for owner in (None, {}, False, dict(state['infra_owner'], phase='suspended'),
                      dict(state['infra_owner'], objects={}), dict(state['infra_owner'], binding='foreign'),
                      dict(state['infra_owner'], objects={'app:fixture.example.invalid': {'id': 'foreign'}})):
            with self.subTest(owner=owner), self.assertRaises(RuntimeError):
                accepted(dict(state, infra_owner=owner))
        with self.assertRaises(RuntimeError):
            accepted({'binding': 'legacy', 'objects': objects})
