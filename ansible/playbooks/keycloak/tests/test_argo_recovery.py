import copy
import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.keycloak.files.integrations import argo as contract_for

runtime = importlib.import_module('playbooks.keycloak.files.argo')


class ArgoRecoveryTests(unittest.TestCase):
    def test_current_projection_and_pending_target_are_required_before_binding(self):
        contract = contract_for('https://login.example.invalid/realms/platform', 'https://console.example.invalid',
                                ['https://cd.internal.example.invalid'])
        original = {'revision': 'c' * 40, 'values': {'loginHost': 'login.example.invalid'}, 'argo': {
            'target': {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'a' * 40},
            'configuration': contract['helm'], 'client': contract['client'], 'recovery': True,
            'currentSecurityProjection': {'revision': 'b' * 40, 'configuration': copy.deepcopy(contract['helm']), 'client': copy.deepcopy(contract['client'])}}}
        source = {'realms': {'platform': {'clients': [contract['client']]}}}
        for change in ('valid', 'missing', 'mutable', 'changed', 'pending'):
            payload = copy.deepcopy(original)
            if change == 'missing': payload['argo'].pop('currentSecurityProjection')
            if change == 'mutable': payload['argo']['currentSecurityProjection']['revision'] = 'main'
            if change == 'changed': payload['argo']['currentSecurityProjection']['client']['callbacks'] = ['https://foreign.invalid']
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                (base / 'ownership.json').write_text(json.dumps({'phase': 'scoped', 'uid': 'owned'}))
                current = {'metadata': {'uid': 'owned', 'labels': {'cloudlab.io/owner': runtime.OWNER}}, 'spec': {'source': {'repoURL': 'public'}}}
                with patch.object(runtime, 'BASE', base), patch.object(runtime, 'prerequisites'), \
                        patch.object(runtime, 'get', return_value=current), patch.object(runtime, 'application_ready', return_value=True), \
                        patch.object(runtime, 'private_inputs', return_value=(source, {'realms': {}}, 'a' * 40)), \
                        patch.object(runtime, 'pending_identity_target', return_value='a' * 40) as pending, \
                        patch.object(runtime, 'pending_identity_checkpoint', return_value={'root_uid': 'owned', 'patchedSource': {'repoURL': 'public'}}), \
                        patch.object(runtime, 'check'), patch.object(runtime, 'proxy_privacy'), \
                        patch.object(runtime, 'public_address'), \
                        patch.object(runtime, 'private_request', return_value={'error': 'invalid_grant'}), \
                        patch.object(runtime, 'bind_identity', return_value={'changed': False}) as bind:
                    if change == 'pending': pending.side_effect = RuntimeError('No exact pending checkpoint')
                    if change == 'valid':
                        runtime.run(payload)
                        bind.assert_called_once_with(payload, payload['argo']['target'])
                    else:
                        with self.assertRaises(RuntimeError): runtime.run(payload)
                        bind.assert_not_called()
                        if change != 'pending': pending.assert_not_called()
