import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.keycloak.files import maintenance


class ScopedReadinessTests(unittest.TestCase):
    def test_read_only_scoped_identity_acceptance_and_ownership_health_refusals(self):
        for change in ('none', 'missing', 'phase', 'revision', 'uid', 'retirement', 'server-uid', 'deleting', 'bootstrap', 'maintenance',
                       'operation', 'unhealthy', 'server-unready', 'compared', 'recovery'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                receipt = {'phase': 'scoped', 'revision': 'b' * 40, 'uid': 'identity'}
                retired = {'phase': 'accepted', 'application_uid': 'identity', 'keycloak_uid': 'server'}
                app = {'metadata': {'uid': 'identity', 'labels': {'cloudlab.io/owner': maintenance.OWNER}},
                       'spec': {'project': maintenance.APP, 'source': {'path': 'platform/identity/keycloak',
                           'helm': {'valuesObject': {'enabled': True, 'reconciliationEnabled': True, 'bootstrapAdminEnabled': False}}}}}
                app['status'] = {'sync': {'comparedTo': {'source': copy.deepcopy(app['spec']['source'])}}}
                server = {'metadata': {'uid': 'server', 'generation': 1}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
                if change == 'phase': receipt['phase'] = 'primary'
                if change == 'revision': receipt['revision'] = 'a' * 40
                if change == 'uid': app['metadata']['uid'] = 'replacement'
                if change == 'retirement': retired['phase'] = 'prepared'
                if change == 'server-uid': server['metadata']['uid'] = 'replacement'
                if change == 'deleting': server['metadata']['deletionTimestamp'] = 'synthetic'
                if change in ('bootstrap', 'maintenance', 'operation'):
                    app['spec']['source']['helm']['valuesObject'][{'bootstrap': 'bootstrapAdminEnabled'}.get(change, change)] = True
                if change == 'server-unready': server['status']['conditions'][0]['status'] = 'False'
                if change == 'compared': app['status']['sync'].pop('comparedTo')
                if change == 'recovery': (base / 'startup-recovery.json').write_text(json.dumps({'phase': 'starting'}))
                if change != 'missing': (base / 'ownership.json').write_text(json.dumps(receipt))
                (base / 'retirement.json').write_text(json.dumps(retired))
                with patch.object(maintenance, 'BASE', base), patch.object(maintenance, 'get', side_effect=lambda kind, *args: server if kind.startswith('keycloak.') else app), \
                        patch.object(maintenance, 'application_ready', return_value=change != 'unhealthy'), \
                        patch.object(maintenance, 'kube', side_effect=AssertionError('mutation')), \
                        patch.object(maintenance, 'wait', side_effect=AssertionError('mutating wait')):
                    if change == 'none': self.assertEqual(maintenance.accepted_scoped_identity(revision='b' * 40), {'identity_ready': True})
                    else:
                        with self.assertRaises(RuntimeError): maintenance.accepted_scoped_identity(revision='b' * 40)
