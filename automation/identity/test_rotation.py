"""Rotation proof distinguishes authenticated invalid code from credential denial."""
import unittest
import json
import copy
from unittest.mock import patch

from automation.identity import rotation


class RotationProofTests(unittest.TestCase):
    def test_refresh_is_scoped_to_the_owned_eso_item_and_preserves_controller_defaults(self):
        from automation.identity.maintenance import OWNER, APP
        app = {'metadata': {'labels': {'cloudlab.io/owner': OWNER}},
               'spec': {'source': {'helm': {'valuesObject': {'privateStateEnabled': True}}}}}
        external = {'metadata': {'uid': 'owned', 'resourceVersion': '42',
                    'annotations': {'argocd.argoproj.io/tracking-id': APP + ':external-secret'}},
                    'spec': {'secretStoreRef': {'name': 'cloudlab', 'kind': 'ClusterSecretStore'},
                             'dataFrom': [{'extract': {'key': rotation.TITLE, 'conversionStrategy': 'Default'}}],
                             'target': {'name': rotation.TITLE}}}
        request = {'action': 'provision', 'realm': 'applications', 'client_id': 'disposable'}
        with patch('automation.mesh.kube.get', side_effect=[app, external]), patch('automation.mesh.kube.kube') as write:
            self.assertEqual(rotation.refresh(request), {'credential_delivery_requested': True, 'realm_changes': 0})
            patch_body = json.loads(write.call_args.args[-1])
            self.assertEqual(set(patch_body), {'metadata'})
            self.assertEqual(patch_body['metadata']['uid'], 'owned')
            self.assertEqual(patch_body['metadata']['resourceVersion'], '42')
        changed = copy.deepcopy(external); changed['spec']['dataFrom'][0]['extract']['key'] = 'unrelated-item'
        with patch('automation.mesh.kube.get', side_effect=[app, changed]), patch('automation.mesh.kube.kube') as write:
            with self.assertRaises(RuntimeError): rotation.refresh(request)
            write.assert_not_called()
    def test_probe_preserves_http_status_and_sends_credentials_only_in_request_body(self):
        request = {'realm': 'platform', 'client_id': 'disposable'}
        with patch.object(rotation, 'private_request', return_value=(401, {'error': 'unauthorized_client'})) as read:
            self.assertEqual(rotation.probe({'admin_host': 'admin.example.invalid', 'callback': 'https://app.example.invalid/callback'},
                                           request, 'private-fixture-secret'), (401, 'unauthorized_client'))
        self.assertTrue(read.call_args.kwargs['with_status'])
        self.assertNotIn('private-fixture-secret', read.call_args.args[0])

    def test_only_authenticated_new_code_and_http_401_old_denial_complete_rotation(self):
        payload = {'request': {'action': 'rotate', 'realm': 'platform', 'client_id': 'disposable'},
                   'old': 'o' * 48, 'new': 'n' * 48}
        cases = [((400, 'invalid_grant'), (401, 'invalid_client'), True),
                 ((400, 'invalid_grant'), (401, 'unauthorized_client'), True),
                 ((400, 'invalid_grant'), (400, 'unauthorized_client'), False),
                 ((400, 'invalid_grant'), (401, 'invalid_grant'), False),
                 ((401, 'invalid_grant'), (401, 'unauthorized_client'), False),
                 ((400, 'invalid_client'), (401, 'unauthorized_client'), False)]
        for new, old, accepted in cases:
            with self.subTest(new=new, old=old), patch.object(rotation, 'inventory', return_value={}), \
                    patch.object(rotation, 'probe', side_effect=[new, old]), \
                    patch('automation.mesh.kube.get', return_value={}), patch('automation.mesh.kube.condition', return_value=True), \
                    patch('automation.mesh.kube.kube'), patch.object(rotation.time, 'sleep', side_effect=RuntimeError('pending')):
                if accepted:
                    result = rotation.verify(payload)
                    self.assertTrue(result['credential_accepted']); self.assertTrue(result['old_credential_denied'])
                    self.assertEqual(result['sessions_created'], 0)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'pending'): rotation.verify(payload)


if __name__ == '__main__':
    unittest.main()
