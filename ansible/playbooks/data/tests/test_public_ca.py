import base64
import copy
import json
import unittest
from unittest.mock import patch
from playbooks.data.files import public_ca


class PublicCATests(unittest.TestCase):
    def test_projection_repairs_rotation_with_uid_precondition_and_preserves_foreign_objects(self):
        values = {'serviceRequests': [{'service': 'notes', 'namespace': 'cloudlab-app-notes', 'database': {}}]}
        ca = '-----BEGIN CERTIFICATE-----\npublic fixture'
        current = {'metadata': {'uid': 'same-uid', 'resourceVersion': '1', 'labels': {'cloudlab.io/owner': public_ca.OWNER}},
                   'data': {'ca.crt': ca}}
        cluster = {'metadata': {'uid': 'cluster-uid'}}
        secret = {'metadata': {'ownerReferences': [{'uid': 'cluster-uid'}]},
                  'data': {'ca.crt': base64.b64encode(ca.encode()).decode(), 'ca.key': 'never-project'}}
        namespace = {'metadata': {'labels': {'cloudlab.io/owner': 'service-platform'},
                    'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-services:/Namespace:/approved'}}}
        def get(kind, name=None, namespace_name=None):
            return {'cluster.postgresql.cnpg.io': cluster, 'secret': secret, 'namespace': namespace,
                    'configmap': current}[kind]
        with patch.object(public_ca, 'get', side_effect=get), patch.object(public_ca, 'kube') as kube:
            self.assertFalse(public_ca.reconcile(values)); kube.assert_not_called()
            current['data']['ca.crt'] = 'old public CA'
            self.assertTrue(public_ca.reconcile(values))
            args = kube.call_args.args
            document = json.loads(args[-1])
            self.assertIn({'op': 'test', 'path': '/metadata/uid', 'value': 'same-uid'}, document)
            self.assertIn({'op': 'test', 'path': '/metadata/resourceVersion', 'value': '1'}, document)
            self.assertNotIn('ca.key', args[-1]); self.assertNotIn('never-project', args[-1])
            namespace['metadata']['annotations'] = {}
            kube.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'ambiguous owner'): public_ca.reconcile(values)
            kube.assert_not_called()
            namespace['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': 'cloudlab-services:/Namespace:/approved'}
            current['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            kube.reset_mock()
            with self.assertRaisesRegex(RuntimeError, 'ambiguous owner'): public_ca.reconcile(values)
            kube.assert_not_called()
            current['metadata']['labels']['cloudlab.io/owner'] = public_ca.OWNER
            values['serviceRequests'][0]['namespace'] = 'argocd'
            with self.assertRaisesRegex(ValueError, 'approved service namespace'): public_ca.reconcile(values)
            kube.assert_not_called()

    def test_handoff_waits_for_successful_new_chart_sync_and_keeps_configmap_uid(self):
        values = {'serviceRequests': [{'service': 'notes', 'namespace': 'cloudlab-app-notes', 'database': {}}]}
        ca = '-----BEGIN CERTIFICATE-----\nfixture'
        current = {'metadata': {'uid': 'retained', 'resourceVersion': '1', 'annotations': {
            'argocd.argoproj.io/tracking-id': 'notes-notes:/ConfigMap:cloudlab-app-notes/database-ca'}},
            'data': {'ca.crt': ca}}
        app = {'spec': {'source': {'targetRevision': 'a' * 40, 'helm': {'valuesObject': {'definition': {}}}}}}
        def get(kind, name=None, namespace=None):
            return {'cluster.postgresql.cnpg.io': {'metadata': {'uid': 'cluster'}},
                    'secret': {'metadata': {'ownerReferences': [{'uid': 'cluster'}]},
                               'data': {'ca.crt': base64.b64encode(ca.encode()).decode()}},
                    'namespace': {'metadata': {'labels': {'cloudlab.io/owner': 'service-platform'},
                    'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-services:/Namespace:/approved'}}},
                    'configmap': current, 'application.argoproj.io': app}[kind]
        with patch.object(public_ca, 'get', side_effect=get), patch.object(public_ca, 'kube') as kube:
            self.assertFalse(public_ca.reconcile(values)); kube.assert_not_called()
            app['spec']['source']['helm']['valuesObject']['definition'] = {'name': 'notes'}
            app['status'] = {'sync': {'revision': 'a' * 40}, 'operationState': {
                'phase': 'Running', 'syncResult': {'revision': 'a' * 40}}}
            self.assertFalse(public_ca.reconcile(values)); kube.assert_not_called()
            app['status']['operationState']['phase'] = 'Succeeded'
            self.assertTrue(public_ca.reconcile(values))
            patch_document = json.loads(kube.call_args.args[-1])
            self.assertEqual(patch_document[0], {'op': 'test', 'path': '/metadata/uid', 'value': 'retained'})
            self.assertIn({'op': 'remove', 'path': '/metadata/annotations/argocd.argoproj.io~1tracking-id'}, patch_document)
            kube.reset_mock()
            current['metadata']['labels'] = {'cloudlab.io/owner': public_ca.OWNER}
            current['metadata']['annotations'] = {}
            self.assertFalse(public_ca.reconcile(values)); kube.assert_not_called()
