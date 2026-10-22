import base64
import copy
import json
import unittest
from unittest.mock import patch
from playbooks.data.files import public_ca


class PublicCATests(unittest.TestCase):
    def test_complete_consumers_cover_existing_owned_and_new_databases_without_expanding_scope(self):
        values = {'serviceConsumers': ['cloudlab-app-notes', 'cloudlab-app-fixture'],
                  'serviceRequests': [{'service': 'fixture', 'namespace': 'cloudlab-app-fixture', 'database': {}},
                                      {'service': 'unapproved', 'namespace': 'cloudlab-app-unapproved', 'database': {}}]}
        ca = '-----BEGIN CERTIFICATE-----\npublic fixture'
        maps = {}
        observed = []
        def get(kind, name=None, namespace=None):
            if kind == 'cluster.postgresql.cnpg.io': return {'metadata': {'uid': 'cluster'}}
            if kind == 'secret': return {'metadata': {'ownerReferences': [{'uid': 'cluster'}]},
                                        'data': {'ca.crt': base64.b64encode(ca.encode()).decode()}}
            if kind == 'namespace':
                observed.append(name)
                return {'metadata': {'labels': {'cloudlab.io/owner': 'service-platform'},
                        'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-services:/Namespace:/approved'}}}
            return maps.get(namespace)
        def create(*args, document):
            self.assertEqual(args, ('create', '-f', '-'))
            self.assertEqual(document['data'], {'ca.crt': ca})
            document = copy.deepcopy(document)
            document['metadata'].update(uid='retained-' + document['metadata']['namespace'], resourceVersion='1')
            maps[document['metadata']['namespace']] = document
        with patch.object(public_ca, 'get', side_effect=get), patch.object(public_ca, 'kube', side_effect=create) as kube:
            self.assertTrue(public_ca.reconcile(values))
            self.assertEqual(set(maps), set(values['serviceConsumers']))
            self.assertEqual(observed, values['serviceConsumers'])
            self.assertEqual(kube.call_count, 2)
            kube.reset_mock()
            self.assertFalse(public_ca.reconcile(values))
            kube.assert_not_called()

    def test_projection_repairs_rotation_with_uid_precondition_and_preserves_foreign_objects(self):
        values = {'serviceConsumers': ['cloudlab-app-notes'], 'serviceRequests': []}
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
            values['serviceConsumers'] = ['argocd']
            with self.assertRaisesRegex(ValueError, 'approved service namespace'): public_ca.reconcile(values)
            kube.assert_not_called()

    def test_handoff_requires_current_rendered_chart_and_accepts_noop_revision(self):
        values = {'serviceConsumers': ['cloudlab-app-notes'], 'serviceRequests': []}
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
            app['status'] = {'sync': {'revision': 'a' * 40, 'status': 'Synced'},
                             'health': {'status': 'Healthy'}, 'operationState': {
                                 'phase': 'Succeeded', 'syncResult': {'revision': 'b' * 40}}}
            valid = copy.deepcopy(app)
            rejected = [
                ('stale revision', lambda: app['status']['sync'].update(revision='b' * 40)),
                ('wrong target', lambda: app['spec']['source'].update(targetRevision='c' * 40)),
                ('out of sync', lambda: app['status']['sync'].update(status='OutOfSync')),
                ('unhealthy', lambda: app['status']['health'].update(status='Progressing')),
                ('active operation', lambda: app.update(operation={'sync': {}})),
                ('running operation', lambda: app['status']['operationState'].update(phase='Running')),
                ('terminating operation', lambda: app['status']['operationState'].update(phase='Terminating')),
                ('old chart', lambda: app['spec']['source']['helm']['valuesObject'].pop('definition')),
            ]
            rejected += [(kind, lambda kind=kind: app['status'].update(conditions=[{'type': kind}]))
                         for kind in ('ComparisonError', 'SyncError', 'InvalidSpecError')]
            for name, alter in rejected:
                with self.subTest(name=name):
                    app.clear(); app.update(copy.deepcopy(valid)); alter()
                    self.assertFalse(public_ca.reconcile(values)); kube.assert_not_called()
            # Argo can render an unchanged chart at a new revision without a new
            # operation; its current Synced/Healthy revision is authoritative.
            app.clear(); app.update(valid)
            self.assertTrue(public_ca.reconcile(values))
            patch_document = json.loads(kube.call_args.args[-1])
            self.assertEqual(patch_document[0], {'op': 'test', 'path': '/metadata/uid', 'value': 'retained'})
            self.assertIn({'op': 'remove', 'path': '/metadata/annotations/argocd.argoproj.io~1tracking-id'}, patch_document)
            kube.reset_mock()
            current['metadata']['labels'] = {'cloudlab.io/owner': public_ca.OWNER}
            current['metadata']['annotations'] = {}
            self.assertFalse(public_ca.reconcile(values)); kube.assert_not_called()
