import unittest
from unittest.mock import Mock, patch

from playbooks.services.files import remote
from playbooks.services.tests.fixtures import definition, approval


class RetentionTests(unittest.TestCase):
    def test_removed_routes_accept_empty_response_and_reject_any_remaining_service_route(self):
        request = {'action': 'route-absent', 'definition': definition(), 'approval': approval()}
        for response in (None, {'items': []}):
            with self.subTest(response=response), patch.object(remote, 'get', return_value=response):
                remote.inspect(request)
        with patch.object(remote, 'get', return_value={'items': [{'metadata': {'name': 'synthetic'}}]}):
            with self.assertRaisesRegex(RuntimeError, 'still exposes'): remote.inspect(request)

    def test_retirement_never_deletes_pvc_secret_namespace_or_shared_resources(self):
        allowed = approval()
        app_name = allowed['name'] + '-synthetic'
        appset = {'metadata': {'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-services:ApplicationSet:argocd/synthetic'}},
                  'spec': {'generators': [{'list': {'elements': []}}]}}
        application = {'metadata': {}, 'spec': {'project': 'synthetic', 'destination': {
            'server': 'https://kubernetes.default.svc', 'namespace': allowed['namespace']}},
            'status': {'resources': [
                {'kind': kind, 'group': group, 'name': 'retained', 'namespace': allowed['namespace']}
                for group, kind in (('', 'PersistentVolumeClaim'), ('', 'Secret'), ('', 'Namespace'),
                                    ('', 'ResourceQuota'), ('', 'ConfigMap'))]}}
        own = {'metadata': {'annotations': {'argocd.argoproj.io/tracking-id': app_name + ':ConfigMap:owned'}}}
        def get(kind, name=None, namespace=None):
            if kind.startswith('applicationset.'): return appset
            if kind.startswith('application.'): return application
            return own
        with patch.object(remote, 'get', side_effect=get), patch.object(remote, 'kube') as kube:
            remote.inspect({'action': 'retire-workload', 'definition': definition(), 'approval': allowed})
            deleted = [(call.args[1], call.args[2]) for call in kube.call_args_list if call.args[0] == 'delete']
            self.assertEqual(deleted, [('ConfigMap', 'retained'), ('application.argoproj.io', app_name)])

    def test_conflicting_owner_blocks_all_resource_deletes(self):
        allowed = approval()
        appset = {'metadata': {'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-services:ApplicationSet:owned'}},
                  'spec': {'generators': [{'list': {'elements': []}}]}}
        application = {'metadata': {}, 'spec': {'project': 'synthetic', 'destination': {
            'server': 'https://kubernetes.default.svc', 'namespace': allowed['namespace']}},
            'status': {'resources': [{'kind': 'Deployment', 'group': 'apps', 'name': 'synthetic', 'namespace': allowed['namespace']}]}}
        def get(kind, name=None, namespace=None):
            return appset if kind.startswith('applicationset.') else application if kind.startswith('application.') else {'metadata': {}}
        with patch.object(remote, 'get', side_effect=get), patch.object(remote, 'kube') as kube:
            with self.assertRaises(RuntimeError): remote.inspect({'action':'retire-workload','definition':definition(),'approval':allowed})
            self.assertFalse(any(call.args[0] == 'delete' for call in kube.call_args_list))
