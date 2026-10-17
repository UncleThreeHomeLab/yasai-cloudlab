from types import SimpleNamespace
import unittest
from unittest.mock import patch

from playbooks.observability.files.verify import kiali_configuration_references


class KialiReferenceTests(unittest.TestCase):
    def resources(self, kind, name=None, namespace=None):
        if kind == 'httproutes.gateway.networking.k8s.io':
            return {'items': [self.route] if namespace == 'gateway' else []}
        return {'metadata': {'name': name}}

    def access(self, *args, **kwargs):
        permitted = args[3] != 'secrets'
        return SimpleNamespace(returncode=0 if permitted else 1, stdout='yes' if permitted else 'no')

    def setUp(self):
        self.route = {'metadata': {'name': 'argocd', 'namespace': 'gateway'}, 'spec': {
            'parentRefs': [{'name': 'cloudlab'}], 'rules': [{'backendRefs': [
                {'name': 'argocd-server', 'namespace': 'argocd', 'port': 443}]}]},
            'status': {'parents': [{'conditions': [{'type': 'ResolvedRefs', 'status': 'True'}]}]}}

    def test_controller_resolved_refs_do_not_hide_backend_outside_kiali_view(self):
        with patch('playbooks.observability.files.verify.kube', side_effect=self.access), \
             patch('playbooks.observability.files.verify.get', side_effect=self.resources):
            with self.assertRaisesRegex(RuntimeError, 'outside Kiali discovery'):
                kiali_configuration_references(['gateway'])
            kiali_configuration_references(['gateway', 'argocd'])

    def test_missing_gateway_service_or_read_permission_fails_verification(self):
        for missing in ('gateway.gateway.networking.k8s.io', 'service', 'permission'):
            with self.subTest(missing=missing):
                def resource(kind, name=None, namespace=None):
                    return None if kind == missing else self.resources(kind, name, namespace)
                access = SimpleNamespace(returncode=1, stdout='no') if missing == 'permission' else None
                with patch('playbooks.observability.files.verify.get', side_effect=resource), \
                     patch('playbooks.observability.files.verify.kube', side_effect=self.access if access is None else None,
                           return_value=access):
                    with self.assertRaises(RuntimeError):
                        kiali_configuration_references(['gateway', 'argocd'])

    def test_backend_visibility_must_not_expose_argo_secrets(self):
        with patch('playbooks.observability.files.verify.get', side_effect=self.resources), \
             patch('playbooks.observability.files.verify.kube', return_value=SimpleNamespace(returncode=0, stdout='yes')):
            with self.assertRaisesRegex(RuntimeError, 'Argo credentials'):
                kiali_configuration_references(['gateway', 'argocd'])
