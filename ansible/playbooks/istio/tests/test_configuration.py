"""Existing Gateway API ownership and namespace trust boundaries are mandatory."""
import unittest
from unittest.mock import patch
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import copy

from kube import contains
from playbooks.istio.files import verify


class ConfigurationTests(unittest.TestCase):
    def test_deployed_verifier_imports_without_the_retired_writer_or_test_fixtures(self):
        root = Path(__file__).resolve().parents[4]
        with tempfile.TemporaryDirectory() as folder:
            for name in ('verify.py', 'kube.py', 'fixtures.py'):
                shutil.copyfile(root / 'ansible/playbooks/istio/files' / name, Path(folder) / name)
            shutil.copyfile(root / 'ansible/playbooks/argocd/files/source_revision.py', Path(folder) / 'source_revision.py')
            result = subprocess.run([sys.executable, '-I', '-S', '-c',
                'import sys;sys.path.insert(0,sys.argv[1]);import verify;'
                'assert callable(verify.gateway_api);assert callable(verify.fixtures.namespace)', folder],
                capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_live_gateway_inventory_accepts_only_reviewed_https_listeners(self):
        gateways = {}
        for exposure in ('public', 'private'):
            hosts = {'https': '*.example.invalid'}
            gateways[exposure] = {'spec': {'listeners': [
                {'name': name, 'hostname': host, 'protocol': 'HTTPS', 'port': 443,
                 'tls': {'mode': 'Terminate', 'certificateRefs': [
                     {'group': '', 'kind': 'Secret', 'name': 'cloudlab-gateway-tls'}]},
                 'allowedRoutes': {'namespaces': {'from': 'Selector', 'selector': {
                     'matchExpressions': [{'key': 'cloudlab.io/gateway', 'operator': 'In',
                                           'values': [exposure, 'mixed']}] }},
                     'kinds': [{'group': 'gateway.networking.k8s.io', 'kind': 'HTTPRoute'}]}}
                for name, host in hosts.items()]}}
        def get(kind, name, namespace):
            exposure = namespace.removeprefix('cloudlab-gateway-')
            if kind.startswith('gateway.'):
                return gateways[exposure]
            if kind == 'service':
                return {'spec': {'type': 'ClusterIP', 'ports': [{'port': 443}]}}
            return {'spec': {'replicas': 2, 'template': {'spec': {'serviceAccountName': 'gateway'}}},
                    'status': {'availableReplicas': 2}}
        with patch.object(verify, 'get', side_effect=get), patch.object(verify, 'condition', return_value=True):
            verify.check_gateways('example.invalid')
            for field, value in (('hostname', '*.internal.example.invalid'), ('name', 'foreign'),
                                 ('port', 80), ('protocol', 'HTTP'),
                                 ('tls', {'mode': 'Passthrough'}),
                                 ('allowedRoutes', {'namespaces': {'from': 'All'}})):
                original = copy.deepcopy(gateways['private'])
                gateways['private']['spec']['listeners'][0][field] = value
                with self.subTest(field=field), self.assertRaises(RuntimeError):
                    verify.check_gateways('example.invalid')
                gateways['private'] = original
            for exposure in ('public', 'private'):
                duplicate = copy.deepcopy(gateways[exposure]['spec']['listeners'][0])
                duplicate.update(name='identity-account', hostname='login.example.invalid')
                gateways[exposure]['spec']['listeners'].append(duplicate)
                with self.subTest(exposure=exposure), self.assertRaises(RuntimeError):
                    verify.check_gateways('example.invalid')
                gateways[exposure]['spec']['listeners'].pop()


    def test_crd_ownership_requires_argo_ssa_not_a_copied_tracking_annotation(self):
        obj = {'kind': 'CustomResourceDefinition'}
        actual = {'metadata': {'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-istio-base:copied'}}}
        self.assertFalse(verify.argo_owned(obj, actual, 'cloudlab-istio-base'))
        actual['metadata']['managedFields'] = [{'manager': 'argocd-controller', 'operation': 'Apply', 'fieldsV1': {'f:spec': {}}}]
        self.assertTrue(verify.argo_owned(obj, actual, 'cloudlab-istio-base'))
        actual['metadata']['managedFields'][0]['manager'] = 'foreign'
        self.assertFalse(verify.argo_owned(obj, actual, 'cloudlab-istio-base'))

    def test_api_spec_and_owner_changes_fail_before_writes(self):
        desired = {'metadata': {'name': 'gateways.gateway.networking.k8s.io'}, 'spec': {'group': 'gateway.networking.k8s.io'}}
        actual = {'metadata': {'uid': 'retained', 'annotations': {
            'meta.helm.sh/release-name': 'traefik-crd', 'gateway.networking.k8s.io/bundle-version': 'v1.6.1'}}, 'spec': desired['spec']}
        with patch.object(verify, 'get', return_value=actual):
            self.assertEqual(list(verify.gateway_api([desired]).values()), ['retained'])
            actual['metadata']['annotations']['meta.helm.sh/release-name'] = 'competing'
            with self.assertRaisesRegex(RuntimeError, 'owner changed'):
                verify.gateway_api([desired])
            actual['metadata']['annotations'].pop('meta.helm.sh/release-name')
            actual['metadata']['annotations']['cloudlab.io/owner'] = 'cloudlab-gateway-api'
            self.assertEqual(list(verify.gateway_api([desired]).values()), ['retained'])

    def test_recursive_contract_allows_defaults_but_not_missing_versions(self):
        self.assertTrue(contains({'versions': [{'name': 'v1', 'served': True}]}, {'versions': [{'name': 'v1'}]}))
        self.assertFalse(contains({'versions': [{'name': 'v1'}]}, {'versions': [{'name': 'v1'}, {'name': 'v1beta1'}]}))


    def test_tls_success_requires_trust_success_http_and_backend(self):
        from types import SimpleNamespace
        for code, body in [(1, 'HTTP/1.1 200 OK\r\nmesh-ok'), (0, 'HTTP/1.1 404 Not Found'), (0, 'HTTP/1.1 200 OK\r\nother')]:
            self.assertFalse(verify.successful_tls(SimpleNamespace(returncode=code, stdout=body)))
        self.assertTrue(verify.successful_tls(SimpleNamespace(returncode=0, stdout='HTTP/1.1 200 OK\r\nmesh-ok')))

    def test_unready_fixture_cannot_count_as_network_denial(self):
        with patch.object(verify, 'get', return_value={'metadata': {}, 'status': {}}), patch.object(verify, 'execute') as execute:
            with self.assertRaisesRegex(RuntimeError, 'not ready'):
                verify.http('fixture', 'client', 'backend')
            execute.assert_not_called()



if __name__ == '__main__':
    unittest.main()
