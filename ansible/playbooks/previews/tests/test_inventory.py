import ast
import copy
import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.previews.files.kube import Kubernetes
from playbooks.previews.files.lifecycle import namespace_disposable
from playbooks.previews.tests.native_admission import REMOTE


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.namespace = 'cloudlab-preview-' + 'a' * 32
        self.group = 'gateway.networking.k8s.io'
        self.root = '/apis/' + self.group
        route = {'name': 'httproutes', 'kind': 'HTTPRoute', 'namespaced': True, 'verbs': ['list']}
        reference = {'name': 'referencegrants', 'kind': 'ReferenceGrant', 'namespaced': True, 'verbs': ['list']}
        self.foreign = {'apiVersion': self.group + '/v1beta1', 'kind': 'ReferenceGrant',
                        'metadata': {'name': 'foreign', 'uid': 'foreign-uid'}}
        self.responses = {
            '/api/v1': {'resources': []},
            '/apis': {'groups': [{'preferredVersion': {'groupVersion': self.group + '/v1'},
                                  'versions': [{'groupVersion': self.group + '/v1'},
                                               {'groupVersion': self.group + '/v1beta1'}]}]},
            self.root + '/v1': {'resources': [route]},
            self.root + '/v1beta1': {'resources': [route, reference]},
            self.root + '/v1/namespaces/' + self.namespace + '/httproutes': {'items': []},
            self.root + '/v1beta1/namespaces/' + self.namespace + '/referencegrants': {'items': [self.foreign]},
        }

    def run_inventory(self, native, failure=None):
        def read(route):
            if route == failure:
                raise RuntimeError('API unavailable')
            return copy.deepcopy(self.responses[route])
        if not native:
            kube = object.__new__(Kubernetes)
            with patch.object(kube, 'request', side_effect=lambda method, route: read(route)) as request:
                objects = kube.namespace_inventory(self.namespace)
            with self.assertRaisesRegex(ValueError, 'Foreign|Unknown|Unowned|ownership|owner'):
                namespace_disposable(objects, [], 'namespace-uid')
            return [call.args[1] for call in request.call_args_list]
        function = next(node for node in ast.parse(REMOTE).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'inventory')
        request = Mock(side_effect=lambda verb, route: json.dumps(read(route.removeprefix('--raw='))))
        scope = {'json': json, 'kube': request, 'created': [], 'p': {'generatedConfigMaps': []}}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<native-inventory>', 'exec'), scope)
        if failure:
            scope['inventory'](self.namespace)
        with self.assertRaisesRegex(RuntimeError, 'Foreign resource'):
            scope['inventory'](self.namespace)
        return [call.args[1].removeprefix('--raw=') for call in request.call_args_list]

    def test_nonpreferred_version_foreign_resource_blocks_both_cleanup_paths(self):
        for native in (False, True):
            with self.subTest(native=native):
                calls = self.run_inventory(native)
                self.assertIn(self.root + '/v1beta1', calls)
                self.assertIn(self.root + '/v1beta1/namespaces/' + self.namespace + '/referencegrants', calls)
                self.assertEqual(sum(route.endswith('/httproutes') for route in calls), 1)

    def test_actual_request_boundary_accepts_only_exact_discovery_root(self):
        kube = object.__new__(Kubernetes)
        kube.context = None
        def response(request, **kwargs):
            self.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-account-token')
            route = request.full_url.removeprefix('https://kubernetes.default.svc')
            return io.BytesIO(json.dumps(self.responses[route]).encode())
        opener = Mock()
        opener.open.side_effect = response
        with tempfile.TemporaryDirectory() as directory:
            kube.account = Path(directory)
            kube.account.joinpath('token').write_text('synthetic-account-token')
            with patch('playbooks.previews.files.kube.urllib.request.build_opener', return_value=opener):
                objects = kube.namespace_inventory(self.namespace)
                self.assertIn(self.foreign, objects)
                self.assertIn('https://kubernetes.default.svc/apis', [call.args[0].full_url for call in opener.open.call_args_list])
                opener.reset_mock()
                for route in ('/api', '/apis-other', '/apis?limit=1', '/apis/../secrets',
                              'https://foreign.invalid/apis', '//foreign.invalid/apis'):
                    with self.subTest(route=route), self.assertRaisesRegex(ValueError, 'Unsupported preview API path'):
                        kube.request('GET', route)
                opener.open.assert_not_called()

    def test_nonpreferred_discovery_and_list_errors_stay_fatal(self):
        for native in (False, True):
            for failure in (self.root + '/v1beta1',
                            self.root + '/v1beta1/namespaces/' + self.namespace + '/referencegrants'):
                with self.subTest(native=native, failure=failure), self.assertRaisesRegex(RuntimeError, 'API unavailable'):
                    self.run_inventory(native, failure)
