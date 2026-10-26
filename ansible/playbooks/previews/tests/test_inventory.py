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
from playbooks.previews.tests.fixtures import native_inventory_graph, inventory_responses


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

    def test_discovery_marks_only_exact_native_metrics_without_payload_authority(self):
        graph = native_inventory_graph(self.namespace); responses = inventory_responses(graph, self.namespace)
        graph[0]['pod_metrics'] = True
        kube = object.__new__(Kubernetes)
        with patch.object(kube, 'request', side_effect=lambda method,route:copy.deepcopy(responses[route])):
            inventory = kube.namespace_inventory(self.namespace)
        metrics = next(obj for obj in inventory if obj['kind'] == 'PodMetrics')
        self.assertEqual(inventory.pod_metrics, {id(metrics)})
        self.assertTrue(namespace_disposable(inventory, {'native-root'}, 'namespace'))
        with self.assertRaises(ValueError): namespace_disposable(list(inventory), {'native-root'}, 'namespace')

    def test_metrics_discovery_payload_and_backing_failures_stay_closed(self):
        root = '/apis/metrics.k8s.io/v1beta1'; route = root + '/namespaces/' + self.namespace + '/pods'
        for change in ('write-verbs', 'kind', 'not-namespaced', 'version', 'group', 'unknown-readonly',
                       'payload-kind', 'payload-version', 'payload-namespace', 'metadata', 'missing-pod',
                       'foreign-refs', 'pagination', 'limit', 'discovery-error', 'list-error'):
            with self.subTest(change=change):
                responses = inventory_responses(native_inventory_graph(self.namespace), self.namespace)
                declaration = responses[root]['resources'][0]; obj = responses[route]['items'][0]
                if change == 'write-verbs': declaration['verbs'].append('delete')
                elif change == 'kind': declaration['kind'] = 'Pod'
                elif change == 'not-namespaced': declaration['namespaced'] = False
                elif change in ('version', 'group'):
                    new = 'metrics.k8s.io/v1alpha1' if change == 'version' else 'foreign.example/v1beta1'
                    for group in responses['/apis']['groups']:
                        for version in group['versions']:
                            if version['groupVersion'] == 'metrics.k8s.io/v1beta1': version['groupVersion'] = new
                    for path in list(responses):
                        if path.startswith(root): responses[path.replace(root, '/apis/' + new)] = responses.pop(path)
                    obj['apiVersion'] = new
                elif change == 'unknown-readonly':
                    declaration.update(name='usage', kind='UsageProjection'); obj['kind'] = 'UsageProjection'
                    responses[route.removesuffix('pods')+'usage'] = responses.pop(route)
                elif change == 'payload-kind': obj['kind'] = 'Pod'
                elif change == 'payload-version': obj['apiVersion'] = 'v1'
                elif change == 'payload-namespace': obj['metadata']['namespace'] = 'foreign'
                elif change == 'metadata': obj['metadata'] = None
                elif change == 'missing-pod': obj['metadata']['name'] = 'foreign'
                elif change == 'foreign-refs': obj['metadata']['ownerReferences'] = [{'uid': 'native-root'}]
                elif change == 'pagination': responses[route]['metadata'] = {'continue': 'next'}
                elif change == 'limit': responses[route]['items'] *= 501
                def read(method, path):
                    if path == (root if change == 'discovery-error' else route if change == 'list-error' else None):
                        raise RuntimeError('API unavailable')
                    return copy.deepcopy(responses[path])
                kube = object.__new__(Kubernetes)
                with patch.object(kube, 'request', side_effect=read), self.assertRaises((RuntimeError, ValueError)):
                    namespace_disposable(kube.namespace_inventory(self.namespace), {'native-root'}, 'namespace')

    def test_collection_payload_cannot_spoof_native_endpoints(self):
        for collection in ('foreign', 'core-alias'):
            with self.subTest(collection=collection):
                responses = inventory_responses(native_inventory_graph(self.namespace), self.namespace)
                source = '/api/v1/namespaces/' + self.namespace + '/endpoints'
                forged = responses[source]['items'].pop()
                resource = {'name': 'observations', 'kind': 'Observation', 'namespaced': True, 'verbs': ['get', 'list']}
                if collection == 'foreign':
                    version = 'foreign.example/v1'
                    responses['/apis']['groups'].append({'versions': [{'groupVersion': version}]})
                    responses['/apis/' + version] = {'resources': [resource]}
                    route = '/apis/' + version + '/namespaces/' + self.namespace + '/observations'
                else:
                    resource['kind'] = 'Endpoints'
                    responses['/api/v1']['resources'].append(resource)
                    route = source.removesuffix('endpoints') + 'observations'
                responses[route] = {'items': [forged]}
                kube = object.__new__(Kubernetes)
                with patch.object(kube, 'request', side_effect=lambda method,path:copy.deepcopy(responses[path])), self.assertRaises(RuntimeError):
                    namespace_disposable(kube.namespace_inventory(self.namespace), {'native-root'}, 'namespace')

    def test_explicit_collection_types_are_checked_but_omitted_types_are_normalized(self):
        for change in ('omitted', 'version', 'kind', 'malformed'):
            with self.subTest(change=change):
                responses = inventory_responses(native_inventory_graph(self.namespace), self.namespace)
                route = '/api/v1/namespaces/' + self.namespace + '/services'
                if change == 'omitted':
                    for value in responses.values():
                        for obj in value.get('items', []):
                            obj.pop('apiVersion'); obj.pop('kind')
                elif change == 'version': responses[route]['items'][0]['apiVersion'] = 'foreign.example/v1'
                elif change == 'kind': responses[route]['items'][0]['kind'] = 'Observation'
                else: responses[route]['items'] = ['malformed']
                kube = object.__new__(Kubernetes)
                with patch.object(kube, 'request', side_effect=lambda method,path:copy.deepcopy(responses[path])):
                    if change == 'omitted':
                        self.assertTrue(namespace_disposable(kube.namespace_inventory(self.namespace), {'native-root'}, 'namespace'))
                    else:
                        with self.assertRaises(RuntimeError): kube.namespace_inventory(self.namespace)
