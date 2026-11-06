import ast
import copy
import http.client
import json
import io
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

from playbooks.previews.files.kube import Kubernetes, APIError, METADATA_ACCEPT
from playbooks.previews.files.lifecycle import namespace_disposable
from playbooks.previews.tests.native_admission import REMOTE
from playbooks.previews.tests.fixtures import native_inventory_graph, inventory_responses


class InventoryTests(unittest.TestCase):
    def secret_responses(self, items):
        responses = inventory_responses(native_inventory_graph(self.namespace), self.namespace)
        responses['/api/v1']['resources'].append(
            {'name': 'secrets', 'kind': 'Secret', 'namespaced': True, 'verbs': ['get', 'list']})
        responses['/api/v1/namespaces/' + self.namespace + '/secrets'] = {
            'apiVersion': 'meta.k8s.io/v1', 'kind': 'PartialObjectMetadataList',
            'metadata': {'resourceVersion': '7'}, 'items': items}
        return responses

    def test_secret_metadata_transport_normalizes_presence_and_keeps_cleanup_veto(self):
        meta = {'name': 'unexpected', 'namespace': self.namespace, 'uid': 'secret-uid', 'resourceVersion': '7',
                'ownerReferences': [{'uid': 'native-root'}],
                'annotations': {'cloudlab.io/retention': 'keep'}}
        secret = {'apiVersion': 'meta.k8s.io/v1', 'kind': 'PartialObjectMetadata', 'metadata': meta}
        route = '/api/v1/namespaces/' + self.namespace + '/secrets'
        for items in ([secret], [], None):
            with self.subTest(items=items), tempfile.TemporaryDirectory() as directory:
                responses = self.secret_responses(items)
                kube = object.__new__(Kubernetes); kube.context = None; kube.account = Path(directory)
                kube.account.joinpath('token').write_text('synthetic-token')
                def response(request, **kwargs):
                    path = request.full_url.removeprefix('https://kubernetes.default.svc')
                    self.assertEqual(request.get_header('Accept'), METADATA_ACCEPT if path == route else None)
                    self.assertEqual(request.get_header('Authorization'), 'Bearer synthetic-token')
                    self.assertEqual(kwargs, {'timeout': 10})
                    # Native metadata JSON may have a plain application/json Content-Type.
                    stream = io.BytesIO(json.dumps(responses[path]).encode())
                    stream.headers = {'Content-Type': 'application/json'}
                    return stream
                opener = Mock(); opener.open.side_effect = response
                with patch('playbooks.previews.files.kube.urllib.request.build_opener', return_value=opener):
                    inventory = kube.namespace_inventory(self.namespace)
                self.assertEqual(sum(call.args[0].full_url.endswith('/secrets') for call in opener.open.call_args_list), 1)
                if items:
                    observed = next(obj for obj in inventory if obj['kind'] == 'Secret')
                    self.assertEqual(observed, {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': meta})
                    with self.assertRaisesRegex(ValueError, 'Unexpected data'):
                        namespace_disposable(inventory, {'native-root'}, 'namespace')
                    # Secret presence alone vetoes cleanup, even with an accepted owner and no retention annotation.
                    observed['metadata'].pop('annotations')
                    with self.assertRaisesRegex(ValueError, 'Unexpected data'):
                        namespace_disposable(inventory, {'native-root'}, 'namespace')
                else:
                    self.assertTrue(namespace_disposable(inventory, {'native-root'}, 'namespace'))

    def test_secret_metadata_invalid_representations_fail_closed_without_fallback(self):
        route = '/api/v1/namespaces/' + self.namespace + '/secrets'
        secret = {'apiVersion': 'meta.k8s.io/v1', 'kind': 'PartialObjectMetadata',
                  'metadata': {'name': 'unexpected', 'namespace': self.namespace,
                               'uid': 'secret-uid', 'resourceVersion': '7'}}
        original = self.secret_responses([secret])[route]
        changes = ('list-version', 'list-kind', 'list-extra', 'list-metadata', 'missing-metadata',
                   'missing-items', 'items-shape', 'limit', 'continuation', 'remaining', 'remaining-type',
                   'null-continuation', 'item-shape', 'item-version', 'item-kind', 'item-metadata',
                   'item-name', 'item-namespace', 'item-uid', 'item-resourceVersion',
                   'data', 'stringData', 'type', 'spec', 'status', 'full-list', 'null-list')
        for change in changes:
            value = copy.deepcopy(original)
            if change == 'list-version': value['apiVersion'] = 'v1'
            elif change == 'list-kind': value['kind'] = 'SecretList'
            elif change == 'list-extra': value['data'] = {'private-body-sentinel': 'sensitive'}
            elif change == 'list-metadata': value['metadata'] = []
            elif change == 'missing-metadata': del value['metadata']
            elif change == 'missing-items': del value['items']
            elif change == 'items-shape': value['items'] = {}
            elif change == 'limit': value['items'] *= 501
            elif change == 'continuation': value['metadata']['continue'] = 'private-body-sentinel'
            elif change == 'remaining': value['metadata']['remainingItemCount'] = 1
            elif change == 'remaining-type': value['metadata']['remainingItemCount'] = True
            elif change == 'null-continuation': value['metadata']['continue'] = None
            elif change == 'item-shape': value['items'] = ['private-body-sentinel']
            elif change == 'item-version': value['items'][0]['apiVersion'] = 'v1'
            elif change == 'item-kind': value['items'][0]['kind'] = 'Secret'
            elif change == 'item-metadata': value['items'][0]['metadata'] = None
            elif change.startswith('item-'): value['items'][0]['metadata'][change.removeprefix('item-')] = ''
            elif change in ('data', 'stringData', 'type', 'spec', 'status'):
                value['items'][0][change] = {'private-body-sentinel': 'sensitive'}
            elif change == 'full-list':
                value.update(apiVersion='v1', kind='SecretList')
                value['items'][0].update(apiVersion='v1', kind='Secret', data={'private-body-sentinel': 'sensitive'})
            else: value = None
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                responses = self.secret_responses([]); responses[route] = value
                kube = object.__new__(Kubernetes); kube.context = None; kube.account = Path(directory)
                kube.account.joinpath('token').write_text('synthetic-token')
                def response(request, **kwargs):
                    path = request.full_url.removeprefix('https://kubernetes.default.svc')
                    self.assertEqual(request.get_header('Accept'), METADATA_ACCEPT if path == route else None)
                    return io.BytesIO(json.dumps(responses[path]).encode())
                opener = Mock(); opener.open.side_effect = response
                with patch('playbooks.previews.files.kube.urllib.request.build_opener', return_value=opener):
                    with self.assertRaises(RuntimeError) as error: kube.namespace_inventory(self.namespace)
                self.assertNotIn('private-body-sentinel', str(error.exception))
                self.assertEqual(sum(call.args[0].full_url.endswith('/secrets') for call in opener.open.call_args_list), 1)

    def test_secret_metadata_transport_failures_are_sanitized_without_fallback(self):
        route = '/api/v1/namespaces/' + self.namespace + '/secrets'
        for failure in (403, 406, b'{private-body-sentinel', b'private-body-sentinel' * 110000,
                        http.client.IncompleteRead(b'private-body-sentinel', 100),
                        OSError('private-body-sentinel')):
            with self.subTest(failure=type(failure)), tempfile.TemporaryDirectory() as directory:
                responses = self.secret_responses([])
                kube = object.__new__(Kubernetes); kube.context = None; kube.account = Path(directory)
                kube.account.joinpath('token').write_text('synthetic-token')
                def response(request, **kwargs):
                    path = request.full_url.removeprefix('https://kubernetes.default.svc')
                    if path != route: return io.BytesIO(json.dumps(responses[path]).encode())
                    self.assertEqual(request.get_header('Accept'), METADATA_ACCEPT)
                    if isinstance(failure, int):
                        raise urllib.error.HTTPError(request.full_url, failure, 'private-body-sentinel', {}, None)
                    stream = io.BytesIO(failure if isinstance(failure, bytes) else b'')
                    if isinstance(failure, Exception): stream.read = Mock(side_effect=failure)
                    return stream
                opener = Mock(); opener.open.side_effect = response
                with patch('playbooks.previews.files.kube.urllib.request.build_opener', return_value=opener):
                    with self.assertRaises(RuntimeError) as error: kube.namespace_inventory(self.namespace)
                self.assertNotIn('private-body-sentinel', str(error.exception))
                self.assertEqual(sum(call.args[0].full_url.endswith('/secrets') for call in opener.open.call_args_list), 1)

    def test_core_secret_discovery_mismatch_fails_before_collection_read(self):
        for change in ({'kind': 'Observation'}, {'name': 'observations'},
                       {'namespaced': False}, {'verbs': ['get']}):
            with self.subTest(change=change):
                responses = self.secret_responses([])
                responses['/api/v1']['resources'][-1].update(change)
                kube = object.__new__(Kubernetes)
                with patch.object(kube, 'request', side_effect=lambda method, path: copy.deepcopy(responses[path])) as request:
                    with self.assertRaisesRegex(RuntimeError, 'Native Secrets'): kube.namespace_inventory(self.namespace)
                self.assertFalse(any(call.args[1].endswith('/secrets') for call in request.call_args_list))

    def test_secret_metadata_negotiation_does_not_change_unknown_collections(self):
        responses = self.secret_responses([])
        version = 'foreign.example/v1'
        responses['/apis']['groups'].append({'versions': [{'groupVersion': version}]})
        responses['/apis/' + version] = {'resources': [
            {'name': 'secrets', 'kind': 'Secret', 'namespaced': True, 'verbs': ['list']}]}
        route = '/apis/' + version + '/namespaces/' + self.namespace + '/secrets'
        foreign = {'apiVersion': version, 'kind': 'Secret', 'metadata': {'name': 'foreign'}, 'spec': {'foreign': True}}
        responses[route] = {'items': [foreign]}
        kube = object.__new__(Kubernetes)
        with patch.object(kube, 'request', side_effect=lambda method, path, **kwargs: copy.deepcopy(responses[path])) as request:
            inventory = kube.namespace_inventory(self.namespace)
        self.assertIn(foreign, inventory)
        self.assertEqual([call.kwargs for call in request.call_args_list if call.args[1] == route], [{}])
        self.assertEqual([call.kwargs for call in request.call_args_list if call.kwargs], [{'_metadata_only': True}])
        with self.assertRaisesRegex(ValueError, 'Unexpected data'):
            namespace_disposable(inventory, {'native-root'}, 'namespace')

    def test_object_get_actual_transport_distinguishes_404_from_uncertain_success(self):
        key = ('v1', 'Namespace', '', 'cloudlab-preview-synthetic')
        namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': key[3], 'uid': 'owned'}}
        for result in (b'', b'null', b'{private-body-sentinel', 404, 403, 500, json.dumps(namespace).encode()):
            with self.subTest(result=result), tempfile.TemporaryDirectory() as directory:
                kube = object.__new__(Kubernetes); kube.context = None; kube.account = Path(directory)
                kube.account.joinpath('token').write_text('synthetic-token')
                opener = Mock()
                if isinstance(result, int):
                    opener.open.side_effect = urllib.error.HTTPError('https://kubernetes.default.svc/fixture', result,
                        'private-body-sentinel', {}, None)
                else: opener.open.side_effect = lambda *args, **kwargs:io.BytesIO(result)
                with patch('playbooks.previews.files.kube.urllib.request.build_opener', return_value=opener):
                    if result == 404: self.assertIsNone(kube.get(key))
                    elif result == json.dumps(namespace).encode(): self.assertEqual(kube.get(key), namespace)
                    else:
                        with self.assertRaises(RuntimeError) as error: kube.get(key)
                        self.assertNotIn('private-body-sentinel', str(error.exception))
                        if isinstance(result, int):
                            self.assertIsInstance(error.exception, APIError); self.assertEqual(error.exception.code, result)

    def test_empty_successful_delete_keeps_request_and_uid_version_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            kube = object.__new__(Kubernetes); kube.context = None; kube.account = Path(directory)
            kube.account.joinpath('token').write_text('synthetic-token')
            def response(request, **kwargs):
                self.assertEqual(request.get_method(), 'DELETE')
                self.assertEqual(json.loads(request.data)['preconditions'], {'uid': 'owned', 'resourceVersion': '7'})
                return io.BytesIO(b'')
            opener = Mock(); opener.open.side_effect = response
            with patch('playbooks.previews.files.kube.urllib.request.build_opener', return_value=opener):
                self.assertIsNone(kube.delete(('v1', 'Namespace', '', 'cloudlab-preview-synthetic'), 'owned', '7'))

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
