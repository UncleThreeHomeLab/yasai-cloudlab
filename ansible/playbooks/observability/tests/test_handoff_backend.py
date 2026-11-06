import copy
from contextlib import nullcontext
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.observability.files import handoff as h, handoff_backend as backend, handoff_execute as execution


class HandoffBackendTests(unittest.TestCase):
    def test_http_framing_and_operator_watch_scope_fail_closed(self):
        self.assertEqual(backend.parse_native_http(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'), b'{}')
        self.assertEqual(backend.parse_native_http(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n'), b'{}')
        for raw in (b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}',
                    b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}',
                    b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}trailer',
                    b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}'):
            with self.subTest(raw=raw):
                with self.assertRaises(RuntimeError): backend.parse_native_http(raw)
        namespaces = {'cloudlab-observability', 'cloudlab-app-notes', 'other'}
        arguments = ['--namespaces=cloudlab-observability,cloudlab-app-notes',
            '--alertmanager-config-namespaces=cloudlab-observability']
        self.assertEqual(backend.operator_scope(arguments, namespaces), ['cloudlab-app-notes', 'cloudlab-observability'])
        for changed in (arguments + ['--unknown-watch=true'], arguments + ['--namespaces=other'],
                        ['--namespaces=missing'], arguments + ['--secret-field-selector=metadata.name=one']):
            with self.subTest(arguments=changed):
                with self.assertRaises(RuntimeError): backend.operator_scope(changed, namespaces)

    def test_unknown_creation_acknowledgement_never_adopts_or_deletes(self):
        class IO:
            def __init__(self): self.exists, self.calls = False, []
            def request(self, path, method='GET', body=None):
                self.calls.append(method)
                if method == 'GET':
                    return {'metadata': {'uid': 'unacknowledged'}} if self.exists else None
                self.exists = True
                raise RuntimeError('Response lost after native creation')
        value = backend.Backend.__new__(backend.Backend)
        value.io, value.journal, value.state = IO(), {}, {'mutations': {}}
        snapshots = []
        value.save = lambda: snapshots.append(copy.deepcopy(value.state))
        document = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {
            'name': 'cloudlab-handoff-probe-' + 'a' * 16, 'namespace': backend.NAMESPACE}, 'spec': {}}
        with self.assertRaises(RuntimeError): value.create('probe', backend.PREFIX + 'pods', document)
        self.assertIsNone(snapshots[0]['mutations']['probe']['uid'])
        with self.assertRaises(RuntimeError): value.create('probe', backend.PREFIX + 'pods', document)
        with self.assertRaises(RuntimeError): value.remove('probe')
        self.assertEqual(value.io.calls, ['GET', 'POST'])

    def test_classification_is_fresh_source_bound_and_exclusive(self):
        with tempfile.TemporaryDirectory(prefix='cloudlab-backend-', dir=Path.home()) as temporary:
            value = backend.Backend.__new__(backend.Backend)
            value.directory, value.operation, value.phase = Path(temporary), 'a' * 16, 'baseline'
            value.intent = {'operationId': value.operation, 'phase': value.phase,
                'prepared': {'bundleSHA256': 'b' * 64}, 'previousPhaseSHA256': None}
            current = {'source': {'name': backend.SOURCE, 'namespace': backend.NAMESPACE,
                'uid': '00000000-0000-0000-0000-000000000001', 'containerID': 'containerd://' + 'c' * 64,
                'startedAt': '2026-11-01T00:00:00Z'}, 'configSHA256': 'd' * 64, 'reloadTimestamp': 123.0, 'errors': {}}
            value.state = {'classifications': {}}
            value.save = lambda: None
            value.native_state = lambda: (copy.deepcopy(current), b'{"config":{"original":"receivers: []"}}')
            with self.assertRaises(backend.NativeConfigPending): value.classify('original')
            challenge = copy.deepcopy(value.state['pendingClassification']['challenge'])
            result = {'version': 'cloudlab-native-config-classification/v1',
                'challengeSHA256': h.digest(h.canonical(challenge)), 'challenge': challenge,
                'classification': 'original', 'originalConfigSHA256': current['configSHA256'],
                'configSHA256': current['configSHA256']}
            result_path = value.directory / ('native-' + challenge['nonce'] + '.classification.json')
            forged = copy.deepcopy(result); forged['challenge']['source']['uid'] = '00000000-0000-0000-0000-000000000002'
            h.write_once(result_path, forged)
            with self.assertRaises(RuntimeError): value.classify('original')
            # Exclusive staging must not replace a mismatching protected result.
            with self.assertRaises(RuntimeError): h.write_once(result_path, result)
            self.assertNotIn('original', value.state['classifications'])

    def test_storage_sync_cannot_precede_disk_validation_and_silence_identity_is_stable(self):
        value = backend.Backend.__new__(backend.Backend)
        value.state = {}
        with self.assertRaises(RuntimeError): value.replacement()
        value.phase, value.journal = 'maintenance', None
        with self.assertRaises(RuntimeError): value.reload_after_secret_sync(1)
        silence = {'id': '00000000-0000-0000-0000-000000000001', 'matchers': [], 'startsAt': 'a',
            'endsAt': 'b', 'createdBy': 'operator', 'comment': 'maintenance', 'status': {'state': 'active'}}
        expired = copy.deepcopy(silence); expired['status']['state'] = 'expired'
        self.assertEqual(backend.silence_state([silence]), backend.silence_state([expired]))
        with self.assertRaises(RuntimeError): backend.silence_state([silence, silence])

        # Build the receipt through the real producer. Core selectors follow
        # Argo's group,omitempty representation; a hand-built receipt hid this bug.
        application = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': {
            'name': 'cloudlab-prometheus', 'namespace': 'argocd',
            'uid': '00000000-0000-0000-0000-000000000001', 'resourceVersion': '7',
            'annotations': {'argocd.argoproj.io/skip-reconcile': 'false'}}, 'spec': {
            'source': {'targetRevision': 'b' * 40}, 'syncPolicy': {
                'automated': copy.deepcopy(execution.HOLD), 'syncOptions': []}}}
        secret = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {
            'name': 'alertmanager-cloudlab', 'namespace': backend.NAMESPACE}, 'data': {'alertmanager.yaml': 'e30='}}
        intent = {'operationId': 'a' * 16, 'applicationBindings': {'cloudlab-prometheus': application}}
        packet = {'objects': {'cloudlab-prometheus': [secret]}}
        documents = {'intent': intent, 'resources': packet,
            'record': {'intentSHA256': h.digest(h.canonical(intent)), 'payloadSHA256': h.digest(h.canonical(packet))},
            'draft-payload': {'phaseApplications': {'cloudlab-prometheus': application}}}
        deny = {'apiVersion': 'security.istio.io/v1', 'kind': 'AuthorizationPolicy', 'metadata': {
            'name': backend.DENY, 'namespace': backend.NAMESPACE,
            'uid': '00000000-0000-0000-0000-000000000002', 'resourceVersion': '8'}, 'spec': {'action': 'DENY'}}
        journal = {'authorization': {'operationId': intent['operationId']}, 'steps': {
            'owned-deny': {'identity': execution.transport.identity(deny), 'spec': deny['spec']}}}
        class IO:
            def __init__(self): self.operation, self.commands = None, []
            def bounded(self, _deadline): return nullcontext()
            def request(self, _path, method='GET', body=None, content_type=None):
                result = copy.deepcopy(application)
                if method == 'PATCH':
                    self.operation = copy.deepcopy(body[-1]['value'])
                    result['operation'] = self.operation
                elif self.operation is not None:
                    result['status'] = {'operationState': {'phase': 'Succeeded', 'operation': self.operation}}
                return result
            def command(self, arguments, **kwargs):
                self.commands.append((arguments, kwargs))
                return b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'
        native = IO()
        with patch.object(h, 'phase_json', side_effect=lambda path: documents[path.name.split('.')[-2]]), \
                patch.object(execution, 'persist'):
            execution.sync_resources(native, Path('/unused'), 'maintenance', journal, 'cloudlab-prometheus', [secret])
        operation = native.operation
        self.assertNotIn('group', operation['sync']['resources'][0])
        value.operation, value.phase, value.journal, value.io = intent['operationId'], 'maintenance', journal, native
        value.state = {'denied': True, 'mutations': {}}
        value.get, value.resource = lambda _path: deny, lambda *_args: secret
        image = 'example.invalid/alertmanager@sha256:' + 'd' * 64
        source = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': backend.SOURCE, 'namespace': backend.NAMESPACE,
            'uid': '00000000-0000-0000-0000-000000000003', 'resourceVersion': '9'},
            'spec': {'containers': [{'name': 'alertmanager', 'image': image}]},
            'status': {'phase': 'Running', 'containerStatuses': [{
                'name': 'alertmanager', 'image': image, 'imageID': image, 'ready': True,
                'restartCount': 0, 'containerID': 'containerd://' + 'c' * 64,
                'state': {'running': {'startedAt': '2026-11-01T00:00:00Z'}}}]}}
        identity = backend.cp.source_identity(source)
        value.native_state = lambda: ({'source': identity, 'reloadTimestamp': 1.0}, b'{}')
        value.source, value.save = lambda: source, lambda: None
        value.wait_reload = lambda previous: {'reloadTimestamp': previous + 1}
        self.assertEqual(value.reload_after_secret_sync(1.0), {'reloadTimestamp': 2.0})
        self.assertEqual(len(native.commands), 1)
        arguments, options = native.commands[0]
        self.assertEqual(arguments, ['exec', '-i', '-n', backend.NAMESPACE, backend.SOURCE, '-c', 'alertmanager',
            '--', '/bin/nc', '-n', '-w', '8', '127.0.0.1', '9093'])
        self.assertEqual(options['body'], b'POST /-/reload HTTP/1.1\r\nHost: 127.0.0.1:9093\r\nConnection: close\r\n'
            b'Accept-Encoding: identity\r\nContent-Length: 0\r\n\r\n')
        value.phase = 'baseline'
        with self.assertRaises(RuntimeError): value.reload_after_secret_sync(1.0)
        value.phase, value.state['denied'] = 'maintenance', False
        with self.assertRaises(RuntimeError): value.reload_after_secret_sync(1.0)
        value.state['denied'] = True
        journal['steps'] = {'owned-deny': journal['steps']['owned-deny']}
        with self.assertRaises(RuntimeError): value.reload_after_secret_sync(1.0)
        self.assertEqual(len(native.commands), 1)


if __name__ == '__main__':
    unittest.main()
