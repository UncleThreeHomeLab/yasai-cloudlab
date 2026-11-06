"""Offline boundaries for the explicit reduced ownership proof mode."""
from contextlib import contextmanager
import base64
import copy
import json
import io
from pathlib import Path
import signal
import socket
import ssl
import threading
import functools
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import yaml

from playbooks.argocd.tests import fixtures
from playbooks.observability.tests import lifecycle_controller_proof as proof

ROOT = Path('/workspace')


def kubeconfig():
    return {'apiVersion': 'v1', 'kind': 'Config', 'clusters': [{'name': 'fixture', 'cluster': {
        'server': 'https://127.0.0.1:6443', 'certificate-authority-data': 'Y2E='}}],
        'users': [{'name': 'fixture', 'user': {'client-certificate-data': 'Y2VydA==', 'client-key-data': 'a2V5'}}],
        'contexts': [{'name': 'fixture', 'context': {'cluster': 'fixture', 'user': 'fixture', 'namespace': 'default'}}],
        'current-context': 'fixture'}


def root():
    return {'metadata': {'uid': 'root-uid'}, 'spec': {
        'source': {'repoURL': proof.RUNTIME_OWNER, 'targetRevision': 'main', 'path': 'runtime-root'},
        'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False}}}}


def release_fixture():
    public_revision, owner_revision, accepted_revision = 'a' * 40, 'c' * 40, 'b' * 40
    root_object = root()
    root_object.update(apiVersion='argoproj.io/v1alpha1', kind='Application')
    root_object['metadata'].update(name='cloudlab-public-root', namespace='argocd')
    root_object['spec']['destination'] = {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
    parent_spec = {'sources': [{'repoURL': proof.RUNTIME_PUBLIC, 'targetRevision': public_revision},
        {'repoURL': proof.RUNTIME_PRIVATE, 'targetRevision': accepted_revision}],
        'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}}
    parent = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': {'name': proof.RUNTIME_PARENT,
        'namespace': 'argocd', 'uid': 'parent-uid', 'annotations': {'argocd.argoproj.io/skip-reconcile': 'false'}}, 'spec': copy.deepcopy(parent_spec)}
    active_set = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet',
        'metadata': {'name': proof.RUNTIME_PARENT, 'namespace': 'argocd', 'uid': 'set-uid'}, 'spec': {'release': True}}
    def ready(app, revision, multiple=False):
        key = 'sources' if multiple else 'source'
        app['status'] = {'sync': {'status': 'Synced', 'revisions' if multiple else 'revision': revision,
            'comparedTo': {key: copy.deepcopy(app['spec'][key]), 'destination': copy.deepcopy(app['spec']['destination'])}},
            'health': {'status': 'Healthy'}}
    ready(root_object, owner_revision)
    ready(parent, [public_revision, accepted_revision], True)
    children = proof.runtime_expected(public_revision, proof.runtime_private_inputs(), False)
    root_path, set_path = proof.runtime_path(root_object), proof.runtime_path(active_set)
    documents = {root_path: root_object, proof.APPS + proof.RUNTIME_PARENT: parent, set_path: copy.deepcopy(active_set)}
    owned = {path: {'identity': proof.runtime_identity(obj)} for path, obj in documents.items()}
    markers = {}
    for index, desired in enumerate(children):
        child = copy.deepcopy(desired); child['metadata']['uid'] = 'child-' + str(index)
        ready(child, public_revision)
        path = proof.runtime_path(child); documents[path] = child; owned[path] = {'identity': proof.runtime_identity(child)}
        marker_path = '/api/v1/namespaces/' + proof.RUNTIME_NAMESPACE + '/configmaps/marker-' + str(index)
        markers[desired['metadata']['name']] = (marker_path, 'marker-' + str(index), {'legacy': 'old'})
        documents[marker_path] = {'metadata': {'uid': 'marker-' + str(index)}, 'data': {'value': 'native',
            'digest': desired['metadata']['annotations']['cloudlab.io/observability-input-digest']}}
    api = Mock(); api.request.side_effect = lambda path: copy.deepcopy(documents[path])
    return {'api': api, 'root_path': root_path, 'root': copy.deepcopy(root_object), 'parent_uid': 'parent-uid',
        'set_path': set_path, 'active_set': active_set, 'expected_active_parent': parent_spec,
        'owner_source': SimpleNamespace(revision=owner_revision), 'public': SimpleNamespace(revision=public_revision),
        'accepted_revision': accepted_revision, 'active_expected': children, 'owned': owned, 'old_markers': markers,
        'diagnostic': {}}, documents


class RuntimeHandoffFixtureTests(unittest.TestCase):
    def test_runtime_https_validates_ca_hostname_and_closed_git_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ca, context = proof.runtime_git_pki(directory / 'pki')
            server = proof.RuntimeGitServer(('127.0.0.1', 0),
                functools.partial(proof.RuntimeGit, directory=str(directory)), context)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            trusted = ssl.create_default_context(cadata=ca)
            def request(path, host='github.com'):
                with socket.create_connection(server.server_address, timeout=3) as raw:
                    with trusted.wrap_socket(raw, server_hostname='github.com') as connection:
                        connection.sendall(('GET ' + path + ' HTTP/1.0\r\nHost: ' + host + '\r\n\r\n').encode())
                        return connection.recv(4096)
            try:
                with patch.object(fixtures, 'git_backend', return_value=
                        b'Content-Type: application/x-git-upload-pack-advertisement\r\n\r\nfixture') as backend:
                    for name in ('public', 'private', 'owner'):
                        self.assertIn(b'200 OK', request('/cloudlab-fixtures/observability-' + name +
                            '.git/info/refs?service=git-upload-pack'))
                        self.assertEqual(backend.call_args.args[1]['PATH_INFO'], '/' + name + '.git/info/refs')
                    for path, host in [('/public.git/info/refs?service=git-upload-pack', 'github.com'),
                            ('/cloudlab-fixtures/unknown.git/info/refs?service=git-upload-pack', 'github.com'),
                            ('/cloudlab-fixtures/observability-public.git/info/refs?service=git-upload-pack', 'other.invalid'),
                            ('/cloudlab-fixtures/observability-public.git/%69nfo/refs?service=git-upload-pack', 'github.com')]:
                        self.assertIn(b'403 Forbidden', request(path, host))
                    self.assertEqual(backend.call_count, 3)
                for client, hostname in [(ssl.create_default_context(), 'github.com'), (trusted, 'other.invalid')]:
                    with self.subTest(hostname=hostname), socket.create_connection(server.server_address, timeout=3) as raw:
                        with self.assertRaises(ssl.SSLCertVerificationError): client.wrap_socket(raw, server_hostname=hostname)
                self.assertEqual((directory / 'pki/server.key').stat().st_mode & 0o777, 0o600)
                self.assertEqual((directory / 'pki/ca.key').stat().st_mode & 0o777, 0o600)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

    def test_runtime_native_chart_renders_ca_alias_and_https_only_network(self):
        argo = ROOT / 'platform/delivery/argocd'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            ca, _ = proof.runtime_git_pki(directory / 'pki')
            values, network = proof.runtime_git_settings(proof.runtime_fixture_settings(
                yaml.safe_load((argo / 'values.yaml').read_text())), ca)
            path = directory / 'values.yaml'
            path.write_text(yaml.safe_dump(values))
            api = Mock()
            fixtures.install_argocd(api, directory, argo / 'charts/argo-cd-10.9.6.tgz',
                argo / 'artifact.lock.json', path, application_sets=True)
            objects = [call.args[0] for call in api.apply.call_args_list]
            certificates = next(obj for obj in objects if obj['kind'] == 'ConfigMap' and
                obj['metadata']['name'] == 'argocd-tls-certs-cm')
            self.assertEqual(certificates['data'], {'github.com': ca})
            for name in ('argocd-repo-server', 'argocd-applicationset-controller'):
                pod = next(obj for obj in objects if obj['kind'] == 'Deployment' and
                    obj['metadata']['name'] == name)['spec']['template']['spec']
                self.assertEqual(pod['hostAliases'], [{'ip': '10.245.237.3', 'hostnames': ['github.com']}])
                self.assertTrue(any(mount['mountPath'] == '/app/config/tls' for container in pod['containers']
                    for mount in container.get('volumeMounts', [])))
                self.assertFalse(any(env['name'] == 'GIT_CONFIG_GLOBAL' for container in pod['containers']
                    for env in container.get('env', [])))
                self.assertNotIn('fixture-git', json.dumps(pod))
            self.assertEqual(network['spec']['egress'][0], {'to': [{'ipBlock': {'cidr': '10.245.237.3/32'}}],
                'ports': [{'protocol': 'TCP', 'port': 443}]})
            self.assertEqual({port['port'] for rule in network['spec']['egress'] for port in rule['ports']}, {443, 53, 6379})

    def test_installer_opt_in_renders_exact_four_pinned_controllers_and_keeps_defaults(self):
        argo = ROOT / 'platform/delivery/argocd'
        for enabled in (False, True):
            api = Mock()
            with tempfile.TemporaryDirectory() as temporary:
                fixtures.install_argocd(api, Path(temporary), argo / 'charts/argo-cd-10.9.6.tgz',
                    argo / 'artifact.lock.json', argo / 'values.yaml', **({'application_sets': True} if enabled else {}))
            objects = [call.args[0] for call in api.apply.call_args_list]
            running = {obj['metadata']['name'] for obj in objects if obj['kind'] in ('Deployment', 'StatefulSet')
                       and obj['spec'].get('replicas', 1) > 0}
            expected = {'argocd-repo-server', 'argocd-redis', 'argocd-application-controller'}
            if enabled: expected.add('argocd-applicationset-controller')
            self.assertEqual(running, expected)
            server = next(obj for obj in objects if obj['kind'] == 'Deployment' and obj['metadata']['name'] == 'argocd-server')
            self.assertEqual(server['spec']['replicas'], 0)
        for invalid in ('true', 1, None):
            api = Mock()
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                fixtures.install_argocd(api, Path('/unused'), None, None, None, application_sets=invalid)
            api.apply.assert_not_called()

    def test_trusted_setup_preserves_signing_key_and_core_preflight_only_observes(self):
        values = yaml.safe_load((ROOT / 'platform/delivery/argocd/values.yaml').read_text())
        self.assertNotIn('server.secretkey', values['argo-cd']['configs'].get('secret', {}).get('extra', {}))
        prepared = proof.runtime_fixture_settings(copy.deepcopy(values))
        key = prepared['argo-cd']['configs']['secret']['extra']['server.secretkey']
        self.assertGreaterEqual(len(key), 32)
        self.assertTrue(proof.runtime_fixture_settings(prepared)['argo-cd']['configs']['secret']['extra']['server.secretkey'] == key,
                        'Trusted fixture signing key changed on repeat preparation')
        self.assertIs(prepared['argo-cd']['configs']['cm']['admin.enabled'], False)
        for setting_name, value in (('application.resourceTrackingMethod', 'label'), ('installationID', 'unapproved')):
            bad = copy.deepcopy(values)
            bad['argo-cd']['configs']['cm'][setting_name] = value
            with self.subTest(fixture_setting=setting_name), self.assertRaisesRegex(RuntimeError, 'annotation tracking'):
                proof.runtime_fixture_settings(bad)
        objects = {
            '/api/v1/namespaces/argocd/secrets/argocd-secret': {'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque',
                'metadata': {'name': 'argocd-secret', 'namespace': 'argocd', 'uid': 'secret', 'resourceVersion': '1'},
                'data': {'server.secretkey': base64.b64encode(key.encode()).decode()}},
            '/apis/argoproj.io/v1alpha1/namespaces/argocd/appprojects/default': {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
                'metadata': {'name': 'default', 'namespace': 'argocd', 'uid': 'project', 'resourceVersion': '2'}, 'spec': {}},
            '/api/v1/namespaces/argocd/configmaps/argocd-cm': {'apiVersion': 'v1', 'kind': 'ConfigMap',
                'metadata': {'name': 'argocd-cm', 'namespace': 'argocd', 'uid': 'settings', 'resourceVersion': '3'},
                'data': {'admin.enabled': 'false', 'application.resourceTrackingMethod': 'annotation'}}}
        read = Mock(side_effect=lambda path: copy.deepcopy(objects[path]))
        before = proof.runtime_core_state(read)
        self.assertEqual(read.call_count, 3)
        self.assertTrue(all(len(value['payloadSHA256']) == 64 for value in before.values()))
        self.assertFalse(key in json.dumps(before), 'Core state must contain hashes instead of signing key values')
        cm = objects['/api/v1/namespaces/argocd/configmaps/argocd-cm']['data']
        for method in (None, 'label', 'annotation+label'):
            if method is None: cm.pop('application.resourceTrackingMethod')
            else: cm['application.resourceTrackingMethod'] = method
            with self.subTest(tracking_method=method), self.assertRaisesRegex(RuntimeError, 'annotation tracking'):
                proof.runtime_core_state(read)
            cm['application.resourceTrackingMethod'] = 'annotation'
        cm['installationID'] = 'unapproved'
        with self.assertRaisesRegex(RuntimeError, 'installation ID'): proof.runtime_core_state(read)
        cm.pop('installationID')
        objects['/api/v1/namespaces/argocd/secrets/argocd-secret']['metadata']['resourceVersion'] = '4'
        self.assertNotEqual(proof.runtime_core_state(read), before)
        objects['/api/v1/namespaces/argocd/secrets/argocd-secret']['data'] = {}
        with self.assertRaises(RuntimeError): proof.runtime_core_state(read)
        self.assertTrue(all(len(call.args) == 1 and not call.kwargs for call in read.call_args_list))

    def test_root_policy_binds_uid_source_idle_and_actual_nonpruning_automation(self):
        current = root()
        expected = copy.deepcopy(current['spec'])
        proof.runtime_root_policy(current, expected, 'root-uid')
        for case in ('uid', 'prune', 'source', 'operation', 'empty-operation', 'running', 'deleting'):
            bad = copy.deepcopy(current)
            if case == 'uid': bad['metadata']['uid'] = 'replacement'
            if case == 'prune': bad['spec']['syncPolicy']['automated']['prune'] = True
            if case == 'source': bad['spec']['source']['targetRevision'] = 'other'
            if case == 'operation': bad['operation'] = {'sync': {}}
            if case == 'empty-operation': bad['operation'] = {}
            if case == 'running': bad['status'] = {'operationState': {'phase': 'Running'}}
            if case == 'deleting': bad['metadata']['deletionTimestamp'] = 'now'
            with self.subTest(case=case), self.assertRaises(RuntimeError): proof.runtime_root_policy(bad, expected, 'root-uid')

    def test_synthetic_public_source_preserves_native_parent_and_exact_six_paused_manifests(self):
        files = proof.runtime_public_files()
        native = ROOT / 'platform/observability/gitops'
        for path in native.rglob('*'):
            if path.is_file(): self.assertEqual(files[path.relative_to(ROOT).as_posix()], path.read_bytes())
        expected = proof.runtime_expected('a' * 40, proof.runtime_private_inputs(), True)
        raw = json.dumps({'manifests': [json.dumps(obj) for obj in expected]}).encode()
        self.assertEqual(proof.runtime_manifest_closure(raw, expected), expected)
        for case in ('extra', 'duplicate', 'kind', 'source', 'pause', 'digest'):
            objects = copy.deepcopy(expected)
            if case == 'extra': objects.append(copy.deepcopy(objects[0]))
            if case == 'duplicate': objects[-1] = copy.deepcopy(objects[0])
            if case == 'kind': objects[0]['kind'] = 'ConfigMap'
            if case == 'source': objects[0]['spec']['source']['targetRevision'] = 'b' * 40
            if case == 'pause': objects[0]['metadata']['annotations']['argocd.argoproj.io/skip-reconcile'] = 'false'
            if case == 'digest': objects[0]['metadata']['annotations']['cloudlab.io/observability-input-digest'] = 'b' * 64
            raw = json.dumps({'manifests': [json.dumps(obj) for obj in objects]}).encode()
            with self.subTest(case=case), self.assertRaises(RuntimeError): proof.runtime_manifest_closure(raw, expected)
        with self.assertRaises(RuntimeError): proof.strict_json('{"manifests":[],"manifests":[]}')
        with self.assertRaises(RuntimeError): proof.strict_json(b'x' * (proof.RUNTIME_HTTP_LIMIT + 1))

    def test_core_expected_adds_only_exact_tracking_and_keeps_whole_manifest_equality(self):
        helm = proof.runtime_expected('a' * 40, proof.runtime_private_inputs(), True)
        before = copy.deepcopy(helm)
        expected = proof.runtime_core_expected(helm)
        self.assertEqual(helm, before)
        for original, projected in zip(helm, expected):
            exact = copy.deepcopy(original)
            exact['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = (
                'cloudlab-observability-gitops:argoproj.io/Application:argocd/' + original['metadata']['name'])
            self.assertEqual(projected, exact)
            self.assertNotIn('argocd.argoproj.io/installation-id', projected['metadata']['annotations'])
        def response(objects): return json.dumps({'manifests': [json.dumps(obj) for obj in objects]}).encode()
        self.assertEqual(proof.runtime_manifest_closure(response(expected), expected), expected)
        for case in ('wrong-owner', 'wrong-tracking-name', 'wrong-name', 'wrong-spec', 'installation'):
            actual = copy.deepcopy(expected)
            annotations = actual[0]['metadata']['annotations']
            if case == 'wrong-owner': annotations['argocd.argoproj.io/tracking-id'] = 'other:argoproj.io/Application:argocd/' + actual[0]['metadata']['name']
            if case == 'wrong-tracking-name': annotations['argocd.argoproj.io/tracking-id'] = 'cloudlab-observability-gitops:argoproj.io/Application:argocd/other'
            if case == 'wrong-name': actual[0]['metadata']['name'] = 'other'
            if case == 'wrong-spec': actual[0]['spec']['source']['targetRevision'] = 'b' * 40
            if case == 'installation': annotations['argocd.argoproj.io/installation-id'] = 'unapproved'
            with self.subTest(case=case), self.assertRaises(RuntimeError): proof.runtime_manifest_closure(response(actual), expected)

    def test_fixture_kubeconfig_changes_only_loopback_endpoint_and_rejects_external_auth(self):
        original = kubeconfig()
        expected = copy.deepcopy(original)
        expected['clusters'][0]['cluster']['server'] = 'https://cluster:6443'
        self.assertEqual(proof.normalized_runtime_kubeconfig(original), expected)
        self.assertEqual(original, kubeconfig())
        for case in ('external', 'proxy', 'exec', 'token', 'context', 'ca'):
            bad = kubeconfig()
            if case == 'external': bad['clusters'][0]['cluster']['server'] = 'https://private.example.invalid'
            if case == 'proxy': bad['clusters'][0]['cluster']['proxy-url'] = 'http://proxy.invalid'
            if case == 'exec': bad['users'][0]['user']['exec'] = {'command': 'other'}
            if case == 'token': bad['users'][0]['user']['token'] = 'synthetic'
            if case == 'context': bad['contexts'][0]['context']['cluster'] = 'other'
            if case == 'ca': bad['clusters'][0]['cluster']['insecure-skip-tls-verify'] = True
            with self.subTest(case=case), self.assertRaises(RuntimeError): proof.normalized_runtime_kubeconfig(bad)

    def test_http_framing_bounds_and_redirects_fail_closed(self):
        body = b'{"manifests":[]}'
        length = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
        chunks = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n' + format(len(body), 'x').encode() + b'\r\n' + body + b'\r\n0\r\n\r\n'
        self.assertEqual(proof.runtime_http_response(length), body)
        self.assertEqual(proof.runtime_http_response(chunks), body)
        for raw in (length.replace(b'200 OK', b'302 Found'), length + b'x',
                length.replace(b'\r\n\r\n', b'\r\nContent-Encoding: gzip\r\n\r\n', 1),
                length.replace(b'\r\n\r\n', b'\r\nLocation: http://other.invalid\r\n\r\n', 1),
                chunks[:-1], chunks + b'x', b'x' * (proof.RUNTIME_HTTP_LIMIT + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(RuntimeError): proof.runtime_http_response(raw)

    def test_generate_endpoint_body_and_generated_parent_are_closed(self):
        receipt = {'version': 'cloudlab-consumer-source-acceptance/v1', 'consumer': 'observability',
            'paths': ['services/catalog.json', 'platform/observability.yaml'], 'revision': 'b' * 40, 'nonce': '2' * 64}
        selected = proof.runtime_root_objects('a' * 40, 'c' * 40, receipt, True)
        expected = next(obj for obj in selected if obj['kind'] == 'ApplicationSet')
        body = proof.runtime_generate_payload(expected)
        self.assertEqual(json.loads(body), {'applicationSet': expected})
        for case in ('extra', 'upsert', 'repo', 'patch', 'branch'):
            bad = copy.deepcopy(expected)
            if case == 'extra': bad['status'] = {}
            if case == 'upsert': bad['spec']['upsert'] = True
            if case == 'repo': bad['spec']['generators'][0]['merge']['generators'][1]['git']['repoURL'] = 'https://other.invalid'
            if case == 'patch': bad['spec']['templatePatch'] = 'spec: {}'
            if case == 'branch': bad['spec']['template']['spec']['sources'][0]['targetRevision'] = 'main'
            with self.subTest(case=case), self.assertRaises(RuntimeError): proof.runtime_generate_payload(bad)
        parent = copy.deepcopy(expected['spec']['template'])
        parent['metadata']['namespace'] = 'argocd'
        parent['spec']['sources'][1]['targetRevision'] = 'b' * 40
        response = json.dumps({'applications': [parent]}).encode()
        proof.runtime_generated_parent(response, parent)
        for case in ('extra', 'wrong', 'persisted'):
            changed = copy.deepcopy(parent)
            if case == 'wrong': changed['metadata']['name'] = 'other'
            if case == 'persisted': changed['metadata']['uid'] = 'persisted'
            objects = [changed, parent] if case == 'extra' else [changed]
            with self.subTest(case=case), self.assertRaises(RuntimeError):
                proof.runtime_generated_parent(json.dumps({'applications': objects}).encode(), parent)
        with self.assertRaises(RuntimeError):
            proof.runtime_core_request(12345, 'create', body, 10, [1024], lambda: None)

    def test_total_deadline_and_parent_binding_block_before_false_manifest_qualification(self):
        expected = proof.runtime_expected('a' * 40, proof.runtime_private_inputs(), True)
        core_expected = proof.runtime_core_expected(expected)
        receipt = {'version': 'cloudlab-consumer-source-acceptance/v1', 'consumer': 'observability',
            'paths': ['services/catalog.json', 'platform/observability.yaml'], 'revision': 'b' * 40, 'nonce': '2' * 64}
        native_set = next(obj for obj in proof.runtime_root_objects('a' * 40, 'c' * 40, receipt, True)
                          if obj['kind'] == 'ApplicationSet')
        installed_set = copy.deepcopy(native_set)
        installed_set['metadata'].update(uid='set-uid', resourceVersion='8')
        generated = copy.deepcopy(native_set['spec']['template'])
        generated['metadata']['namespace'] = 'argocd'
        generated['spec']['sources'][1]['targetRevision'] = 'b' * 40
        parent = copy.deepcopy(generated)
        parent['metadata'].update(uid='parent-uid', resourceVersion='7', ownerReferences=[{'uid': 'set-uid'}])
        bodies = [json.dumps({'applications': [generated]}).encode(),
                  json.dumps({'manifests': [json.dumps(obj) for obj in core_expected]}).encode()]
        packets = [b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body for body in bodies]
        clock = [0]
        @contextmanager
        def dashboard(*args):
            yield 12345, lambda: None
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        for delay, stale_set in ((0, False), (30, False), (0, True)):
            clock[0] = 0
            chunks = iter([packets[0], b'', packets[1], b''])
            def receive(size):
                clock[0] += delay
                return next(chunks)
            connection.recv.side_effect = receive
            connection.sendall.reset_mock()
            api = Mock()
            final_set = copy.deepcopy(installed_set)
            if stale_set: final_set['metadata']['resourceVersion'] = '9'
            api.request.side_effect = [copy.deepcopy(parent), copy.deepcopy(installed_set),
                copy.deepcopy(installed_set), copy.deepcopy(parent), copy.deepcopy(parent), final_set]
            with patch.object(proof, 'runtime_dashboard', dashboard), patch.object(proof.socket, 'create_connection', return_value=connection), \
                    patch.object(proof, 'runtime_core_state', return_value={'settings': 'unchanged'}) as settings, \
                    patch.object(proof.time, 'monotonic', side_effect=lambda: clock[0]):
                if delay or stale_set:
                    with self.assertRaises(RuntimeError):
                        proof.runtime_manifest_read(api, Path('/unused'), {}, parent, expected, native_set, installed_set)
                    self.assertEqual(api.request.call_count, 2 if delay else 6)
                else:
                    self.assertEqual(proof.runtime_manifest_read(api, Path('/unused'), {}, parent, expected, native_set, installed_set), core_expected)
                    self.assertEqual(api.request.call_count, 6)
                    sent = [call.args[0] for call in connection.sendall.call_args_list]
                    self.assertTrue(sent[0].startswith(b'POST /api/v1/applicationsets/generate HTTP/1.1\r\n'))
                    self.assertEqual(json.loads(sent[0].split(b'\r\n\r\n', 1)[1]), {'applicationSet': native_set})
                    self.assertTrue(sent[1].startswith(('GET ' + proof.RUNTIME_MANIFEST_PATH + ' HTTP/1.1\r\n').encode()))
                self.assertEqual(settings.call_count, 2)
        for case in ('changed-version', 'empty-operation'):
            api = Mock()
            changed = copy.deepcopy(parent)
            if case == 'changed-version': changed['metadata']['resourceVersion'] = '8'
            else: changed['operation'] = {}
            api.request.side_effect = [changed, copy.deepcopy(installed_set)]
            with self.subTest(case=case), patch.object(proof, 'runtime_dashboard') as start, self.assertRaises(RuntimeError):
                proof.runtime_manifest_read(api, Path('/unused'), {}, parent, expected, native_set, installed_set)
            start.assert_not_called()

    def test_cleanup_fills_only_missing_typemeta_from_validated_discovery(self):
        resource = {'kind': 'ConfigMap', 'name': 'configmaps', 'namespaced': True, 'verbs': ['get', 'list']}
        # Native Core list rows omit TypeMeta; keep the received payload unchanged.
        raw = {'metadata': {}, 'items': [{'metadata': {'name': 'kube-root-ca.crt',
            'namespace': proof.RUNTIME_NAMESPACE, 'uid': 'fixture-public-ca'}, 'data': {'ca.crt': 'synthetic public CA'}}]}
        read = Mock(return_value=raw)
        expected = copy.deepcopy(raw['items'][0]) | {'kind': 'ConfigMap', 'apiVersion': 'v1'}
        self.assertEqual(proof.runtime_cleanup_rows('/api/v1', resource, read), [expected])
        self.assertNotIn('kind', raw['items'][0])
        self.assertNotIn('apiVersion', raw['items'][0])
        read.assert_called_once_with('/api/v1/namespaces/' + proof.RUNTIME_NAMESPACE + '/configmaps')
        for key, value in (('kind', 'Secret'), ('apiVersion', 'other.invalid/v1')):
            bad = copy.deepcopy(raw)
            bad['items'][0][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                proof.runtime_cleanup_rows('/api/v1', resource, Mock(return_value=bad))
        with self.assertRaises(RuntimeError):
            proof.runtime_cleanup_rows('/apis/../v1', resource, read)
        read.assert_called_once()

    def test_owned_listener_checks_argv_group_socket_and_loopback_address(self):
        process = Mock(pid=123)
        arguments = ['/usr/local/bin/argocd', 'admin', 'dashboard']
        row = '0: 0100007F:3039 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 321\n'
        for case in ('valid', 'argv', 'group', 'outside', 'socket', 'child'):
            def directory(path):
                if str(path) == '/proc':
                    return iter([Path('/proc/123')] + ([Path('/proc/124')] if case == 'child' else []))
                return iter([Path('/proc/123/fd/9')])
            def text(path, *args, **kwargs):
                if path.name == 'stat': return '123 (argocd) S 42 123 123 0 0'
                if path.name == 'tcp': return 'header\n' + (row.replace('0100007F', '00000000') if case == 'outside' else row)
                return 'header\n'
            commandline = b'wrong\0' if case == 'argv' else b'\0'.join(arg.encode() for arg in arguments) + b'\0'
            with self.subTest(case=case), patch.object(proof.os, 'getpgid', return_value=124 if case == 'group' else 123), \
                    patch.object(Path, 'read_bytes', return_value=commandline), patch.object(Path, 'resolve', return_value=Path(arguments[0])), \
                    patch.object(Path, 'iterdir', directory), patch.object(Path, 'read_text', text), \
                    patch.object(proof.os, 'readlink', return_value='socket:[999]' if case == 'socket' else 'socket:[321]'):
                if case == 'valid': self.assertTrue(proof.runtime_listener(process, arguments, 12345))
                elif case == 'socket': self.assertFalse(proof.runtime_listener(process, arguments, 12345))
                else:
                    with self.assertRaises(RuntimeError): proof.runtime_listener(process, arguments, 12345)

    def test_dashboard_requires_complete_exact_ready_line_before_exclusive_process_guard(self):
        marker = b'Argo CD UI is available at http://127.0.0.1:12346'
        for case in ('fragmented-ready', 'wrong-port', 'no-marker', 'extra-member'):
            process = Mock(pid=12345)
            process.stdout.fileno.return_value = 9
            channel = Mock()
            channel.__enter__ = Mock(return_value=channel)
            channel.__exit__ = Mock(return_value=False)
            channel.getsockname.return_value = ('127.0.0.1', 12346)
            channel.connect_ex.return_value = 111
            clock = [0]
            chunks = ([marker, b'', b'\n', b''] if case == 'fragmented-ready' else
                [marker.replace(b'12346', b'12347') + b'\n', b''] if case == 'wrong-port' else
                [marker + b'\n', b''] if case == 'extra-member' else [b''])
            def read(_fd, _count): return chunks.pop(0) if chunks else b''
            def sleep(_seconds):
                guard.assert_not_called()  # An early socket or startup child cannot release the caller.
                clock[0] += 1
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(proof, 'runtime_binary', return_value='/usr/local/bin/argocd'), \
                    patch.object(proof.subprocess, 'Popen', return_value=process), \
                    patch.object(proof.socket, 'socket', return_value=channel), \
                    patch.object(proof.os, 'set_blocking'), patch.object(proof.os, 'read', side_effect=read), \
                    patch.object(proof.os, 'waitid', return_value=None), \
                    patch.object(proof.time, 'monotonic', side_effect=lambda: clock[0]), \
                    patch.object(proof.time, 'sleep', side_effect=sleep), \
                    patch.object(proof, 'runtime_listener', side_effect=RuntimeError('extra member') if case == 'extra-member' else None,
                        return_value=True) as guard, patch.object(proof, 'stop_dashboard') as cleanup:
                if case == 'fragmented-ready':
                    with proof.runtime_dashboard(Path(temporary), kubeconfig(), 2):
                        self.assertEqual(clock[0], 1)
                        guard.assert_called_once()
                else:
                    with self.assertRaisesRegex(RuntimeError, 'extra member' if case == 'extra-member' else 'deadline expired'):
                        with proof.runtime_dashboard(Path(temporary), kubeconfig(), 2):
                            self.fail('Core released caller before valid readiness and process guard')
                    if case == 'extra-member': guard.assert_called_once()
                    else: guard.assert_not_called()
                cleanup.assert_called_once_with(process)

    def test_dashboard_cleanup_runs_for_body_failure_and_wait_failure(self):
        process = Mock(pid=12345)
        process.stdout.fileno.return_value = 9
        channel = Mock()
        channel.__enter__ = Mock(return_value=channel)
        channel.__exit__ = Mock(return_value=False)
        channel.getsockname.return_value = ('127.0.0.1', 12346)
        channel.connect_ex.return_value = 111
        with tempfile.TemporaryDirectory() as temporary, patch.object(proof, 'runtime_binary', return_value='/usr/local/bin/argocd'), \
                patch.object(proof.subprocess, 'Popen', return_value=process) as launch, patch.object(proof.socket, 'socket', return_value=channel), \
                patch.object(proof.os, 'set_blocking'), patch.object(proof.os, 'read', side_effect=[b'Argo CD UI is available at http://127.0.0.1:12346\n', b'']), \
                patch.object(proof.os, 'waitid', return_value=None), patch.object(proof, 'runtime_listener', return_value=True), \
                patch.object(proof, 'stop_dashboard') as stop:
            with self.assertRaisesRegex(RuntimeError, 'body failed'):
                with proof.runtime_dashboard(Path(temporary), kubeconfig(), proof.time.monotonic() + 10):
                    raise RuntimeError('body failed')
            arguments = launch.call_args.args[0]
            config = Path(temporary) / 'dashboard-kubeconfig'
            self.assertEqual(launch.call_args.kwargs['env']['KUBECONFIG'], str(config))
            self.assertEqual(arguments[arguments.index('--kubeconfig') + 1], str(config))
            self.assertEqual(arguments[arguments.index('--config') + 1], str(Path(temporary) / 'dashboard-config'))
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(yaml.safe_load(config.read_text()), proof.normalized_runtime_kubeconfig(kubeconfig()))
            stop.assert_called_once_with(process)
        with patch.object(proof.os, 'killpg') as kill, patch.object(proof.os, 'waitid', side_effect=RuntimeError('wait failed')):
            with self.assertRaisesRegex(RuntimeError, 'wait failed'): proof.stop_dashboard(process)
        self.assertEqual([call.args for call in kill.call_args_list], [(12345, signal.SIGTERM), (12345, signal.SIGKILL)])
        process.wait.assert_called_once_with(timeout=5)
        process.stdout.close.assert_called_once()

    def test_release_timeout_reports_closed_failed_stage_without_more_reads_or_raw_errors(self):
        cases = [('set', 'set-spec', None, 3), ('parent', 'parent-spec', None, 3),
                 ('child', 'child-spec', proof.RUNTIME_CHILDREN[0], 6), ('marker', 'marker-digest', proof.RUNTIME_CHILDREN[0], 6),
                 ('guard', 'parent-set-identity', None, 3), ('api', 'parent-read', None, 2)]
        for case, stage, component, reads in cases:
            arguments, documents = release_fixture()
            desired = arguments['active_expected'][0]
            child_path = proof.runtime_path(desired)
            marker_path = arguments['old_markers'][desired['metadata']['name']][0]
            if case == 'set': documents[arguments['set_path']]['spec']['release'] = False
            if case == 'parent': documents[proof.APPS + proof.RUNTIME_PARENT]['spec']['changed'] = True
            if case == 'child': documents[child_path]['spec']['source']['targetRevision'] = 'd' * 40
            if case == 'marker': documents[marker_path]['data']['digest'] = 'wrong'
            if case == 'guard': documents[proof.APPS + proof.RUNTIME_PARENT]['metadata']['uid'] = 'replacement'
            raw_error = 'must-not-print-private-error-or-payload'
            if case == 'api':
                def read(path):
                    if path == proof.APPS + proof.RUNTIME_PARENT: raise RuntimeError(raw_error)
                    return copy.deepcopy(documents[path])
                arguments['api'].request.side_effect = read
            def wait(predicate, label, seconds):
                self.assertEqual((label, seconds), (proof.RUNTIME_RELEASE_LABEL, 420))
                try: predicate()
                except (OSError, ValueError, RuntimeError): pass
                raise RuntimeError('Runtime fixture timed out: ' + label)
            output = io.StringIO()
            with self.subTest(case=case), patch('sys.stdout', output):
                with self.assertRaisesRegex(RuntimeError, 'Runtime fixture timed out'):
                    try:
                        proof.runtime_release_wait(wait, lambda: proof.runtime_released(**arguments), arguments['diagnostic'])
                    finally:
                        self.assertTrue(output.getvalue(), 'Timeout diagnostic must precede caller cleanup')
            lines = output.getvalue().splitlines(); self.assertEqual(len(lines), 1)
            self.assertLess(len(lines[0]), 2048); self.assertNotIn(raw_error, lines[0])
            self.assertNotIn('replacement', lines[0]); self.assertNotIn('repoURL', lines[0])
            expected = {'stage': stage, 'component': component, 'exceptionType': 'RuntimeError' if case in ('guard', 'api') else None}
            self.assertEqual(json.loads(lines[0]), {'runtimeReleaseDiagnostic': {'firstFailed': expected, 'lastFailed': expected}})
            self.assertEqual(arguments['api'].request.call_count, reads)

    def test_release_diagnostic_retains_first_and_last_failure_but_pass_prints_nothing(self):
        arguments, documents = release_fixture()
        documents[arguments['set_path']]['spec']['release'] = False
        self.assertFalse(proof.runtime_released(**arguments))
        first = copy.deepcopy(arguments['diagnostic']['firstFailed'])
        documents[arguments['set_path']]['spec']['release'] = True
        first_child = arguments['active_expected'][0]['metadata']['name']
        marker_path = arguments['old_markers'][first_child][0]
        documents[marker_path]['data']['value'] = 'old'
        self.assertFalse(proof.runtime_released(**arguments))
        self.assertEqual(arguments['diagnostic']['firstFailed'], first)
        self.assertEqual(arguments['diagnostic']['lastFailed'], {'stage': 'marker-value', 'component': first_child, 'exceptionType': None})
        documents[marker_path]['data']['value'] = 'native'
        arguments['api'].request.reset_mock()
        def wait(predicate, label, seconds):
            self.assertEqual((label, seconds), (proof.RUNTIME_RELEASE_LABEL, 420))
            return predicate()
        output = io.StringIO()
        with patch('sys.stdout', output):
            self.assertTrue(proof.runtime_release_wait(wait, lambda: proof.runtime_released(**arguments), arguments['diagnostic']))
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(arguments['api'].request.call_count, 16)

    def test_release_diagnostic_preserves_closed_exception_classes_and_non_timeout_errors(self):
        for error, category in ((OSError('private'), 'OSError'), (ValueError('private'), 'ValueError'), (RuntimeError('private'), 'RuntimeError')):
            diagnostic = {}
            def fail(): raise error
            with self.subTest(category=category), self.assertRaises(type(error)) as raised:
                proof.runtime_release_observe(diagnostic, 'root-policy', fail)
            self.assertIs(raised.exception, error)
            self.assertEqual(diagnostic['lastFailed']['exceptionType'], category)
        output = io.StringIO()
        def wait(*args): raise RuntimeError('not the release timeout')
        with patch('sys.stdout', output), self.assertRaisesRegex(RuntimeError, 'not the release timeout'):
            proof.runtime_release_wait(wait, lambda: True, {})
        self.assertEqual(output.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
