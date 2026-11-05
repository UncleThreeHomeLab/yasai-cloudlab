"""Offline fixed-scope proof procedure tests; these do not qualify a controller."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import yaml
import private_source_acceptance as proof

ROOT = Path(__file__).resolve().parents[4]


def files(path):
    base = ROOT / path
    return {item.relative_to(base).as_posix(): item.read_bytes() for item in base.rglob('*') if item.is_file()}


class SourceAcceptanceProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_files = files('gitops/roots/public')
        cls.fixture_files = files(proof.CHART)
        cls.public = yaml.safe_load(cls.root_files['values.yaml'])

    def setUp(self):
        self.config = {'version': proof.VERSION, 'attempt': '1' * 32, 'publicRevision': 'f' * 40,
            'privateRepository': 'https://github.com/example/private.git', 'privateBranch': 'proof/prices-source-' + '2' * 32,
            'receiptA': {'version': 'cloudlab-private-source-acceptance/v1', 'consumer': 'private-sources', 'revision': 'a' * 40, 'nonce': 'c' * 64},
            'receiptB': {'version': 'cloudlab-private-source-acceptance/v1', 'consumer': 'private-sources', 'revision': 'b' * 40, 'nonce': 'd' * 64}}
        self.objects = {('configmap', 'kube-root-ca.crt', 'argocd'): {'data': {'ca.crt': 'public-root'}},
            ('application.argoproj.io', 'cloudlab-public-root', 'argocd'): {'metadata': {'uid': 'root-authority'}},
            ('deployment', 'argocd-applicationset-controller', 'argocd'): {'metadata': {'uid': 'controller-authority'}}}
        self.writes = []; self.version = 0; self.repair = False
        self.fail_list = False
        self.context_patch = patch.object(proof, 'context', side_effect=lambda config, state=None: (
            proof.config_guard(config, state) or self.public, self.root_files, self.fixture_files,
            {'Root': 'root-authority', 'ApplicationSetController': 'controller-authority'}))
        self.context_patch.start(); self.addCleanup(self.context_patch.stop)
        get = patch.object(proof, 'get', side_effect=self.get); get.start(); self.addCleanup(get.stop)
        kube = patch.object(proof, 'kube', side_effect=self.kube); kube.start(); self.addCleanup(kube.stop)

    def stored(self, obj):
        self.version += 1; obj = copy.deepcopy(obj)
        obj['metadata'].setdefault('uid', 'uid-' + str(self.version))
        obj['metadata']['resourceVersion'] = str(self.version)
        resource = {'Namespace': 'namespace', 'AppProject': 'appproject.argoproj.io', 'ExternalSecret': 'externalsecret.external-secrets.io',
            'ApplicationSet': 'applicationset.argoproj.io', 'Application': 'application.argoproj.io', 'ConfigMap': 'configmap', 'Secret': 'secret', 'ServiceAccount': 'serviceaccount'}[obj['kind']]
        self.objects[resource, obj['metadata']['name'], obj['metadata'].get('namespace')] = obj
        return copy.deepcopy(obj)

    def get(self, resource, name=None, namespace=None):
        obj = self.objects.get((resource, name, namespace))
        if self.repair and resource == 'configmap' and name == 'approval-marker' and obj and obj['data']['revision'].startswith('source-proof-drift-'):
            obj['data'] = {'revision': self.config['receiptA']['revision']}
        return copy.deepcopy(obj)

    def kube(self, *args, document=None, **kwargs):
        if args[0] == 'api-resources': return 'configmaps\nserviceaccounts\npods\nwidgets.example.invalid'
        if args[0] == 'get':
            if self.fail_list: raise proof.ProofError('synthetic list denial')
            kinds = {'configmaps': 'configmap', 'serviceaccounts': 'serviceaccount', 'pods': 'pod', 'widgets.example.invalid': 'widget'}
            return json.dumps({'items': [row for (kind, name, ns), row in self.objects.items() if kind == kinds[args[1]] and ns == proof.NAME]})
        self.writes.append((args, copy.deepcopy(document)))
        if args[0] == 'create':
            result = self.stored(document)
            if document['kind'] == 'Namespace':
                self.objects['namespace', proof.NAME, None]['spec'] = {'finalizers': ['kubernetes']}
                self.stored({'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'default', 'namespace': proof.NAME}})
                self.stored({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'kube-root-ca.crt', 'namespace': proof.NAME}, 'data': {'ca.crt': 'public-root'}})
            return json.dumps(result)
        if args[0] == 'patch':
            resource = 'configmap' if args[1] == 'configmap' else 'applicationset.argoproj.io'
            namespace = proof.NAME if resource == 'configmap' else 'argocd'
            actual = copy.deepcopy(self.objects[resource, args[2], namespace])
            for row in document:
                keys = [key.replace('~1', '/').replace('~0', '~') for key in row['path'].strip('/').split('/')]
                target = actual
                for key in keys[:-1]: target = target[key]
                if row['op'] == 'test':
                    if target.get(keys[-1]) != row['value']: raise proof.ProofError('synthetic atomic test failed')
                else: target[keys[-1]] = row['value']
            return json.dumps(self.stored(actual))
        if args[0] == 'delete':
            path = args[1].split('=', 1)[1]
            key = next(key for key, (_, name, _, prefix) in proof.RESOURCES.items() if prefix + name == path)
            resource, name, namespace, _ = proof.RESOURCES[key]
            obj = self.objects[resource, name, namespace]
            self.assertEqual(document['preconditions'], {'uid': obj['metadata']['uid'], 'resourceVersion': obj['metadata']['resourceVersion']})
            del self.objects[resource, name, namespace]
            for row in self.objects.values():
                if any(owner.get('uid') == obj['metadata']['uid'] for owner in row.get('metadata', {}).get('ownerReferences', [])):
                    row['metadata'].pop('ownerReferences')
            if key == 'Namespace':
                self.objects = {key: value for key, value in self.objects.items() if key[2] != proof.NAME}
            return '{}'
        raise AssertionError('Unexpected proof command')

    def begin(self):
        state = proof.create(self.config)['state']
        external = self.objects['externalsecret.external-secrets.io', proof.NAME + '-source', 'argocd']
        external['metadata']['finalizers'] = [proof.native.ESO_FINALIZER]
        external['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
        data = {'type': 'git', 'url': self.config['privateRepository'], 'project': proof.NAME,
            'githubAppID': '1', 'githubAppInstallationID': '2', 'githubAppPrivateKey': 'synthetic'}
        self.stored({'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque', 'metadata': {'name': proof.NAME + '-source', 'namespace': 'argocd',
            'labels': {'cloudlab.io/owner': proof.OWNER, 'cloudlab.io/proof-attempt': self.config['attempt'], 'argocd.argoproj.io/secret-type': 'repository'},
            'ownerReferences': [{'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'name': proof.NAME + '-source',
                'uid': state['identities']['ExternalSecret'], 'controller': True, 'blockOwnerDeletion': True}]},
            'data': {key: base64.b64encode(value.encode()).decode() for key, value in data.items()}})
        self.converge(state)
        return proof.observe(self.config, state)['state']

    def converge(self, state):
        desired = proof.declarations(self.config, state, self.public, self.root_files)
        metadata = desired['ApplicationSet']['spec']['template']['metadata']
        existing = self.objects.get(('application.argoproj.io', proof.NAME, 'argocd'))
        metadata = copy.deepcopy(metadata)
        if existing: metadata['uid'] = existing['metadata']['uid']
        metadata['ownerReferences'] = [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': proof.NAME,
            'uid': state['identities']['ApplicationSet'], 'controller': True, 'blockOwnerDeletion': True}]
        self.stored({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': metadata,
            'spec': proof.child_spec(self.config, state, desired, state['approval'], state['markerEnabled']),
            'status': {'sync': {'status': 'Synced', 'revisions': [self.config['publicRevision'], self.config['receipt' + state['approval']]['revision']]},
                'health': {'status': 'Healthy'}}})
        values = {'sources': [], 'proofAttempt': self.config['attempt'], 'acceptedRevision': self.config['receipt' + state['approval']]['revision'], 'markerEnabled': state['markerEnabled']}
        result = subprocess.run(['helm', 'template', 'proof', str(ROOT / proof.CHART), '-n', proof.NAME, '-f', '-'], input=json.dumps(values), capture_output=True, text=True, timeout=30, check=True)
        rendered = [row for row in yaml.safe_load_all(result.stdout) if row]
        for row in rendered:
            old = self.objects.get(('configmap', row['metadata']['name'], proof.NAME))
            if old: row['metadata']['uid'] = old['metadata']['uid']
            row['metadata'].setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = proof.NAME + ':/ConfigMap:' + proof.NAME + '/' + row['metadata']['name']
            self.stored(row)
        if not state['markerEnabled']: self.objects.pop(('configmap', 'approval-marker', proof.NAME), None)
        self.objects['applicationset.argoproj.io', proof.NAME, 'argocd']['status'] = {'conditions': [{'type': 'ParametersGenerated', 'status': 'True'}, {'type': 'ErrorOccurred', 'status': 'False'}]}

    def test_fixed_fixture_b_updates_and_marker_removal_preserve_captured_sentinel(self):
        state = self.begin(); before = state['identities'].copy()
        state = proof.change(self.config, state, approval='B')['state']; self.converge(state)
        state = proof.observe(self.config, state)['state']
        self.assertEqual(state['identities'], before)
        state = proof.change(self.config, state, marker=False)['state']; self.converge(state)
        state = proof.observe(self.config, state)['state']
        self.assertIsNone(proof.read('Marker')); self.assertEqual(proof.read('Retained')['data'], proof.RETAINED)
        self.assertEqual(proof.read('Retained')['metadata']['uid'], before['Retained'])
        self.assertTrue(proof.cleanup(self.config, state)['cleanup_complete'])
        self.assertIsNone(proof.read('Namespace'))

    def test_source_error_observation_requires_exact_retained_child_and_visible_error(self):
        state = self.begin(); uid = state['identities']['Application']
        state = proof.change(self.config, state, available=False)['state']
        self.objects['applicationset.argoproj.io', proof.NAME, 'argocd']['status']['conditions'] = [{'type': 'ErrorOccurred', 'status': 'True'}]
        self.assertTrue(proof.observe(self.config, state, rejected=True)['parent_error_retains_child'])
        self.assertEqual(proof.read('Application')['metadata']['uid'], uid)
        with self.assertRaisesRegex(proof.ProofError, 'Restore valid A'):
            proof.observe(self.config, state, rejected=True)
        self.objects['application.argoproj.io', proof.NAME, 'argocd']['spec']['sources'][1]['targetRevision'] = 'e' * 40
        desired = proof.declarations(self.config, state, self.public, self.root_files)
        with self.assertRaises(proof.ProofError): proof.child(self.config, state, desired, 'A', True)

    def test_receipt_rejection_requires_native_gate_error_not_unrelated_auth_or_network_failure(self):
        state = self.begin()
        parent = self.objects['applicationset.argoproj.io', proof.NAME, 'argocd']
        for available in (True, False):
            if not available:
                parent['status']['conditions'] = [{'type': 'ParametersGenerated', 'status': 'True'}]
                proof.observe(self.config, state)
                state = proof.change(self.config, state, available=False)['state']
                parent = self.objects['applicationset.argoproj.io', proof.NAME, 'argocd']
            for message in ('repository authentication failed', 'network unavailable', 'Private source acceptance refused'):
                with self.subTest(source_available=available, message=message):
                    parent['status']['conditions'] = [{'type': 'ErrorOccurred', 'status': 'True', 'message': message}]
                    candidate = copy.deepcopy(state)
                    def once(check, **kwargs):
                        if not check(): raise proof.ProofError('synthetic observation did not qualify')
                    with patch.object(proof, 'poll', side_effect=once):
                        if (message == 'Private source acceptance refused') == available:
                            result = proof.observe(self.config, candidate, rejected=True)
                            self.assertTrue(result['parent_error_retains_child'])
                            self.assertNotIn(message, json.dumps(result))
                        else:
                            with self.assertRaisesRegex(proof.ProofError, 'did not qualify'):
                                proof.observe(self.config, candidate, rejected=True)
                            self.assertEqual(candidate['lastObservation'], state['lastObservation'])

    def test_nonce_patch_simulated_repair_and_compensation_are_distinguished(self):
        state = self.begin(); self.repair = True
        result = proof.drift(self.config, state)
        self.assertTrue(result['self_heal_verified']); self.assertFalse(result['cleanup_restored'])
        self.repair = False
        def timeout(check, **kwargs):
            self.assertFalse(check()); raise proof.ProofError('synthetic timeout')
        with patch.object(proof, 'poll', side_effect=timeout): result = proof.drift(self.config, state)
        self.assertFalse(result['self_heal_verified']); self.assertTrue(result['cleanup_restored'])
        self.assertEqual(proof.read('Marker')['data'], {'revision': self.config['receiptA']['revision']})
        patches = [data for args, data in self.writes if args[:2] == ('patch', 'configmap')]
        self.assertTrue(all([row['path'] for row in patch[:3]] == ['/metadata/uid', '/metadata/resourceVersion', '/data'] for patch in patches))

    def test_foreign_scope_data_or_list_failure_blocks_cleanup_before_any_delete(self):
        for case in ('extra-object', 'list-denied', 'data', 'binary', 'finalizer', 'uid', 'credential-owner'):
            self.setUp()
            with self.subTest(case=case):
                state = self.begin(); self.writes.clear()
                if case == 'extra-object': self.objects['widget', 'foreign', proof.NAME] = {'kind': 'Widget', 'metadata': {'name': 'foreign', 'namespace': proof.NAME, 'uid': 'foreign'}}
                if case == 'list-denied': self.fail_list = True
                if case == 'data': self.objects['configmap', 'retained-data', proof.NAME]['data'] = {'foreign': 'retained'}
                if case == 'binary': self.objects['configmap', 'retained-data', proof.NAME]['binaryData'] = {'foreign': 'YQ=='}
                if case == 'finalizer': self.objects['externalsecret.external-secrets.io', proof.NAME + '-source', 'argocd']['metadata']['finalizers'].append('foreign')
                if case == 'uid': self.objects['configmap', 'retained-data', proof.NAME]['metadata']['uid'] = 'foreign'
                if case == 'credential-owner': self.objects['secret', proof.NAME + '-source', 'argocd']['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                with self.assertRaises(proof.ProofError): proof.cleanup(self.config, state)
                self.assertFalse(any(args[0] == 'delete' for args, _ in self.writes))

    def test_preexisting_objects_and_marker_uid_race_never_receive_a_write(self):
        self.objects['namespace', proof.NAME, None] = {'metadata': {'uid': 'foreign'}}
        with self.assertRaises(proof.ProofError): proof.create(self.config)
        self.assertEqual(self.writes, [])
        self.objects.pop(('namespace', proof.NAME, None)); state = self.begin(); self.writes.clear()
        marker = proof.read('Marker'); marker['metadata']['uid'] = 'foreign'
        with self.assertRaises(proof.ProofError): proof.marker_patch(marker, {'revision': 'nonce'}, self.config, state, marker['data'])
        self.assertEqual(self.writes, [])

    def test_partial_creation_returns_scope_for_safe_cleanup_or_exact_attempt_resume(self):
        kube = self.kube
        def fail_eso(*args, document=None, **kwargs):
            if args[0] == 'create' and document['kind'] == 'ExternalSecret': raise proof.ProofError('synthetic ESO failure')
            return kube(*args, document=document, **kwargs)
        with patch.object(proof, 'kube', side_effect=fail_eso): result = proof.create(self.config)
        self.assertFalse(result['created']); self.assertEqual(set(result['state']['identities']), {'Namespace', 'Project'})
        failed = proof.failure_result({'action': 'cleanup', 'config': self.config, 'state': result['state']},
            proof.ProofError('Namespace defaults are not captured; cleanup retained'))
        self.assertEqual(failed['state'], result['state']); self.assertEqual(failed['operation'], 'cleanup')
        hidden = proof.failure_result({'action': 'cleanup', 'config': self.config, 'state': result['state']}, RuntimeError('private-value-must-not-escape'))
        self.assertNotIn('private-value-must-not-escape', json.dumps(hidden)); self.assertNotIn(self.config['privateRepository'], json.dumps(hidden))
        self.assertTrue(proof.cleanup(self.config, result['state'])['cleanup_complete'])
        self.setUp(); kube = self.kube
        def uncertain_eso(*args, document=None, **kwargs):
            response = kube(*args, document=document, **kwargs)
            if args[0] == 'create' and document['kind'] == 'ExternalSecret': raise proof.ProofError('synthetic lost response')
            return response
        with patch.object(proof, 'kube', side_effect=uncertain_eso): result = proof.create(self.config)
        before = result['state']['identities'].copy()
        resumed = proof.resume_create(self.config, result['state'])
        self.assertTrue(resumed['created'])
        self.assertEqual({key: resumed['state']['identities'][key] for key in before}, before)
        self.assertEqual(resumed['state']['identities']['ExternalSecret'], proof.read('ExternalSecret')['metadata']['uid'])
        self.setUp(); kube = self.kube
        def broaden_project(*args, document=None, **kwargs):
            response = kube(*args, document=document, **kwargs)
            if args[0] == 'create' and document['kind'] == 'AppProject':
                obj = json.loads(response); obj['spec']['sourceRepos'] = ['*']
                self.objects['appproject.argoproj.io', proof.NAME, 'argocd'] = obj
                return json.dumps(obj)
            return response
        with patch.object(proof, 'kube', side_effect=broaden_project): result = proof.create(self.config)
        self.assertFalse(result['created']); self.assertIn('Project', result['state']['identities'])
        self.assertFalse(any(data.get('kind') == 'ApplicationSet' for args, data in self.writes if args[0] == 'create'))

    def test_replaced_trusted_authority_is_never_owned_cleanup_scope(self):
        state = self.begin(); self.writes.clear()
        self.assertEqual(set(state['authority']), {'Root', 'ApplicationSetController'})
        self.assertFalse(set(state['authority']) & set(state['identities']))
        self.objects['deployment', 'argocd-applicationset-controller', 'argocd']['metadata']['uid'] = 'replacement'
        with self.assertRaisesRegex(proof.ProofError, 'was replaced'): proof.change(self.config, state, approval='B')
        with self.assertRaisesRegex(proof.ProofError, 'was replaced'): proof.cleanup(self.config, state)
        self.assertEqual(self.writes, [])

    def test_fixture_consumes_complete_private_values_without_rendering_catalog_details(self):
        values = {'sources': [{'name': 'private', 'repository': self.config['privateRepository'], 'revision': 'main', 'path': 'gitops/private'}],
            'acceptedRevision': self.config['receiptA']['revision'], 'proofAttempt': self.config['attempt']}
        command = ['helm', 'template', 'proof', str(ROOT / proof.CHART), '-n', proof.NAME, '-f', '-']
        result = subprocess.run(command, input=json.dumps(values), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr); self.assertNotIn(self.config['privateRepository'], result.stdout)
        self.assertIn(self.config['receiptA']['revision'], result.stdout)
        values.pop('sources')
        result = subprocess.run(command, input=json.dumps(values), capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)

    def test_published_artifact_and_controller_policy_are_checked_before_creation(self):
        root = {'metadata': {'uid': 'root'}, 'spec': {'project': 'cloudlab-root', 'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}, 'source': {'repoURL': proof.PUBLIC, 'targetRevision': 'main',
            'path': 'gitops/roots/public', 'helm': {'valuesObject': {'identity': {'argo': {'valuesRepository': self.config['privateRepository'], 'valuesRevision': 'a' * 40}}}}}},
            'status': {'sync': {'status': 'Synced', 'revision': self.config['publicRevision']}, 'health': {'status': 'Healthy'}}}
        artifacts = files('platform/delivery/argocd'); lock = json.loads(artifacts['artifact.lock.json'])
        raw = artifacts['artifact.lock.json']
        lock_file = {'type': 'file', 'path': 'platform/delivery/argocd/artifact.lock.json', 'encoding': 'base64',
            'content': base64.b64encode(raw).decode(), 'size': len(raw), 'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
        image = next(name + '@' + digest for name, digest in lock['images'].items() if name.startswith('quay.io/argoproj/argocd:'))
        controller = {'metadata': {'uid': 'controller', 'generation': 1}, 'spec': {'replicas': 1, 'template': {'spec': {'containers': [{'image': image,
            'args': ['--policy=create-update', '--enable-policy-override=false']}]}}}, 'status': {'availableReplicas': 1, 'observedGeneration': 1}}
        self.context_patch.stop()
        with patch.object(proof.native, 'published_source', return_value=(self.public, self.config['publicRevision'])), \
                patch.object(proof.native.source_snapshot, 'chart_files', side_effect=lambda source, **kwargs: artifacts if source['path'] == 'platform/delivery/argocd' else self.root_files if source['path'] == 'gitops/roots/public' else self.fixture_files), \
                patch.object(proof.native.source_snapshot, 'request', return_value=lock_file) as request, \
                patch.object(proof, 'get', side_effect=lambda kind, *args: controller if kind == 'deployment' else root):
            proof.context(self.config)
            self.assertTrue(request.call_args.args[0].endswith('artifact.lock.json?ref=' + self.config['publicRevision']))
            lock_file['sha'] = '0' * 40
            with self.assertRaisesRegex(proof.ProofError, 'blob integrity'): proof.context(self.config)
            lock_file['sha'] = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            controller['spec']['template']['spec']['containers'][0]['args'][-1] = '--enable-policy-override=true'
            with self.assertRaises(proof.ProofError): proof.context(self.config)
        self.assertEqual(self.writes, [])
