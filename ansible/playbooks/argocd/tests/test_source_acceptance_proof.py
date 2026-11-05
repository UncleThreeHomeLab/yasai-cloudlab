"""Offline fixed-scope proof procedure tests; these do not qualify a controller."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
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
        self.profile = proof.REGISTRY_PROFILE
        self.config = {'version': proof.VERSION, 'attempt': '1' * 32, 'publicRevision': 'f' * 40,
            'privateRepository': 'https://github.com/example/private.git', 'privateBranch': 'proof/prices-source-' + '2' * 32,
            'receiptA': {'version': 'cloudlab-private-source-acceptance/v1', 'consumer': 'private-sources', 'revision': 'a' * 40, 'nonce': 'c' * 64},
            'receiptB': {'version': 'cloudlab-private-source-acceptance/v1', 'consumer': 'private-sources', 'revision': 'b' * 40, 'nonce': 'd' * 64}}
        self.objects = {('configmap', 'kube-root-ca.crt', 'argocd'): {'data': {'ca.crt': 'public-root'}},
            ('application.argoproj.io', 'cloudlab-public-root', 'argocd'): {'metadata': {'uid': 'root-authority'}},
            ('deployment', 'argocd-applicationset-controller', 'argocd'): {'metadata': {'uid': 'controller-authority'}}}
        self.writes = []; self.version = 0; self.repair = False
        for name, data in (('istio-ca-root-cert', {'root-cert.pem': 'synthetic-root'}), ('istio-ca-crl', {'ca-crl.pem': ''})):
            self.stored({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': name, 'namespace': 'argocd',
                'labels': {'istio.io/config': 'true'}}, 'data': data})
        self.fail_list = False
        self.context_patch = patch.object(proof, 'context', side_effect=lambda config, state=None, **kwargs: (
            proof.config_guard(config, state, **kwargs) or self.public, self.root_files, self.fixture_files,
            {'Root': 'root-authority', 'ApplicationSetController': 'controller-authority'}))
        self.context_patch.start(); self.addCleanup(self.context_patch.stop)
        get = patch.object(proof, 'get', side_effect=self.get); get.start(); self.addCleanup(get.stop)
        kube = patch.object(proof, 'kube', side_effect=self.kube); kube.start(); self.addCleanup(kube.stop)

    def call(self, function, *args, **kwargs):
        return function(*args, **kwargs, profile=self.profile)

    def select_consumer(self, consumer):
        fixed = proof.CONSUMER_PROFILES[consumer]
        self.config.update(version=proof.CONSUMER_VERSION, consumer=consumer,
            privateBranch='proof/prices-consumers-' + self.config['attempt'])
        paths = ['services/catalog-source-proof.yaml', 'platform/observability.yaml'] if consumer == 'observability' else ['platform/permissions.yaml']
        for approval in ('A', 'B'):
            self.config['receipt' + approval].update(version='cloudlab-consumer-source-acceptance/v1', consumer=consumer, paths=paths.copy())
        self.profile = dict(fixed, peer={'snapshot': proof.peer_snapshot(fixed), 'cleanup': False})
        self.fixture_files = files(self.profile['chart'])

    def bundle(self, approval):
        if self.profile['consumer'] is None: return {'sources': []}
        if self.profile['consumer'] == 'observability':
            return {'consumer': 'observability', 'catalog': [], 'dataApprovals': {}, 'observabilityProof': {'marker': approval}}
        return {'consumer': 'permissions', 'permissionsProof': {'marker': approval}}

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
            return json.dumps({'items': [row for (kind, name, ns), row in self.objects.items() if kind == kinds[args[1]] and ns == self.profile['name']]})
        self.writes.append((args, copy.deepcopy(document)))
        if args[0] == 'create':
            result = self.stored(document)
            if document['kind'] == 'Namespace':
                self.objects['namespace', self.profile['name'], None]['spec'] = {'finalizers': ['kubernetes']}
                self.stored({'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'name': 'default', 'namespace': self.profile['name']}})
                self.stored({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'kube-root-ca.crt', 'namespace': self.profile['name']}, 'data': {'ca.crt': 'public-root'}})
                for name in ('istio-ca-root-cert', 'istio-ca-crl'):
                    reference = copy.deepcopy(self.objects['configmap', name, 'argocd'])
                    reference['metadata'].pop('uid'); reference['metadata']['namespace'] = self.profile['name']
                    self.stored(reference)
            return json.dumps(result)
        if args[0] == 'patch':
            resource = 'configmap' if args[1] == 'configmap' else 'applicationset.argoproj.io'
            namespace = self.profile['name'] if resource == 'configmap' else 'argocd'
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
            key = next(key for key, (_, name, _, prefix) in self.profile['resources'].items() if prefix + name == path)
            resource, name, namespace, _ = self.profile['resources'][key]
            obj = self.objects[resource, name, namespace]
            self.assertEqual(document['preconditions'], {'uid': obj['metadata']['uid'], 'resourceVersion': obj['metadata']['resourceVersion']})
            del self.objects[resource, name, namespace]
            for row in self.objects.values():
                if any(owner.get('uid') == obj['metadata']['uid'] for owner in row.get('metadata', {}).get('ownerReferences', [])):
                    row['metadata'].pop('ownerReferences')
            if key == 'Namespace':
                self.objects = {key: value for key, value in self.objects.items() if key[2] != self.profile['name']}
            return '{}'
        raise AssertionError('Unexpected proof command')

    def credentials(self, state):
        external = self.objects['externalsecret.external-secrets.io', self.profile['name'] + '-source', 'argocd']
        external['metadata']['finalizers'] = [proof.native.ESO_FINALIZER]
        external['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
        data = {'type': 'git', 'url': self.config['privateRepository'], 'project': self.profile['name'],
            'githubAppID': '1', 'githubAppInstallationID': '2', 'githubAppPrivateKey': 'synthetic'}
        self.stored({'apiVersion': 'v1', 'kind': 'Secret', 'type': 'Opaque', 'metadata': {'name': self.profile['name'] + '-source', 'namespace': 'argocd',
            'labels': {'cloudlab.io/owner': proof.OWNER, 'cloudlab.io/proof-attempt': self.config['attempt'], 'argocd.argoproj.io/secret-type': 'repository',
                'reconcile.external-secrets.io/managed': 'true',
                'reconcile.external-secrets.io/created-by': hashlib.sha3_224(('argocd/' + self.profile['name'] + '-source').encode()).hexdigest()},
            'ownerReferences': [{'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'name': self.profile['name'] + '-source',
                'uid': state['identities']['ExternalSecret'], 'controller': True, 'blockOwnerDeletion': True}]},
            'data': {key: base64.b64encode(value.encode()).decode() for key, value in data.items()}})
    def begin(self):
        state = self.call(proof.create, self.config)['state']
        self.credentials(state)
        def healthy(check, **kwargs):
            self.converge(state)
            self.assertTrue(check())
        with patch.object(proof, 'poll', side_effect=healthy):
            result = self.call(proof.seed, self.config, state)
        self.assertTrue(result['seed_healthy'], result)
        state = self.call(proof.adopt, self.config, result['state'])['state']
        self.converge(state)
        return self.call(proof.observe, self.config, state)['state']

    def converge(self, state):
        desired = self.call(proof.declarations, self.config, state, self.public, self.root_files)
        metadata = desired['ApplicationSet']['spec']['template']['metadata']
        existing = self.objects.get(('application.argoproj.io', self.profile['name'], 'argocd'))
        metadata = copy.deepcopy(metadata)
        if existing: metadata['uid'] = existing['metadata']['uid']
        if 'ApplicationSet' in state['identities']:
            metadata['ownerReferences'] = [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': self.profile['name'],
                'uid': state['identities']['ApplicationSet'], 'controller': True, 'blockOwnerDeletion': True}]
        self.stored({'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': metadata,
            'spec': self.call(proof.child_spec, self.config, state, desired, state['approval'], state['markerEnabled']),
            'status': {'sync': {'status': 'Synced', 'revisions': [self.config['publicRevision'], self.config['receipt' + state['approval']]['revision']]},
                'health': {'status': 'Healthy'}}})
        values = dict(self.bundle(state['approval']), proofAttempt=self.config['attempt'], acceptedRevision=self.config['receipt' + state['approval']]['revision'], markerEnabled=state['markerEnabled'])
        result = subprocess.run(['helm', 'template', 'proof', str(ROOT / self.profile['chart']), '-n', self.profile['name'], '-f', '-'], input=json.dumps(values), capture_output=True, text=True, timeout=30, check=True)
        rendered = [row for row in yaml.safe_load_all(result.stdout) if row]
        for row in rendered:
            old = self.objects.get(('configmap', row['metadata']['name'], self.profile['name']))
            if old: row['metadata']['uid'] = old['metadata']['uid']
            row['metadata'].setdefault('annotations', {})['argocd.argoproj.io/tracking-id'] = self.profile['name'] + ':/ConfigMap:' + self.profile['name'] + '/' + row['metadata']['name']
            self.stored(row)
        if not state['markerEnabled']: self.objects.pop(('configmap', 'approval-marker', self.profile['name']), None)
        if 'ApplicationSet' in state['identities']:
            self.objects['applicationset.argoproj.io', self.profile['name'], 'argocd']['status'] = {'conditions': [{'type': 'ParametersGenerated', 'status': 'True'}, {'type': 'ErrorOccurred', 'status': 'False'}]}

    def test_fixed_fixture_b_updates_and_marker_removal_preserve_captured_sentinel(self):
        state = self.begin(); before = state['identities'].copy()
        state = self.call(proof.change, self.config, state, approval='B')['state']; self.converge(state)
        state = self.call(proof.observe, self.config, state)['state']
        self.assertEqual(state['identities'], before)
        state = self.call(proof.change, self.config, state, marker=False)['state']; self.converge(state)
        state = self.call(proof.observe, self.config, state)['state']
        self.assertIsNone(self.call(proof.read, 'Marker')); self.assertEqual(self.call(proof.read, 'Retained')['data'], proof.RETAINED)
        self.assertEqual(self.call(proof.read, 'Retained')['metadata']['uid'], before['Retained'])
        self.assertTrue(self.call(proof.cleanup, self.config, state)['cleanup_complete'])

    def test_consumer_profiles_same_uid_adoption_advance_removal_and_exact_cleanup(self):
        for consumer in ('observability', 'permissions'):
            with self.subTest(consumer=consumer):
                self.select_consumer(consumer)
                state = self.begin(); before = state['identities'].copy()
                self.assertEqual(state['consumer'], consumer)
                state = proof.main({'action': 'approve-b', 'config': self.config, 'state': state})['state']
                self.converge(state)
                state = proof.main({'action': 'accept', 'config': self.config, 'state': state})['state']
                self.assertEqual(state['identities'], before)
                self.repair = True
                # Drift must repair to B, not a compensation patch or manual sync.
                original_get = self.get
                def repair_b(kind, name=None, namespace=None):
                    obj = self.objects.get((kind, name, namespace))
                    if kind == 'configmap' and name == 'approval-marker' and obj and obj['data']['revision'].startswith('source-proof-drift-'):
                        obj['data'] = {'revision': self.config['receiptB']['revision']}
                    return original_get(kind, name, namespace)
                with patch.object(proof, 'get', side_effect=repair_b):
                    self.assertTrue(proof.main({'action': 'drift', 'config': self.config, 'state': state})['self_heal_verified'])
                state = proof.main({'action': 'remove-marker', 'config': self.config, 'state': state})['state']
                self.converge(state)
                state = proof.main({'action': 'accept', 'config': self.config, 'state': state})['state']
                self.assertEqual(self.call(proof.read, 'Retained')['metadata']['uid'], before['Retained'])
                self.assertTrue(proof.main({'action': 'cleanup', 'config': self.config, 'state': state})['cleanup_complete'])

    def test_consumer_gate_uses_structured_receipt_and_single_accepted_values_source(self):
        for consumer in ('observability', 'permissions'):
            self.select_consumer(consumer)
            state = self.call(proof.create, self.config)['state']
            parent = self.call(proof.declarations, self.config, state, self.public, self.root_files)['ApplicationSet']['spec']
            self.assertEqual(parent['generators'][0]['merge']['mergeKeys'], ['consumer'])
            generators = parent['generators'][0]['merge']['generators']
            self.assertEqual(generators[0]['list']['elements'], [{'consumer': consumer}])
            self.assertEqual(generators[1]['git']['files'], [{'path': 'platform/acceptance/' + consumer + '.yaml'}])
            sources = parent['template']['spec']['sources']
            self.assertEqual(len(sources), 2)
            self.assertEqual(sources[1]['ref'], 'values')
            self.assertEqual(sources[0]['helm']['valueFiles'], ['$values/' + path for path in self.config['receiptA']['paths']])
            gate = sources[1]['targetRevision']
            self.assertEqual(sources[0]['helm']['parameters'][0]['value'], gate)
            params = dict(self.config['receiptA'], path={'path': 'platform/acceptance', 'basename': 'acceptance',
                'basenameNormalized': 'acceptance', 'filename': consumer + '.yaml', 'filenameNormalized': consumer + '.yaml',
                'segments': ['platform', 'acceptance']})
            with tempfile.TemporaryDirectory() as directory:
                chart = Path(directory); (chart / 'templates').mkdir()
                (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: consumer-gate-proof\nversion: 1.0.0\n')
                (chart / 'templates/gate.yaml').write_text('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: proof}\ndata:\n  revision: {{ tpl .Values.gate .Values.params | quote }}\n')
                for case in ('valid', 'missing', 'consumer', 'paths', 'mixed-sha', 'replay'):
                    candidate = copy.deepcopy(params)
                    if case == 'missing': candidate = {'consumer': consumer}
                    if case == 'consumer': candidate['consumer'] = 'permissions' if consumer == 'observability' else 'observability'
                    if case == 'paths': candidate['paths'] = list(reversed(candidate['paths'])) if consumer == 'observability' else ['platform/observability.yaml']
                    if case == 'mixed-sha': candidate['revisions'] = ['a' * 40, 'b' * 40]
                    if case == 'replay': candidate.update(self.config['receiptB'])
                    result = subprocess.run(['helm', 'template', 'proof', str(chart), '-f', '-'], input=json.dumps({'gate': gate, 'params': candidate}),
                        capture_output=True, text=True, timeout=30)
                    if case == 'valid':
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(yaml.safe_load(result.stdout)['data']['revision'], self.config['receiptA']['revision'])
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('Consumer source acceptance refused', result.stderr)
            # Avoid crossing attempts/scopes in the next loop's preexisting guard.
            self.objects = {key: value for key, value in self.objects.items() if key[1] not in (self.profile['name'], self.profile['name'] + '-source') and key[2] != self.profile['name']}

    def test_consumer_rejection_matcher_distinguishes_gate_and_source_outage(self):
        for consumer in ('observability', 'permissions'):
            self.select_consumer(consumer); state = self.begin()
            parent = self.objects['applicationset.argoproj.io', self.profile['name'], 'argocd']
            for available in (True, False):
                if not available:
                    state = self.call(proof.change, self.config, state, available=False)['state']
                    parent = self.objects['applicationset.argoproj.io', self.profile['name'], 'argocd']
                for message in ('Consumer source acceptance refused', 'Private source acceptance refused', 'repository authentication failed'):
                    parent['status']['conditions'] = [{'type': 'ErrorOccurred', 'status': 'True', 'message': message}]
                    def once(check, **kwargs):
                        if not check(): raise proof.ProofError('synthetic case not qualified')
                    with patch.object(proof, 'poll', side_effect=once):
                        candidate = copy.deepcopy(state)
                        if (message == 'Consumer source acceptance refused') == available:
                            self.assertTrue(self.call(proof.observe, self.config, candidate, rejected=True)['parent_error_retains_child'])
                        else:
                            with self.assertRaisesRegex(proof.ProofError, 'not qualified'):
                                self.call(proof.observe, self.config, candidate, rejected=True)

    def test_consumer_peer_snapshot_preserves_absence_and_exact_other_scope(self):
        self.select_consumer('observability')
        state = self.begin()
        permissions = proof.CONSUMER_PROFILES['permissions']
        # An object appearing after capture is not an accepted unchanged peer.
        self.stored({'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {'name': 'retained-data', 'namespace': permissions['name']}, 'data': proof.RETAINED})
        self.writes.clear()
        with self.assertRaisesRegex(proof.ProofError, 'Other consumer resource changed'):
            self.call(proof.change, self.config, state, approval='B')
        self.assertEqual(self.writes, [])
        self.select_consumer('observability')
        for case in ('uid', 'data', 'disappear'):
            snapshot = proof.peer_snapshot(self.profile)
            peer = self.objects['configmap', 'retained-data', permissions['name']]
            saved = copy.deepcopy(peer)
            if case == 'uid': peer['metadata']['uid'] = 'foreign-replacement'
            if case == 'data': peer['data'] = {'sentinel': 'changed'}
            if case == 'disappear': del self.objects['configmap', 'retained-data', permissions['name']]
            with self.assertRaisesRegex(proof.ProofError, 'Other consumer resource changed'):
                proof.peer_guard(dict(self.profile, peer={'snapshot': snapshot}))
            self.objects['configmap', 'retained-data', permissions['name']] = saved

    def test_consumers_advance_independently_with_both_scopes_present(self):
        self.select_consumer('observability'); observability = self.begin()
        self.select_consumer('permissions'); permissions = self.begin()
        self.select_consumer('observability'); other = proof.peer_snapshot(self.profile)
        observability = proof.main({'action': 'approve-b', 'config': self.config, 'state': observability})['state']
        self.converge(observability)
        observability = proof.main({'action': 'accept', 'config': self.config, 'state': observability})['state']
        self.assertEqual(proof.peer_snapshot(self.profile), other)
        self.select_consumer('permissions'); other = proof.peer_snapshot(self.profile)
        permissions = proof.main({'action': 'approve-b', 'config': self.config, 'state': permissions})['state']
        self.converge(permissions)
        permissions = proof.main({'action': 'accept', 'config': self.config, 'state': permissions})['state']
        self.assertEqual(proof.peer_snapshot(self.profile), other)
        proof.main({'action': 'cleanup', 'config': self.config, 'state': permissions})
        self.select_consumer('observability')
        proof.main({'action': 'cleanup', 'config': self.config, 'state': observability})

    def test_consumer_fixture_requires_complete_bundle_without_rendering_private_documents(self):
        for consumer in ('observability', 'permissions'):
            self.select_consumer(consumer)
            values = dict(self.bundle('A'), acceptedRevision='a' * 40, proofAttempt='1' * 32)
            command = ['helm', 'template', 'proof', str(ROOT / self.profile['chart']), '-n', self.profile['name'], '-f', '-']
            result = subprocess.run(command, input=json.dumps(values), capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({row['metadata']['name'] for row in yaml.safe_load_all(result.stdout)}, {'approval-marker', 'retained-data'})
            self.assertNotIn('observabilityProof', result.stdout); self.assertNotIn('permissionsProof', result.stdout)
            for key in ('catalog', 'dataApprovals', 'observabilityProof') if consumer == 'observability' else ('permissionsProof',):
                missing = copy.deepcopy(values); missing.pop(key)
                result = subprocess.run(command, input=json.dumps(missing), capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)

    def test_consumer_scope_envelopes_and_cleanup_fail_before_writes(self):
        self.select_consumer('observability'); state = self.begin()
        self.writes.clear()
        for case in ('consumer', 'version', 'identity', 'paths', 'branch'):
            config, candidate = copy.deepcopy(self.config), copy.deepcopy(state)
            if case == 'consumer': candidate['consumer'] = 'permissions'
            if case == 'version': config['version'] = proof.VERSION
            if case == 'identity': candidate['identities']['foreign'] = 'invented'
            if case == 'paths': config['receiptA']['paths'] = ['platform/permissions.yaml']
            if case == 'branch': config['privateBranch'] += '-foreign'
            with self.assertRaises((proof.ProofError, ValueError)):
                proof.main({'action': 'cleanup', 'config': config, 'state': candidate})
            self.assertEqual(self.writes, [])
        self.objects['widget', 'foreign', self.profile['name']] = {'metadata': {'name': 'foreign', 'uid': 'foreign'}}
        with self.assertRaisesRegex(proof.ProofError, 'Unexpected namespace resource'):
            proof.main({'action': 'cleanup', 'config': self.config, 'state': state})
        self.assertEqual(self.writes, [])

    def test_consumer_quota_reserves_cleanup_before_public_metadata_or_writes(self):
        self.select_consumer('permissions'); self.context_patch.stop()
        with patch.object(proof.native.source_snapshot, 'request', return_value={'resources': {'core': {'remaining': 11}}}) as request, \
                patch.object(proof.native, 'published_source') as published:
            with self.assertRaisesRegex(proof.ProofError, 'budget reserved'):
                self.call(proof.create, self.config)
            self.assertEqual(request.call_args.args[0], 'rate_limit')
            published.assert_not_called(); self.assertEqual(self.writes, [])

    def test_consumer_interrupted_seed_parent_and_pending_cleanup_use_same_guards(self):
        for consumer in ('observability', 'permissions'):
            self.select_consumer(consumer)
            self.check_seed_and_parent_lost_responses()
            state = self.call(proof.observe, self.config, self.recovered_state)['state']
            self.assertTrue(proof.main({'action': 'cleanup', 'config': self.config, 'state': state})['cleanup_complete'])
            self.check_pending_ownerless_adoption_cleanup()
        self.assertIsNone(self.call(proof.read, 'Namespace'))

    def test_ownerless_seed_is_healthy_before_parent_and_same_uid_adoption_is_required(self):
        self.assertNotIn(proof.TRACKING_OWNER, (self.profile['name'], 'cloudlab-public-root'))
        self.objects['application.argoproj.io', proof.TRACKING_OWNER, 'argocd'] = {'metadata': {'uid': 'foreign-tracking-owner'}}
        with self.assertRaisesRegex(proof.ProofError, 'synthetic tracking owner'): self.call(proof.create, self.config)
        self.assertEqual(self.writes, [])
        del self.objects['application.argoproj.io', proof.TRACKING_OWNER, 'argocd']
        state = self.call(proof.create, self.config)['state']; self.credentials(state)
        self.assertEqual(state['adoptionPhase'], 'seed-intent')
        self.assertIsNone(self.call(proof.read, 'ApplicationSet')); self.assertIsNone(self.call(proof.read, 'Application'))
        with self.assertRaises(proof.ProofError): self.call(proof.adopt, self.config, state)
        def healthy(check, **kwargs):
            self.assertIsNone(self.call(proof.read, 'ApplicationSet'))
            self.converge(state)
            self.assertFalse(self.call(proof.read, 'Application')['metadata'].get('ownerReferences'))
            self.assertEqual(self.call(proof.read, 'Application')['metadata']['annotations']['argocd.argoproj.io/tracking-id'],
                proof.TRACKING_OWNER + ':argoproj.io/Application:argocd/' + self.profile['name'])
            self.assertTrue(check())
        with patch.object(proof, 'poll', side_effect=healthy): result = self.call(proof.seed, self.config, state)
        self.assertTrue(result['seed_healthy'], result)
        before = state['identities'].copy()
        self.assertTrue({'Application', 'Marker', 'Retained'} <= set(before))
        for key in ('IstioRoot', 'IstioCRL'):
            incomplete = copy.deepcopy(state); incomplete['identities'].pop(key)
            self.writes.clear()
            with self.assertRaisesRegex(proof.ProofError, 'previously observed seed identity'):
                self.call(proof.adopt, self.config, incomplete)
            self.assertEqual(self.writes, [])
        state = self.call(proof.adopt, self.config, state)['state']
        desired = self.call(proof.declarations, self.config, state, self.public, self.root_files)
        self.assertFalse(self.call(proof.child, self.config, state, desired, 'A', True))
        self.converge(state)
        state = self.call(proof.observe, self.config, state)['state']
        self.assertEqual(state['adoptionPhase'], 'adopted')
        self.assertEqual({key: state['identities'][key] for key in before}, before)
        for key in ('Application', 'Marker', 'Retained', 'IstioRoot', 'IstioCRL'):
            incomplete = copy.deepcopy(state); incomplete['identities'].pop(key)
            with self.assertRaisesRegex(proof.ProofError, 'previously observed seed identity'):
                self.call(proof.observe, self.config, incomplete)
        original = copy.deepcopy(self.objects)
        for case in ('ownerless', 'replacement', 'foreign-owner', 'protection'):
            self.objects = copy.deepcopy(original); self.writes.clear()
            app = self.objects['application.argoproj.io', self.profile['name'], 'argocd']
            if case == 'ownerless': app['metadata'].pop('ownerReferences')
            if case == 'replacement': app['metadata']['uid'] = 'replacement'
            if case == 'foreign-owner': app['metadata']['ownerReferences'][0]['uid'] = 'foreign'
            if case == 'protection': app['metadata']['annotations'].pop('argocd.argoproj.io/sync-options')
            with self.subTest(case=case):
                with self.assertRaises(proof.ProofError): self.call(proof.observe, self.config, copy.deepcopy(state))
                with self.assertRaises(proof.ProofError): self.call(proof.cleanup, self.config, copy.deepcopy(state))
                self.assertEqual(self.writes, [])

    def test_seed_and_parent_lost_responses_recover_only_recorded_exact_attempt(self):
        self.check_seed_and_parent_lost_responses()

    def check_seed_and_parent_lost_responses(self):
        state = self.call(proof.create, self.config)['state']; self.credentials(state)
        kube = self.kube
        def lost_child(*args, document=None, **kwargs):
            response = kube(*args, document=document, **kwargs)
            if args[0] == 'create' and document['kind'] == 'Application': raise RuntimeError('lost response')
            return response
        with patch.object(proof, 'kube', side_effect=lost_child): result = self.call(proof.seed, self.config, state)
        self.assertFalse(result['seed_healthy']); self.assertEqual(state['adoptionPhase'], 'seed-intent')
        uid = self.call(proof.read, 'Application')['metadata']['uid']; self.writes.clear()
        def healthy(check, **kwargs):
            self.converge(state); self.assertTrue(check())
        with patch.object(proof, 'poll', side_effect=healthy): result = self.call(proof.seed, self.config, state)
        self.assertTrue(result['seed_healthy'], result); self.assertEqual(state['identities']['Application'], uid)
        self.assertEqual(self.writes, [])
        def lost_parent(*args, document=None, **kwargs):
            response = kube(*args, document=document, **kwargs)
            if args[0] == 'create' and document['kind'] == 'ApplicationSet': raise RuntimeError('lost response')
            return response
        with patch.object(proof, 'kube', side_effect=lost_parent), self.assertRaises(RuntimeError): self.call(proof.adopt, self.config, state)
        self.assertNotIn('ApplicationSet', state['identities']); self.writes.clear()
        state = self.call(proof.adopt, self.config, state)['state']
        self.assertEqual(self.writes, []); self.converge(state)
        self.assertTrue(self.call(proof.observe, self.config, state)['accepted'])
        self.recovered_state = state

    def test_seed_refuses_foreign_child_or_scope_without_creating_parent(self):
        state = self.call(proof.create, self.config)['state']; self.credentials(state)
        desired = self.call(proof.declarations, self.config, state, self.public, self.root_files)
        app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
            'metadata': desired['ApplicationSet']['spec']['template']['metadata'],
            'spec': self.call(proof.child_spec, self.config, state, desired, 'A', True)}
        baseline = copy.deepcopy(self.objects)
        for case in ('attempt', 'spec', 'owner', 'annotation'):
            self.objects = copy.deepcopy(baseline); obj = copy.deepcopy(app)
            if case == 'attempt': obj['metadata']['labels']['cloudlab.io/proof-attempt'] = '9' * 32
            if case == 'spec': obj['spec']['destination']['namespace'] = 'foreign'
            if case == 'owner': obj['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
            if case == 'annotation': obj['metadata']['annotations']['foreign'] = 'true'
            self.stored(obj); self.writes.clear()
            with self.subTest(case=case):
                result = self.call(proof.seed, self.config, copy.deepcopy(state))
                self.assertFalse(result['seed_healthy']); self.assertEqual(self.writes, [])
                self.assertIsNone(self.call(proof.read, 'ApplicationSet'))

    def test_pending_ownerless_adoption_cleanup_after_parent_create_or_lost_response(self):
        self.check_pending_ownerless_adoption_cleanup()

    def check_pending_ownerless_adoption_cleanup(self):
        state = self.call(proof.create, self.config)['state']; self.credentials(state)
        def healthy(check, **kwargs):
            self.converge(state); self.assertTrue(check())
        with patch.object(proof, 'poll', side_effect=healthy):
            self.assertTrue(self.call(proof.seed, self.config, state)['seed_healthy'])
        baseline, seed_state = copy.deepcopy(self.objects), copy.deepcopy(state)
        for lost_response in (False, True):
            self.objects = copy.deepcopy(baseline); state = copy.deepcopy(seed_state)
            if lost_response:
                kube = self.kube
                def lost(*args, document=None, **kwargs):
                    response = kube(*args, document=document, **kwargs)
                    if args[0] == 'create' and document['kind'] == 'ApplicationSet': raise RuntimeError('lost response')
                    return response
                with patch.object(proof, 'kube', side_effect=lost), self.assertRaises(RuntimeError):
                    self.call(proof.adopt, self.config, state)
                self.assertNotIn('ApplicationSet', state['identities'])
                self.writes.clear()
                with self.assertRaises(proof.ProofError): self.call(proof.cleanup, self.config, state)
                self.assertEqual(self.writes, [])
            state = self.call(proof.adopt, self.config, state)['state']
            self.assertEqual(state['adoptionPhase'], 'adopting'); self.assertIsNone(state['acceptedApproval'])
            self.assertEqual(self.call(proof.read, 'Application')['metadata'].get('ownerReferences', []), [])
            self.assertEqual(self.call(proof.read, 'Application')['metadata']['uid'], seed_state['identities']['Application'])
            self.writes.clear()
            app = self.objects['application.argoproj.io', self.profile['name'], 'argocd']
            app['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
            with self.assertRaises(proof.ProofError): self.call(proof.cleanup, self.config, state)
            self.assertEqual(self.writes, [])
            app['metadata'].pop('ownerReferences')
            with self.subTest(lost_parent_response=lost_response):
                self.assertTrue(self.call(proof.cleanup, self.config, state)['cleanup_complete'])
                self.assertIsNone(self.call(proof.read, 'Namespace'))
                self.assertTrue(all(args[0] == 'delete' for args, _ in self.writes))

    def test_source_error_observation_requires_exact_retained_child_and_visible_error(self):
        state = self.begin(); uid = state['identities']['Application']
        state = self.call(proof.change, self.config, state, available=False)['state']
        self.objects['applicationset.argoproj.io', self.profile['name'], 'argocd']['status']['conditions'] = [{'type': 'ErrorOccurred', 'status': 'True'}]
        self.assertTrue(self.call(proof.observe, self.config, state, rejected=True)['parent_error_retains_child'])
        self.assertEqual(self.call(proof.read, 'Application')['metadata']['uid'], uid)
        with self.assertRaisesRegex(proof.ProofError, 'Restore valid A'):
            self.call(proof.observe, self.config, state, rejected=True)
        self.objects['application.argoproj.io', self.profile['name'], 'argocd']['spec']['sources'][1]['targetRevision'] = 'e' * 40
        desired = self.call(proof.declarations, self.config, state, self.public, self.root_files)
        with self.assertRaises(proof.ProofError): self.call(proof.child, self.config, state, desired, 'A', True)

    def test_native_istio_trust_defaults_capture_both_and_preserve_trusted_references(self):
        state = self.begin()
        for key in ('IstioRoot', 'IstioCRL'):
            self.assertEqual(state['identities'][key], self.call(proof.read, key)['metadata']['uid'])
        self.assertEqual(self.call(proof.read, 'IstioCRL')['data'], {'ca-crl.pem': ''})
        for namespace in ('argocd', self.profile['name']):
            self.objects['configmap', 'istio-ca-crl', namespace]['data'] = {'ca-crl.pem': 'synthetic-crl'}
        self.assertTrue(self.call(proof.defaults, state))
        references = {name: copy.deepcopy(self.objects['configmap', name, 'argocd']) for name in ('istio-ca-root-cert', 'istio-ca-crl')}
        self.assertTrue(self.call(proof.cleanup, self.config, state)['cleanup_complete'])
        for name, obj in references.items(): self.assertEqual(self.objects['configmap', name, 'argocd'], obj)

    def test_native_istio_trust_mismatch_or_foreign_profile_blocks_all_cleanup_writes(self):
        state = self.begin(); baseline = copy.deepcopy(self.objects)
        for name, field in (('istio-ca-root-cert', 'root-cert.pem'), ('istio-ca-crl', 'ca-crl.pem')):
            for namespace in (self.profile['name'], 'argocd'):
                for case in ('missing', 'type', 'data-type', 'data-mismatch', 'extra-data', 'label', 'label-type',
                        'extra-label', 'annotation', 'owner', 'finalizer', 'deletion', 'binary', 'kind', 'api', 'name', 'namespace', 'uid', 'version'):
                    self.objects = copy.deepcopy(baseline); candidate = copy.deepcopy(state); self.writes.clear()
                    obj = self.objects['configmap', name, namespace]
                    if case == 'missing': del self.objects['configmap', name, namespace]
                    if case == 'type': obj['data'][field] = 1
                    if case == 'data-type': obj['data'] = []
                    if case == 'data-mismatch': obj['data'][field] = 'changed'
                    if case == 'extra-data': obj['data']['extra'] = 'foreign'
                    if case == 'label': obj['metadata']['labels']['istio.io/config'] = 'false'
                    if case == 'label-type': obj['metadata']['labels']['istio.io/config'] = True
                    if case == 'extra-label': obj['metadata']['labels']['foreign'] = 'true'
                    if case == 'annotation': obj['metadata']['annotations'] = {'foreign': 'true'}
                    if case == 'owner': obj['metadata']['ownerReferences'] = [{'uid': 'foreign'}]
                    if case == 'finalizer': obj['metadata']['finalizers'] = ['foreign']
                    if case == 'deletion': obj['metadata']['deletionTimestamp'] = 'now'
                    if case == 'binary': obj['binaryData'] = {'foreign': 'eA=='}
                    if case == 'kind': obj['kind'] = 'Secret'
                    if case == 'api': obj['apiVersion'] = 'foreign/v1'
                    if case == 'name': obj['metadata']['name'] = 'foreign'
                    if case == 'namespace': obj['metadata']['namespace'] = 'foreign'
                    if case == 'uid': obj['metadata']['uid'] = False
                    if case == 'version': obj['metadata']['resourceVersion'] = False
                    with self.subTest(name=name, namespace=namespace, case=case):
                        with self.assertRaises(proof.ProofError): self.call(proof.cleanup, self.config, candidate)
                        self.assertEqual(self.writes, [])
        self.objects = copy.deepcopy(baseline); self.writes.clear()
        self.objects['configmap', 'istio-ca-root-cert', self.profile['name']]['metadata']['uid'] = 'replacement'
        with self.assertRaises(proof.ProofError): self.call(proof.cleanup, self.config, copy.deepcopy(state))
        self.assertEqual(self.writes, [])
        self.objects = copy.deepcopy(baseline)
        candidate = copy.deepcopy(state)
        for key in ('IstioRoot', 'IstioCRL'): candidate['identities'].pop(key)
        self.objects['configmap', 'istio-ca-crl', self.profile['name']]['data']['ca-crl.pem'] = False
        with self.assertRaises(proof.ProofError): self.call(proof.defaults, candidate)
        self.assertFalse({'IstioRoot', 'IstioCRL'} & set(candidate['identities']))
        self.objects = copy.deepcopy(baseline)
        for namespace in (self.profile['name'], 'argocd'):
            self.objects['configmap', 'istio-ca-root-cert', namespace]['data']['root-cert.pem'] = ''
        with self.assertRaises(proof.ProofError): self.call(proof.cleanup, self.config, copy.deepcopy(state))
        self.assertEqual(self.writes, [])

    def test_receipt_rejection_requires_native_gate_error_not_unrelated_auth_or_network_failure(self):
        state = self.begin()
        parent = self.objects['applicationset.argoproj.io', self.profile['name'], 'argocd']
        for available in (True, False):
            if not available:
                parent['status']['conditions'] = [{'type': 'ParametersGenerated', 'status': 'True'}]
                self.call(proof.observe, self.config, state)
                state = self.call(proof.change, self.config, state, available=False)['state']
                parent = self.objects['applicationset.argoproj.io', self.profile['name'], 'argocd']
            for message in ('repository authentication failed', 'network unavailable', 'Private source acceptance refused'):
                with self.subTest(source_available=available, message=message):
                    parent['status']['conditions'] = [{'type': 'ErrorOccurred', 'status': 'True', 'message': message}]
                    candidate = copy.deepcopy(state)
                    def once(check, **kwargs):
                        if not check(): raise proof.ProofError('synthetic observation did not qualify')
                    with patch.object(proof, 'poll', side_effect=once):
                        if (message == 'Private source acceptance refused') == available:
                            result = self.call(proof.observe, self.config, candidate, rejected=True)
                            self.assertTrue(result['parent_error_retains_child'])
                            self.assertNotIn(message, json.dumps(result))
                        else:
                            with self.assertRaisesRegex(proof.ProofError, 'did not qualify'):
                                self.call(proof.observe, self.config, candidate, rejected=True)
                            self.assertEqual(candidate['lastObservation'], state['lastObservation'])

    def test_nonce_patch_simulated_repair_and_compensation_are_distinguished(self):
        state = self.begin(); self.repair = True
        result = self.call(proof.drift, self.config, state)
        self.assertTrue(result['self_heal_verified']); self.assertFalse(result['cleanup_restored'])
        self.repair = False
        def timeout(check, **kwargs):
            self.assertFalse(check()); raise proof.ProofError('synthetic timeout')
        with patch.object(proof, 'poll', side_effect=timeout): result = self.call(proof.drift, self.config, state)
        self.assertFalse(result['self_heal_verified']); self.assertTrue(result['cleanup_restored'])
        self.assertEqual(self.call(proof.read, 'Marker')['data'], {'revision': self.config['receiptA']['revision']})
        patches = [data for args, data in self.writes if args[:2] == ('patch', 'configmap')]
        self.assertTrue(all([row['path'] for row in patch[:3]] == ['/metadata/uid', '/metadata/resourceVersion', '/data'] for patch in patches))

    def test_foreign_scope_data_or_list_failure_blocks_cleanup_before_any_delete(self):
        for case in ('extra-object', 'list-denied', 'data', 'binary', 'finalizer', 'uid', 'credential-owner'):
            self.setUp()
            with self.subTest(case=case):
                state = self.begin(); self.writes.clear()
                if case == 'extra-object': self.objects['widget', 'foreign', self.profile['name']] = {'kind': 'Widget', 'metadata': {'name': 'foreign', 'namespace': self.profile['name'], 'uid': 'foreign'}}
                if case == 'list-denied': self.fail_list = True
                if case == 'data': self.objects['configmap', 'retained-data', self.profile['name']]['data'] = {'foreign': 'retained'}
                if case == 'binary': self.objects['configmap', 'retained-data', self.profile['name']]['binaryData'] = {'foreign': 'YQ=='}
                if case == 'finalizer': self.objects['externalsecret.external-secrets.io', self.profile['name'] + '-source', 'argocd']['metadata']['finalizers'].append('foreign')
                if case == 'uid': self.objects['configmap', 'retained-data', self.profile['name']]['metadata']['uid'] = 'foreign'
                if case == 'credential-owner': self.objects['secret', self.profile['name'] + '-source', 'argocd']['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                with self.assertRaises(proof.ProofError): self.call(proof.cleanup, self.config, state)
                self.assertFalse(any(args[0] == 'delete' for args, _ in self.writes))

    def test_preexisting_objects_and_marker_uid_race_never_receive_a_write(self):
        self.objects['namespace', self.profile['name'], None] = {'metadata': {'uid': 'foreign'}}
        with self.assertRaises(proof.ProofError): self.call(proof.create, self.config)
        self.assertEqual(self.writes, [])
        self.objects.pop(('namespace', self.profile['name'], None)); state = self.begin(); self.writes.clear()
        marker = self.call(proof.read, 'Marker'); marker['metadata']['uid'] = 'foreign'
        with self.assertRaises(proof.ProofError): self.call(proof.marker_patch, marker, {'revision': 'nonce'}, self.config, state, marker['data'])
        self.assertEqual(self.writes, [])

    def test_native_eso_secret_labels_are_exact_metadata_not_an_ownership_substitute(self):
        state = self.begin(); baseline = copy.deepcopy(self.objects); captured = copy.deepcopy(state)
        for case in ('missing-managed', 'missing-created', 'false', 'managed-type', 'created-type', 'malformed-hash',
                     'foreign-hash', 'unknown-label', 'non-secret', 'wrong-name', 'wrong-namespace', 'replaced-eso'):
            self.objects = copy.deepcopy(baseline); state = copy.deepcopy(captured); self.writes.clear()
            secret = self.objects['secret', self.profile['name'] + '-source', 'argocd']; labels = secret['metadata']['labels']
            if case == 'missing-managed': labels.pop('reconcile.external-secrets.io/managed')
            if case == 'missing-created': labels.pop('reconcile.external-secrets.io/created-by')
            if case == 'false': labels['reconcile.external-secrets.io/managed'] = 'false'
            if case == 'managed-type': labels['reconcile.external-secrets.io/managed'] = True
            if case == 'created-type': labels['reconcile.external-secrets.io/created-by'] = 224
            if case == 'malformed-hash': labels['reconcile.external-secrets.io/created-by'] = 'g' * 56
            if case == 'foreign-hash': labels['reconcile.external-secrets.io/created-by'] = 'f' * 56
            if case == 'unknown-label': labels['foreign'] = 'true'
            if case == 'non-secret':
                self.objects['configmap', 'retained-data', self.profile['name']]['metadata']['labels'].update({
                    key: labels[key] for key in ('reconcile.external-secrets.io/managed', 'reconcile.external-secrets.io/created-by')})
            if case == 'wrong-name': secret['metadata']['name'] = 'foreign'
            if case == 'wrong-namespace': secret['metadata']['namespace'] = self.profile['name']
            if case == 'replaced-eso': secret['metadata']['ownerReferences'][0]['uid'] = 'replacement'
            with self.subTest(case=case):
                with self.assertRaises(proof.ProofError): self.call(proof.observe, self.config, state)
                with self.assertRaises(proof.ProofError): self.call(proof.cleanup, self.config, state)
                self.assertEqual(self.writes, [])
        self.objects = baseline
        self.assertTrue(self.call(proof.observe, self.config, captured)['accepted'])
        self.assertTrue(self.call(proof.cleanup, self.config, captured)['cleanup_complete'])

    def test_partial_creation_returns_scope_for_safe_cleanup_or_exact_attempt_resume(self):
        kube = self.kube
        def fail_eso(*args, document=None, **kwargs):
            if args[0] == 'create' and document['kind'] == 'ExternalSecret': raise proof.ProofError('synthetic ESO failure')
            return kube(*args, document=document, **kwargs)
        with patch.object(proof, 'kube', side_effect=fail_eso): result = self.call(proof.create, self.config)
        self.assertFalse(result['created']); self.assertEqual(set(result['state']['identities']), {'Namespace', 'Project'})
        failed = proof.failure_result({'action': 'cleanup', 'config': self.config, 'state': result['state']},
            proof.ProofError('Namespace defaults are not captured; cleanup retained'))
        self.assertEqual(failed['state'], result['state']); self.assertEqual(failed['operation'], 'cleanup')
        hidden = proof.failure_result({'action': 'cleanup', 'config': self.config, 'state': result['state']}, RuntimeError('private-value-must-not-escape'))
        self.assertNotIn('private-value-must-not-escape', json.dumps(hidden)); self.assertNotIn(self.config['privateRepository'], json.dumps(hidden))
        self.assertTrue(self.call(proof.cleanup, self.config, result['state'])['cleanup_complete'])
        self.setUp(); kube = self.kube
        def uncertain_eso(*args, document=None, **kwargs):
            response = kube(*args, document=document, **kwargs)
            if args[0] == 'create' and document['kind'] == 'ExternalSecret': raise proof.ProofError('synthetic lost response')
            return response
        with patch.object(proof, 'kube', side_effect=uncertain_eso): result = self.call(proof.create, self.config)
        before = result['state']['identities'].copy()
        resumed = self.call(proof.resume_create, self.config, result['state'])
        self.assertTrue(resumed['created'])
        self.assertEqual({key: resumed['state']['identities'][key] for key in before}, before)
        self.assertEqual(resumed['state']['identities']['ExternalSecret'], self.call(proof.read, 'ExternalSecret')['metadata']['uid'])
        self.setUp(); kube = self.kube
        def broaden_project(*args, document=None, **kwargs):
            response = kube(*args, document=document, **kwargs)
            if args[0] == 'create' and document['kind'] == 'AppProject':
                obj = json.loads(response); obj['spec']['sourceRepos'] = ['*']
                self.objects['appproject.argoproj.io', self.profile['name'], 'argocd'] = obj
                return json.dumps(obj)
            return response
        with patch.object(proof, 'kube', side_effect=broaden_project): result = self.call(proof.create, self.config)
        self.assertFalse(result['created']); self.assertIn('Project', result['state']['identities'])
        self.assertFalse(any(data.get('kind') == 'ApplicationSet' for args, data in self.writes if args[0] == 'create'))

    def test_replaced_trusted_authority_is_never_owned_cleanup_scope(self):
        state = self.begin(); self.writes.clear()
        self.assertEqual(set(state['authority']), {'Root', 'ApplicationSetController'})
        self.assertFalse(set(state['authority']) & set(state['identities']))
        self.objects['deployment', 'argocd-applicationset-controller', 'argocd']['metadata']['uid'] = 'replacement'
        with self.assertRaisesRegex(proof.ProofError, 'was replaced'): self.call(proof.change, self.config, state, approval='B')
        with self.assertRaisesRegex(proof.ProofError, 'was replaced'): self.call(proof.cleanup, self.config, state)
        self.assertEqual(self.writes, [])

    def test_fixture_consumes_complete_private_values_without_rendering_catalog_details(self):
        values = {'sources': [{'name': 'private', 'repository': self.config['privateRepository'], 'revision': 'main', 'path': 'gitops/private'}],
            'acceptedRevision': self.config['receiptA']['revision'], 'proofAttempt': self.config['attempt']}
        command = ['helm', 'template', 'proof', str(ROOT / self.profile['chart']), '-n', self.profile['name'], '-f', '-']
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
        revision, tree_sha = self.config['publicRevision'], 'e' * 40
        prefix = 'repos/' + proof.native.repository(proof.PUBLIC) + '/git/'
        commit_path, tree_path = prefix + 'commits/' + revision, prefix + 'trees/' + tree_sha + '?recursive=1'
        commit = {'sha': revision, 'tree': {'sha': tree_sha}}
        charts = {'gitops/roots/public': self.root_files, self.profile['chart']: self.fixture_files}
        tree = {'sha': tree_sha, 'truncated': False, 'tree': [
            {'path': path + '/' + name, 'type': 'blob', 'mode': '100644', 'size': len(data),
                'sha': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}
            for path, chart in charts.items() for name, data in chart.items()]}
        real_chart_files = proof.native.source_snapshot.chart_files
        def chart_snapshot(source, **kwargs):
            return real_chart_files(source, read_file=lambda source, name, size, deadline: charts[source['path']][name], **kwargs)
        def metadata_request(path, deadline):
            if path == commit_path: return commit
            if path == tree_path: return tree
            self.assertEqual(path, 'repos/' + proof.native.repository(proof.PUBLIC) + '/contents/platform/delivery/argocd/artifact.lock.json?ref=' + revision)
            return lock_file
        self.context_patch.stop()
        with patch.object(proof.native, 'published_source', return_value=(self.public, revision)) as published, \
                patch.object(proof.native.source_snapshot, 'chart_files', side_effect=chart_snapshot) as snapshots, \
                patch.object(proof.native.source_snapshot, 'request', side_effect=metadata_request) as request, \
                patch.object(proof, 'get', side_effect=lambda kind, *args: controller if kind == 'deployment' else root):
            self.call(proof.context, self.config)
            self.assertEqual([call.args[0] for call in request.call_args_list], [commit_path, tree_path,
                'repos/' + proof.native.repository(proof.PUBLIC) + '/contents/platform/delivery/argocd/artifact.lock.json?ref=' + revision])
            self.assertEqual(snapshots.call_count, 2); self.assertEqual(published.call_count, 1)
            self.assertEqual(snapshots.call_args_list[0].kwargs['deadline'], snapshots.call_args_list[1].kwargs['deadline'])
            self.call(proof.context, self.config)
            self.assertEqual([call.args[0] for call in request.call_args_list].count(commit_path), 2)
            self.assertEqual([call.args[0] for call in request.call_args_list].count(tree_path), 2)
            self.assertEqual(published.call_count, 2)
            request.side_effect = ValueError('synthetic metadata unavailable')
            with self.assertRaisesRegex(ValueError, 'metadata unavailable'): self.call(proof.create, self.config)
            self.assertEqual(self.writes, [])
            request.side_effect = metadata_request
            self.call(proof.context, self.config)
            self.assertEqual(published.call_count, 4)
            tree['truncated'] = True
            with self.assertRaisesRegex(ValueError, 'tree is incomplete'): self.call(proof.context, self.config)
            tree['truncated'] = False
            original = self.fixture_files['Chart.yaml']
            self.fixture_files['Chart.yaml'] = original + b'\n'
            try:
                with self.assertRaisesRegex(ValueError, 'exact Git blob'): self.call(proof.context, self.config)
            finally:
                self.fixture_files['Chart.yaml'] = original
            lock_file['sha'] = '0' * 40
            with self.assertRaisesRegex(proof.ProofError, 'blob integrity'): self.call(proof.context, self.config)
            lock_file['sha'] = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            controller['spec']['template']['spec']['containers'][0]['args'][-1] = '--enable-policy-override=true'
            with self.assertRaises(proof.ProofError): self.call(proof.context, self.config)
        self.assertEqual(self.writes, [])
