import base64
import copy
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import initial_bootstrap
import inputs
import kube
import native
from fixtures import accepted, prepared


class NativeCertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.contract, cls.values, cls.public, cls.binding = prepared()

    def check(self, stage='native', mutate=None, expected_tls=None):
        state, objects = accepted(self.contract, stage)
        if mutate: mutate(state, objects)
        def get(kind, name, namespace=None): return objects.get((kind, name, namespace))
        def request(*args, **kwargs):
            self.assertEqual(args[:2], ('get', 'secrets'))
            return json.dumps({'items': [obj for (kind, name, ns), obj in objects.items()
                if kind == 'secret' and ns == 'argocd']})
        with patch.object(native, 'get', side_effect=get), patch.object(kube, 'get', side_effect=get), \
                patch.object(native, 'kube', side_effect=request):
            result = native.guard(self.contract, state, stage=stage, expected_tls=expected_tls)
        return result

    def test_legacy_preflight_and_native_observation_preserve_tls_and_handle_absent_or_null_source(self):
        before = self.check('legacy')
        self.assertFalse(before['native_owner_verified'])
        self.assertTrue(self.check(expected_tls=before['tls'])['native_owner_verified'])
        self.assertTrue(self.check(mutate=lambda s, o: o['application.argoproj.io', native.APP, 'argocd']['spec'].update(source=None))['native_owner_verified'])

    def test_initial_reader_collision_including_another_credential_name_refuses_handoff(self):
        def collision(state, objects):
            _, existing = accepted(self.contract, 'native')
            objects['secret', 'another-reader', 'argocd'] = existing['secret', 'cloudlab-certificates-source', 'argocd']
        for kind in ('secret', 'externalsecret.external-secrets.io'):
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                self.check('legacy', mutate=lambda s, o: o.update({(kind, 'cloudlab-certificates-source', 'argocd'): {'metadata': {}}}))
        with self.assertRaisesRegex(RuntimeError, 'occupied'): self.check('legacy', mutate=collision)

    def test_source_receipt_uid_scope_and_termination_conflicts_fail_without_writes(self):
        changes = [lambda s, o: s.update(application_uid='changed'),
            lambda s, o: s.update(zone_hash='0' * 64),
            lambda s, o: o['application.argoproj.io', native.APP, 'argocd']['spec'].update(source={'repoURL': 'old'}),
            lambda s, o: o['application.argoproj.io', native.APP, 'argocd']['spec'].update(ignoreDifferences=[
                {'group': 'cert-manager.io', 'kind': 'Certificate', 'jsonPointers': ['/spec']}]),
            lambda s, o: o['application.argoproj.io', native.APP, 'argocd'].update(operation={'sync': {}}),
            lambda s, o: o['appproject.argoproj.io', native.APP, 'argocd']['spec']['namespaceResourceWhitelist'].append({'group': '', 'kind': 'Secret'}),
            lambda s, o: o['namespace', 'cloudlab-gateway-public', None]['metadata'].update(deletionTimestamp='pending'),
            lambda s, o: o['certificate.cert-manager.io', 'cloudlab-staging', 'cert-manager']['metadata'].update(deletionTimestamp='pending'),
            lambda s, o: o['secret', 'cloudlab-staging-tls', 'cert-manager']['metadata'].update(deletionTimestamp='pending'),
            lambda s, o: o['secret', 'cloudlab-acme-staging', 'cert-manager']['data'].update(extra='changed')]
        for mutate in changes:
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError): self.check(mutate=mutate)

    def test_native_eso_and_secret_exact_ownership_scope_and_duplicates_are_required(self):
        external = ('externalsecret.external-secrets.io', 'cloudlab-certificates-source', 'argocd')
        secret = ('secret', 'cloudlab-certificates-source', 'argocd')
        changes = [lambda s, o: o[external]['spec']['target'].update(deletionPolicy='Delete'),
            lambda s, o: o[external]['metadata']['annotations'].clear(),
            lambda s, o: o[secret]['metadata']['ownerReferences'][0].update(uid='foreign'),
            lambda s, o: o[secret]['data'].update(extra='c3ludGhldGlj'),
            lambda s, o: o[secret]['data'].update(project=base64.b64encode(b'other').decode()),
            lambda s, o: o.update({('secret', 'duplicate', 'argocd'): copy.deepcopy(o[secret])})]
        for mutate in changes:
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError): self.check(mutate=mutate)

    def test_skip_reconcile_cannot_attest_stale_health_on_legacy_or_native_applications(self):
        for stage in ('legacy', 'native'):
            def paused(state, objects):
                app = objects['application.argoproj.io', native.APP, 'argocd']
                app['metadata'].setdefault('annotations', {})['argocd.argoproj.io/skip-reconcile'] = 'true'
            with self.subTest(stage=stage), self.assertRaises(RuntimeError):
                self.check(stage, mutate=paused)

    def test_tls_content_baseline_is_transition_only(self):
        baseline = self.check()['tls']
        def renewed(state, objects): objects['secret', 'cloudlab-staging-tls', 'cert-manager']['data']['tls.crt'] = 'renewed'
        with self.assertRaisesRegex(RuntimeError, 'TLS credentials changed'): self.check(mutate=renewed, expected_tls=baseline)
        self.assertTrue(self.check(mutate=renewed)['native_owner_verified'])

    def test_accepted_bootstrap_never_calls_provider_or_configure_or_changes_receipt(self):
        state, _ = accepted(self.contract, 'native')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ownership.json'
            path.write_text(json.dumps(state))
            before = path.read_bytes()
            for contract in (self.contract, None):
                with patch.object(initial_bootstrap, 'BASE', Path(directory)), \
                        patch.object(initial_bootstrap, 'zone') as zone, patch.object(initial_bootstrap, 'configure') as configure, \
                        patch.object(initial_bootstrap, 'kube') as write, patch.object(native, 'guard') as observe, \
                        patch.object(native, 'observe_legacy'):
                    result = initial_bootstrap.run({'native': contract})
                self.assertFalse(result['changed'])
                zone.assert_not_called(); configure.assert_not_called(); write.assert_not_called()
                self.assertEqual(path.read_bytes(), before)
            with patch.object(initial_bootstrap, 'BASE', Path(directory)), patch.object(initial_bootstrap, 'configure') as configure, \
                    patch.object(initial_bootstrap, 'zone') as zone, self.assertRaises(RuntimeError):
                initial_bootstrap.run({'native': {}})
            configure.assert_not_called(); zone.assert_not_called()

    def test_current_certificate_readiness_and_eso_exception_are_distinct(self):
        obj = {'kind': 'Certificate', 'metadata': {'generation': 2}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        self.assertFalse(kube.ready(obj))
        obj['kind'] = 'ExternalSecret'
        self.assertTrue(kube.ready(obj))
        obj['kind'] = 'Certificate'; obj['status']['conditions'][0]['observedGeneration'] = 2
        self.assertTrue(kube.ready(obj))
        obj['status']['conditions'].append({'type': 'Issuing', 'status': 'True', 'observedGeneration': 2})
        self.assertFalse(kube.ready(obj))

    def test_multisource_revision_checks_keep_operator_public_head_distinct_from_chart_pin(self):
        _, objects = accepted(self.contract, 'native')
        with patch.object(kube, 'get', side_effect=lambda kind, name, namespace=None: objects.get((kind, name, namespace))):
            self.assertTrue(kube.application_ready('cloudlab-cert-manager', self.contract['public_revision']))
            self.assertFalse(kube.application_ready('cloudlab-cert-manager', self.contract['configuration_revision']))
            self.assertTrue(kube.application_ready(native.APP, self.contract['configuration_revision'], self.contract['private_revision']))
            self.assertFalse(kube.application_ready(native.APP, self.contract['public_revision'], self.contract['private_revision']))
            objects['application.argoproj.io', native.APP, 'argocd']['status']['sync']['revisions'][1] = 'main'
            self.assertFalse(kube.application_ready(native.APP, self.contract['configuration_revision'], 'main'))

    def test_missing_binding_needs_no_private_inputs_but_present_malformed_binding_fails(self):
        for identity, success in (({}, True), ({'argo': {}}, False), ({'argo': None}, False), ({'argo': False}, False)):
            root = {'spec': {'source': {'helm': {'valuesObject': {'identity': identity}}}}}
            result = subprocess.run([sys.executable, inputs.__file__], input=json.dumps({'root': root, 'public': {'revision': 'd' * 40}}),
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode == 0, success, result.stderr)
            if success: self.assertEqual(json.loads(result.stdout), {'native': None})

    def test_authenticated_values_schema_regular_file_and_approved_revision_fail_closed(self):
        def invoke(document, expected=None):
            def authenticated(values, *, read): return read(Mock(request=Mock(return_value=document)), 'c' * 40)
            with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=authenticated):
                return inputs.prepare(self.values, self.public, self.binding, 'd' * 40, expected_revision=expected)
        for selected in ({'zone': 'example.invalid', 'production': False}, {'zone': '../bad', 'production': True},
                         {'zone': 'example.invalid', 'production': True, 'secret': 'not-allowed'}):
            raw = json.dumps(selected).encode()
            with self.subTest(selected=selected), self.assertRaises((ValueError, RuntimeError)):
                invoke({'type': 'file', 'encoding': 'base64', 'size': len(raw), 'content': base64.b64encode(raw).decode()})
        for document in ({'type': 'symlink'}, {'type': 'file', 'encoding': 'base64', 'size': 65537}):
            with self.assertRaises(ValueError): invoke(document)
        with self.assertRaises(ValueError): invoke({}, expected='e' * 40)
        for binding in (None, False, {}):
            with self.assertRaises(ValueError): inputs.prepare(self.values, self.public, binding, 'd' * 40)

    def test_private_file_failure_still_revokes_the_scoped_disposable_token(self):
        from playbooks.argocd.files import github_app
        api, client = Mock(), Mock()
        api.request.side_effect = [{'app_id': 1, 'repository_selection': 'selected',
            'permissions': {'contents': 'read', 'metadata': 'read'}}, {'token': 'synthetic'}]
        client.request.side_effect = [{'full_name': 'example/private', 'private': True, 'default_branch': 'main'},
            {'object': {'sha': 'c' * 40}}, RuntimeError('private diagnostic must not escape'), None]
        with patch('playbooks.secrets.files.vault.fields', return_value={'APP_ID': '1', 'INSTALLATION_ID': '2', 'PRIVATE_KEY': 'synthetic'}), \
                patch.object(github_app, 'app_token', return_value='synthetic'), \
                patch.object(github_app, 'GitHub', side_effect=[api, client]), \
                self.assertRaisesRegex(ValueError, '^Authenticated certificate values are unavailable or invalid$'):
            inputs.prepare(self.values, self.public, self.binding, 'd' * 40)
        client.request.assert_called_with('DELETE', 'installation/token')
        self.assertEqual(api.request.call_args.args[2], {'repositories': ['private'], 'permissions': {'contents': 'read'}})
