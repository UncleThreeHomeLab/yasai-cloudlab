import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / 'verification/integration'))
import verify


PAYLOAD = {'repository': 'https://github.com/example/platform.git', 'revision': 'b' * 40,
           'public_namespace': 'fixture'}


class VerificationTests(unittest.TestCase):
    def test_untrusted_probe_has_no_identity_or_trusted_network_label(self):
        doc = verify.pod('fixture', 'probe', 'image@sha256:fixture', 'true')
        self.assertFalse(doc['spec']['automountServiceAccountToken'])
        self.assertNotIn('app.kubernetes.io/part-of', doc['metadata']['labels'])
        self.assertTrue(doc['spec']['securityContext']['runAsNonRoot'])
        self.assertFalse(doc['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'])

    def test_failed_probe_creation_never_deletes_an_existing_pod(self):
        with patch.object(verify, 'kube', side_effect=RuntimeError('Already exists')) as kube:
            with self.assertRaises(RuntimeError):
                verify.verify_pod(verify.pod('fixture', 'probe', 'image', 'true'))
            self.assertEqual(kube.call_count, 1)

    def denied_spec(self, case, message):
        created, calls = {}, []
        observed = {'metadata': {'name': 'denied'},
                    'status': {'conditions': [{'type': 'InvalidSpecError', 'message': message}]}}
        def kube(*args, document=None):
            calls.append(args)
            if document is not None:
                created.update(document)
            return ''
        with patch.object(verify, 'kube', side_effect=kube), patch.object(verify, 'get', return_value=observed):
            verify.denied_application(PAYLOAD, case, 'suffix')
        self.assertNotIn('fixtures/public', json.dumps(created))
        self.assertIn(('delete', 'application.argoproj.io', 'cloudlab-denied-' + case + '-suffix',
                       '-n', 'argocd', '--ignore-not-found', '--wait=true', '--timeout=60s'), calls)
        return created['spec']

    def test_denied_source_keeps_project_verdict_without_fixture_files(self):
        spec = self.denied_spec('source', 'repo is not permitted in project')
        self.assertEqual(spec['source']['repoURL'], 'https://github.com/example/forbidden.git')
        self.assertEqual(spec['source']['path'], 'gitops/fixtures/intentionally-missing')
        self.assertEqual(spec['destination']['namespace'], 'fixture')

    def test_denied_namespace_keeps_project_verdict_without_fixture_files(self):
        spec = self.denied_spec('namespace', 'destinations do not match any of the allowed destinations')
        self.assertEqual(spec['source']['repoURL'], PAYLOAD['repository'])
        self.assertEqual(spec['destination']['namespace'], 'argocd')

    def lifecycle(self, reads, configmaps):
        created, calls = {}, []
        def kube(*args, document=None):
            calls.append(args)
            if document is not None:
                created.update(document)
            if args[:2] == ('get', 'configmap'):
                return configmaps.pop(0)
            return ''
        with patch.object(verify, 'kube', side_effect=kube), \
                patch.object(verify, 'get', side_effect=reads), \
                patch.object(verify, 'wait_application', return_value=PAYLOAD['revision']) as converged:
            verify.public_lifecycle(PAYLOAD)
        return created, calls, converged

    def test_lifecycle_admits_permitted_spec_and_reproves_roots(self):
        admitted = {'metadata': {'name': 'cloudlab-public-fixture'},
                    'status': {'reconciledAt': 'now', 'conditions': []}}
        created, calls, converged = self.lifecycle([None, admitted], ['', ''])
        spec = created['spec']
        self.assertEqual((spec['project'], spec['source']['repoURL'], spec['source']['targetRevision'],
                          spec['source']['path'], spec['destination']['namespace']),
                         ('cloudlab-public', PAYLOAD['repository'], PAYLOAD['revision'],
                          'gitops/fixtures/intentionally-missing', 'fixture'))
        self.assertNotIn('automated', spec.get('syncPolicy', {}))
        self.assertNotIn('fixtures/public', json.dumps(created))
        self.assertEqual(converged.call_count, 2)
        self.assertIn(('delete', 'application.argoproj.io', 'cloudlab-public-fixture',
                       '-n', 'argocd', '--ignore-not-found', '--wait=true', '--timeout=60s'), calls)
        self.assertFalse([args for args in calls if args[:2] == ('delete', 'configmap')])

    def test_lifecycle_refuses_foreign_owned_names_before_creating(self):
        foreign = {'metadata': {'name': 'cloudlab-public-fixture', 'labels': {}}}
        for reads, configmaps in (([foreign], ['']), ([None], [json.dumps(foreign)])):
            calls = []
            def kube(*args, document=None):
                calls.append(args)
                if args[:2] == ('get', 'configmap'):
                    return configmaps.pop(0)
                return ''
            with self.subTest(previous=bool(reads[0])), patch.object(verify, 'kube', side_effect=kube), \
                    patch.object(verify, 'get', side_effect=list(reads)):
                with self.assertRaisesRegex(RuntimeError, 'another actor'):
                    verify.public_lifecycle(PAYLOAD)
            self.assertFalse([args for args in calls if args[0] in ('create', 'apply', 'delete')])

    def test_lifecycle_fails_closed_when_project_rejects_permitted_spec(self):
        rejected = {'metadata': {'name': 'cloudlab-public-fixture'},
                    'status': {'conditions': [{'type': 'InvalidSpecError', 'message': 'denied'}]}}
        calls = []
        def kube(*args, document=None):
            calls.append(args)
            return ''
        with patch.object(verify, 'kube', side_effect=kube), \
                patch.object(verify, 'get', side_effect=[None, rejected]), \
                patch.object(verify, 'wait_application', side_effect=AssertionError('no convergence on rejection')):
            with self.assertRaisesRegex(RuntimeError, 'Project rejected'):
                verify.public_lifecycle(PAYLOAD)
        self.assertTrue([args for args in calls if args[:2] == ('delete', 'application.argoproj.io')])

    def test_lifecycle_removes_only_own_labelled_legacy_configmap(self):
        admitted = {'metadata': {'name': 'cloudlab-public-fixture'},
                    'status': {'reconciledAt': 'now', 'conditions': []}}
        ours = json.dumps({'metadata': {'name': 'cloudlab-public-fixture',
                                        'labels': {'cloudlab.io/verification': 'gitops-public-fixture'}}})
        _, calls, _ = self.lifecycle([None, admitted], ['', ours])
        self.assertIn(('delete', 'configmap', 'cloudlab-public-fixture',
                       '-n', 'fixture', '--wait=true'), calls)
