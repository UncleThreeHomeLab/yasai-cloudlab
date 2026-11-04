import copy
import base64
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / 'verification/integration'))
from private_verify import healthy, configuration_healthy, credential_owner, run
from private_activation import APP, OWNER, TRACKING


class PrivateConvergenceTests(unittest.TestCase):
    def test_external_registered_child_degradation_fails_stability_observation(self):
        payload = {'configuration_repository': 'private-source', 'configuration_revision': 'b' * 40,
                   'sources': [{'name': 'example', 'repository': 'other-source'}]}
        consumer = {'metadata': {'name': 'configuration-consumer'},
                    'spec': {'source': {'repoURL': 'private-source'}}}
        def request(*args):
            self.assertEqual(args[0], 'get')
            return json.dumps({'items': [consumer] if args[1] == 'applications.argoproj.io' else []})
        with patch('private_verify.kube', side_effect=request), patch('private_verify.get', return_value={}), \
                patch('private_verify.configuration_healthy', return_value=True), \
                patch('private_verify.healthy', side_effect=[True, False]) as child_health, \
                patch('private_verify.credential_owner'), patch('private_verify.foundation_sample', return_value=()), \
                patch('private_verify.fingerprint', return_value=()), \
                patch('private_verify.wait', side_effect=lambda check, description: self.assertTrue(check())), \
                patch('private_verify.time.sleep'), patch('private_verify.time.monotonic', side_effect=[0, 1]):
            with self.assertRaisesRegex(RuntimeError, 'changed during stability observation'):
                run(payload)
        self.assertEqual([call.args for call in child_health.call_args_list], [('cloudlab-private-example',)] * 2)

    def test_native_empty_catalog_requires_exact_owned_source_and_does_not_write(self):
        payload = {'configuration_repository': 'https://github.com/example/private.git',
            'configuration_revision': 'b' * 40, 'catalog_enabled': True, 'sources': [], 'objects': [],
            'public_repository': 'https://github.com/example/platform.git', 'platform_revision': 'a' * 40}
        app = {'metadata': {'name': APP, 'labels': {'cloudlab.io/owner': OWNER},
            'annotations': {'argocd.argoproj.io/tracking-id': TRACKING}},
            'spec': {'project': APP, 'sources': [
                {'repoURL': payload['public_repository'], 'targetRevision': 'a' * 40,
                 'path': 'platform/delivery/private-sources', 'helm': {'valueFiles': ['$values/platform/sources.yaml']}},
                {'repoURL': payload['configuration_repository'], 'targetRevision': 'main', 'ref': 'values'}],
                'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
                'syncPolicy': {'automated': {'enabled': True, 'prune': True, 'selfHeal': True, 'allowEmpty': True},
                    'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true', 'PruneLast=true']}},
            'status': {'sync': {'status': 'Synced', 'revisions': ['a' * 40, 'b' * 40]},
                       'health': {'status': 'Healthy'}}}
        project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject',
            'metadata': {'name': 'cloudlab-private-example', 'labels': {'cloudlab.io/owner': 'private-gitops'}},
            'spec': {'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': 'cloudlab-private-example'}]}}
        payload['objects'] = [project]
        def request(*args):
            self.assertEqual(args[0], 'get')
            if args[1] == 'appproject.argoproj.io': return json.dumps(actual_project)
            return json.dumps({'items': [app] if args[1] == 'applications.argoproj.io' else []})
        for bad in ('none', 'catalog', 'project'):
            changed = copy.deepcopy(app)
            actual_project = copy.deepcopy(project)
            actual_project['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id':
                APP + ':argoproj.io/AppProject:argocd/cloudlab-private-example'}
            if bad == 'catalog': changed['metadata']['annotations'] = {}
            if bad == 'project': actual_project['spec']['destinations'][0]['namespace'] = 'argocd'
            with patch('private_verify.get', return_value=changed), patch('private_verify.kube', side_effect=request), \
                    patch('private_verify.credential_owner'), patch('private_verify.foundation_sample', return_value=()), \
                    patch('private_verify.wait', side_effect=lambda check, description: self.assertTrue(check())), \
                    patch('private_verify.fingerprint', return_value=()), patch('private_verify.time.monotonic', side_effect=[0, 61, 62]):
                if bad != 'none':
                    with self.assertRaisesRegex(RuntimeError, 'ownership or source|native declaration'): run(payload)
                else:
                    self.assertTrue(run(payload)['private_access_verified'])

    def test_main_must_resolve_to_authenticated_configuration_head(self):
        app = {'spec': {'source': {'repoURL': 'private-source', 'targetRevision': 'main'}},
               'status': {'sync': {'revision': 'a' * 40, 'status': 'Synced'}, 'health': {'status': 'Healthy'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(configuration_healthy('consumer', 'private-source', 'a' * 40))
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'b' * 40))
            self.assertFalse(configuration_healthy('consumer', 'other-source', 'a' * 40))
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'main'))

    def test_native_private_values_main_requires_authenticated_head_without_relaxing_other_sources(self):
        app = {'spec': {'sources': [{'repoURL': 'public-source', 'targetRevision': 'main'},
                                   {'repoURL': 'private-source', 'targetRevision': 'main', 'ref': 'values'}]},
               'status': {'sync': {'status': 'Synced', 'revisions': ['a' * 40, 'b' * 40]},
                          'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}}
        original = copy.deepcopy(app)
        with patch('private_verify.get', return_value=app):
            self.assertTrue(configuration_healthy('consumer', 'private-source', 'b' * 40))
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'c' * 40))
        self.assertEqual(app, original)
        for target in ('c' * 40, 'unapproved-branch'):
            changed = copy.deepcopy(app)
            changed['spec']['sources'][1]['targetRevision'] = target
            with patch('private_verify.get', return_value=changed):
                self.assertFalse(configuration_healthy('consumer', 'private-source', 'b' * 40))
        changed = copy.deepcopy(app)
        changed['spec']['sources'].append({'repoURL': 'other-source', 'targetRevision': 'main'})
        changed['status']['sync']['revisions'].append('d' * 40)
        with patch('private_verify.get', return_value=changed):
            self.assertFalse(configuration_healthy('consumer', 'private-source', 'b' * 40))

    def test_private_credential_requires_exact_project_and_ready_eso_owner(self):
        app = {'spec': {'project': 'approved'}}
        secret = {'metadata': {'name': 'source', 'labels': {'argocd.argoproj.io/secret-type': 'repository'},
                               'ownerReferences': [{'kind': 'ExternalSecret', 'name': 'source', 'uid': 'owner', 'controller': True}]},
                  'data': {key: base64.b64encode(value.encode()).decode() for key, value in {
                      'url': 'private-source', 'project': 'approved', 'githubAppID': '1',
                      'githubAppInstallationID': '2', 'githubAppPrivateKey': 'synthetic'}.items()}}
        external = {'metadata': {'name': 'source', 'uid': 'owner'},
                    'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        credential_owner(app, 'private-source', [secret], [external])
        for changed, externals in ((dict(secret, data=dict(secret['data'], project='')), [external]),
                                   (dict(secret, metadata=dict(secret['metadata'], ownerReferences=[])), [external]),
                                   (secret, [dict(external, status={})])):
            with self.subTest(changed=changed['metadata']['name']), self.assertRaises(RuntimeError):
                credential_owner(app, 'private-source', [changed], externals)
        with self.assertRaises(RuntimeError):
            credential_owner(app, 'private-source', [secret, secret], [external])

    def test_missing_private_capability_never_passes_as_verified(self):
        with self.assertRaises(RuntimeError):
            run({'sources': []})
        with patch('private_verify.kube', return_value='{"items": []}'), self.assertRaises(RuntimeError):
            run({'sources': [], 'configuration_repository': 'private-source'})

    def test_native_multiple_sources_require_every_pinned_values_revision(self):
        app = {'spec': {'sources': [{'targetRevision': 'main'}, {'targetRevision': 'b' * 40}]},
               'status': {'sync': {'status': 'Synced', 'revisions': ['a' * 40, 'b' * 40]},
                          'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(healthy('cloudlab-argocd'))
        for revisions, target in ((['a' * 40], 'b' * 40), (['a' * 40, 'c' * 40], 'b' * 40),
                                  (['a' * 40, 'main'], 'main')):
            changed = copy.deepcopy(app)
            changed['status']['sync']['revisions'] = revisions
            changed['spec']['sources'][1]['targetRevision'] = target
            with self.subTest(revisions=revisions), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('cloudlab-argocd'))

    def test_retained_resources_can_converge_without_a_new_sync_operation(self):
        app = {'status': {'sync': {'status': 'Synced', 'revision': 'resolved-commit'},
                          'health': {'status': 'Healthy'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(healthy('fixture'))
        for phase in ('Running', 'Failed', 'Error', 'Terminating'):
            changed = copy.deepcopy(app)
            changed['status']['operationState'] = {'phase': phase}
            with self.subTest(phase=phase), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('fixture'))
        for change in ({'sync': {'status': 'Synced'}}, {'conditions': [{'type': 'ComparisonError'}]},
                       {'sync': {'status': 'Unknown', 'revision': 'old'}}):
            changed = copy.deepcopy(app)
            changed['status'].update(change)
            with self.subTest(change=change), patch('private_verify.get', return_value=changed):
                self.assertFalse(healthy('fixture'))
