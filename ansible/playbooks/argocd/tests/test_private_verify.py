import copy
from contextlib import nullcontext
import base64
import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / 'verification/integration'))
import private_verify as verify_module
from private_verify import healthy, configuration_healthy, credential_owner, controller_items, observability_healthy, run
from private_activation import APP, OWNER, TRACKING
from controller_stability import fingerprint
from fixtures import source_approval, first_binding_observation




class PrivateControllerStabilityTests(unittest.TestCase):
    def setUp(self):
        self.controller = {'apiVersion': 'apps/v1', 'kind': 'Deployment',
            'metadata': {'name': 'controller', 'namespace': 'argocd', 'uid': 'controller-uid', 'generation': 1},
            'spec': {'replicas': 1},
            'status': {'observedGeneration': 1, 'readyReplicas': 1, 'updatedReplicas': 1}}
        self.pod = {'apiVersion': 'v1', 'kind': 'Pod',
            'metadata': {'name': 'controller-pod', 'namespace': 'argocd', 'uid': 'pod-uid'},
            'status': {'phase': 'Running', 'conditions': [{'type': 'Ready', 'status': 'True'}],
                       'containerStatuses': [{'name': 'controller', 'restartCount': 0, 'containerID': 'container-1'}]}}
        self.job = {'apiVersion': 'batch/v1', 'kind': 'Job',
                    'metadata': {'name': 'scheduled', 'namespace': 'argocd', 'uid': 'job-uid'}}
        self.job_pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {
            'name': 'scheduled-pod', 'namespace': 'argocd', 'uid': 'job-pod-uid', 'ownerReferences': [
                {'apiVersion': 'batch/v1', 'kind': 'Job', 'controller': True, 'name': 'scheduled', 'uid': 'job-uid'}]},
            'status': {'phase': 'Pending'}}

    def test_proven_job_pod_start_completion_and_disappearance_preserve_controller_fingerprint(self):
        baseline = fingerprint([self.controller, self.pod])
        completed = copy.deepcopy(self.job_pod)
        completed['status']['phase'] = 'Succeeded'
        for transient in ([], [self.job], [self.job, self.job_pod], [self.job, completed], []):
            with self.subTest(transient=transient):
                self.assertEqual(fingerprint(controller_items([self.controller, self.pod] + transient)), baseline)

    def test_missing_or_mismatched_job_ownership_cannot_hide_an_unready_pod(self):
        changes = [{}, {'ownerReferences': []}, {'ownerReferences': ['malformed']},
                   {'ownerReferences': {'kind': 'Job'}}]
        owner = self.job_pod['metadata']['ownerReferences'][0]
        for field, value in (('kind', 'ReplicaSet'), ('apiVersion', 'apps/v1'), ('controller', False),
                             ('controller', 1), ('uid', 'foreign'), ('uid', None), ('name', 'other')):
            changes.append({'ownerReferences': [owner | {field: value}]})
        changes.append({'namespace': 'other'})
        for change in changes:
            pod = copy.deepcopy(self.job_pod)
            pod['metadata'].pop('ownerReferences')
            pod['metadata'].update(change)
            pod['metadata']['name'] = 'cloudlab-previews-scheduled-looking-pod'
            with self.subTest(change=change):
                filtered = controller_items([self.controller, self.pod, self.job, pod])
                self.assertIn(pod, filtered)
                with self.assertRaisesRegex(RuntimeError, 'not ready'): fingerprint(filtered)

    def test_missing_or_malformed_listed_job_does_not_prove_pod_ownership(self):
        jobs = [None, self.job | {'apiVersion': 'batch/v1beta1'}]
        for field, value in (('uid', ''), ('uid', None), ('name', ''), ('namespace', 'other')):
            jobs.append(self.job | {'metadata': self.job['metadata'] | {field: value}})
        for job in jobs:
            with self.subTest(job=job):
                filtered = controller_items([self.controller, self.pod, self.job_pod] + ([job] if job else []))
                self.assertIn(self.job_pod, filtered)
                with self.assertRaisesRegex(RuntimeError, 'not ready'): fingerprint(filtered)

    def test_persistent_pod_restart_replacement_and_unreadiness_remain_visible(self):
        baseline = fingerprint(controller_items([self.controller, self.pod, self.job, self.job_pod]))
        restarted = copy.deepcopy(self.pod)
        restarted['status']['containerStatuses'][0]['restartCount'] = 1
        replaced = self.pod | {'metadata': self.pod['metadata'] | {'uid': 'replacement'}}
        for pod in (restarted, replaced):
            self.assertNotEqual(fingerprint(controller_items([self.controller, pod, self.job, self.job_pod])), baseline)
        unready = copy.deepcopy(self.pod)
        unready['status']['conditions'][0]['status'] = 'False'
        with self.assertRaisesRegex(RuntimeError, 'not ready'):
            fingerprint(controller_items([self.controller, unready, self.job, self.job_pod]))
        controller = self.controller | {'status': self.controller['status'] | {'readyReplicas': 0}}
        with self.assertRaisesRegex(RuntimeError, 'rollout is not complete'):
            fingerprint(controller_items([controller, self.pod, self.job, self.job_pod]))


class PrivateConvergenceTests(unittest.TestCase):
    def test_declared_symbolic_refs_require_the_authenticated_snapshot_and_preserve_input(self):
        for ref in ('feature/prices', 'release/v2'):
            app = {'spec': {'source': {'repoURL': 'private-source', 'targetRevision': ref}},
                   'status': {'sync': {'revision': 'b' * 40, 'status': 'Synced'}, 'health': {'status': 'Healthy'}}}
            original = copy.deepcopy(app)
            with patch('private_verify.get', return_value=app):
                self.assertTrue(configuration_healthy('consumer', 'private-source', 'a' * 40, {ref: 'b' * 40}))
                for snapshot in (None, {}, {'undeclared': 'b' * 40}, {ref: 'c' * 40}, {ref: 'main'},
                                 {ref: None}, [], {'-flag': 'b' * 40}):
                    with self.subTest(ref=ref, snapshot=snapshot):
                        self.assertFalse(configuration_healthy('consumer', 'private-source', 'a' * 40, snapshot))
            self.assertEqual(app, original)

    def test_symbolic_map_cannot_override_main_or_immutable_pins(self):
        for ref, expected in (('main', 'a' * 40), ('b' * 40, 'b' * 40)):
            app = {'spec': {'source': {'repoURL': 'private-source', 'targetRevision': ref}},
                   'status': {'sync': {'revision': expected, 'status': 'Synced'}, 'health': {'status': 'Healthy'}}}
            with patch('private_verify.get', return_value=app):
                self.assertTrue(configuration_healthy('consumer', 'private-source', 'a' * 40))
                self.assertFalse(configuration_healthy('consumer', 'private-source', 'a' * 40, {ref: expected}))
                app['status']['sync']['revision'] = 'c' * 40
                self.assertFalse(configuration_healthy('consumer', 'private-source', 'a' * 40, {ref: 'c' * 40}))

    def test_mixed_sources_keep_main_and_every_pin_bound_while_comparing_symbolic_private_refs(self):
        app = {'spec': {'sources': [
            {'repoURL': 'public-source', 'targetRevision': 'main'},
            {'repoURL': 'private-source', 'targetRevision': 'feature/prices'},
            {'repoURL': 'private-source', 'targetRevision': 'c' * 40},
            {'repoURL': 'private-source', 'targetRevision': 'main'},
            {'repoURL': 'other-source', 'targetRevision': 'd' * 40}]},
            'status': {'sync': {'status': 'Synced', 'revisions': ['e' * 40, 'b' * 40, 'c' * 40, 'a' * 40, 'd' * 40]},
                       'health': {'status': 'Healthy'}}}
        with patch('private_verify.get', return_value=app):
            self.assertTrue(configuration_healthy('consumer', 'private-source', 'a' * 40, {'feature/prices': 'b' * 40}))
            for index in range(1, 5):
                original = app['status']['sync']['revisions'][index]
                app['status']['sync']['revisions'][index] = 'f' * 40
                self.assertFalse(configuration_healthy('consumer', 'private-source', 'a' * 40, {'feature/prices': 'b' * 40}))
                app['status']['sync']['revisions'][index] = original

    def test_symbolic_snapshot_reaches_initial_consumer_child_and_stability_checks(self):
        snapshots = {'feature/prices': 'b' * 40}
        payload = {'configuration_repository': 'private-source', 'configuration_revision': 'a' * 40,
                   'symbolic_revisions': snapshots, 'sources': [{'name': 'example', 'repository': 'private-source'}]}
        consumer = {'metadata': {'name': 'cloudlab-private-example'}, 'spec': {'source': {'repoURL': 'private-source'}}}
        def request(*args): return json.dumps({'items': [consumer] if args[1] == 'applications.argoproj.io' else []})
        def healthy(name, repository, revision, symbols):
            self.assertIs(symbols, snapshots)
            return True
        with patch('private_verify.kube', side_effect=request), patch('private_verify.get', return_value=consumer), \
                patch('private_verify.configuration_healthy', side_effect=healthy) as checks, \
                patch('private_verify.credential_owner'), patch('private_verify.foundation_sample', return_value=()), \
                patch('private_verify.fingerprint', return_value=()), \
                patch('private_verify.wait', side_effect=lambda check, description: self.assertTrue(check())), \
                patch('private_verify.time.sleep'), patch('private_verify.time.monotonic', side_effect=[0, 1, 61, 62]):
            self.assertTrue(run(payload)['private_access_verified'])
        self.assertEqual(checks.call_count, 4)

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


class TelemetryConvergenceTests(unittest.TestCase):
    def telemetry_fixture(self, paused=False):
        repository = 'https://github.com/example/private.git'
        target = {'valuesRepository': repository, 'valuesRevision': 'd' * 40}
        root = Path(__file__).resolve().parents[4]
        chart = root / 'gitops/roots/public'
        values = {'identity': {'enabled': True, 'argo': target},
                  'services': {'acceptanceCommitment': '3' * 64},
                  'observability': {'configuration': {'enabled': True, 'paused': paused, 'revision': 'e' * 40,
                                                      'acceptanceCommitment': '1' * 64}}}
        command = ['helm', 'template', 'cloudlab-public-root', str(chart), '-n', 'argocd',
                   '--kube-version', '1.36.5', '-f', '-']
        result = subprocess.run(command, input=yaml.safe_dump(values).encode(), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        parent = next(obj for obj in yaml.safe_load_all(result.stdout) if obj and obj['kind'] == 'ApplicationSet'
                      and obj['metadata']['name'] == 'cloudlab-observability-gitops')
        declaration = {'parent': parent['spec'], 'paused': paused}
        evidence = {'acceptedRevision': 'b' * 40}
        desired = copy.deepcopy(parent['spec']['template']['spec'])
        for source in desired['sources']:
            if isinstance(source.get('targetRevision'), str) and 'Consumer source acceptance refused' in source['targetRevision']:
                source['targetRevision'] = 'b' * 40
        objects = {
            ('applicationset.argoproj.io', 'cloudlab-observability-gitops'): {
                'metadata': {'uid': 'telemetry-parent', 'labels': {'cloudlab.io/owner': 'observability-platform'},
                             'annotations': {'argocd.argoproj.io/tracking-id':
                                 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/cloudlab-observability-gitops'}},
                'spec': copy.deepcopy(parent['spec'])},
            ('application.argoproj.io', 'cloudlab-observability-gitops'): {
                'metadata': {'uid': 'telemetry-child', 'labels': {'cloudlab.io/owner': 'observability-platform'},
                             'annotations': {'argocd.argoproj.io/tracking-id':
                                 'cloudlab-public-root:argoproj.io/Application:argocd/cloudlab-observability-gitops'},
                             'ownerReferences': [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet',
                                 'name': 'cloudlab-observability-gitops', 'uid': 'telemetry-parent',
                                 'controller': True, 'blockOwnerDeletion': True}]},
                'spec': desired,
                'status': {'health': {'status': 'Healthy'}, 'sync': {'status': 'Synced'}}},
            ('application.argoproj.io', 'cloudlab-public-root'): {
                'metadata': {'uid': 'root'},
                'spec': {'source': {'helm': {'valuesObject': {'identity': {'enabled': True, 'argo': target}}}}}}}
        return repository, evidence, declaration, objects, target

    def test_telemetry_requires_exact_paused_aware_owner_parent_and_project(self):
        repository, evidence, declaration, objects, target = self.telemetry_fixture()
        read = lambda kind, name: copy.deepcopy(objects.get((kind, name)))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'identity-values-binding.json').write_text(json.dumps({'target': target, 'root_uid': 'root'}))
            with patch.object(verify_module, 'BASE', base):
                self.assertTrue(observability_healthy(repository, evidence, declaration, read))
                child = objects[('application.argoproj.io', 'cloudlab-observability-gitops')]
                for change in ('owner', 'tracking', 'ownerref', 'spec', 'project', 'operation', 'error', 'health', 'sync', 'parent', 'root'):
                    objects[('application.argoproj.io', 'cloudlab-observability-gitops')] = copy.deepcopy(child)
                    if change == 'owner': objects[('application.argoproj.io', 'cloudlab-observability-gitops')]['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
                    if change == 'tracking': objects[('application.argoproj.io', 'cloudlab-observability-gitops')]['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
                    if change == 'ownerref': objects[('application.argoproj.io', 'cloudlab-observability-gitops')]['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                    if change == 'spec': objects[('application.argoproj.io', 'cloudlab-observability-gitops')]['spec']['sources'][1]['targetRevision'] = 'c' * 40
                    if change == 'project': objects[('application.argoproj.io', 'cloudlab-observability-gitops')]['spec']['project'] = 'foreign'
                    if change == 'operation': objects[('application.argoproj.io', 'cloudlab-observability-gitops')]['operation'] = {'sync': {}}
                    if change == 'error': objects[('application.argoproj.io', 'cloudlab-observability-gitops')]['status']['conditions'] = [{'type': 'SyncError'}]
                    if change == 'health': objects[('application.argoproj.io', 'cloudlab-observability-gitops')]['status']['health']['status'] = 'Progressing'
                    if change == 'sync': objects[('application.argoproj.io', 'cloudlab-observability-gitops')]['status']['sync']['status'] = 'OutOfSync'
                    if change == 'parent': objects[('applicationset.argoproj.io', 'cloudlab-observability-gitops')]['spec'] = {}
                    if change == 'root': objects[('application.argoproj.io', 'cloudlab-public-root')]['metadata']['uid'] = 'foreign'
                    with self.subTest(change=change):
                        self.assertFalse(observability_healthy(repository, evidence, declaration, read))
                    objects[('applicationset.argoproj.io', 'cloudlab-observability-gitops')]['spec'] = copy.deepcopy(declaration['parent'])
                    objects[('application.argoproj.io', 'cloudlab-public-root')]['metadata']['uid'] = 'root'

    def test_paused_telemetry_relaxes_convergence_but_keeps_exact_ownership(self):
        repository, evidence, declaration, objects, _ = self.telemetry_fixture(paused=True)
        child = objects[('application.argoproj.io', 'cloudlab-observability-gitops')]
        child['status'] = {'health': {'status': 'Progressing'}, 'sync': {'status': 'OutOfSync'}}
        read = lambda kind, name: copy.deepcopy(objects.get((kind, name)))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'identity-values-binding.json').write_text(json.dumps(
                {'target': objects[('application.argoproj.io', 'cloudlab-public-root')]['spec']['source']['helm']['valuesObject']['identity']['argo'],
                 'root_uid': 'root'}))
            with patch.object(verify_module, 'BASE', base):
                self.assertTrue(observability_healthy(repository, evidence, declaration, read))
                child['spec']['sources'][1]['targetRevision'] = 'c' * 40
                self.assertFalse(observability_healthy(repository, evidence, declaration, read))

    def test_missing_paused_telemetry_contract_converges_as_enabled(self):
        repository, _, parented, objects, target = self.telemetry_fixture()
        declaration = {'parent': parented['parent']}
        observability = {'contract': {'context': {'observability': {'configuration': {'enabled': True}}}},
                         'acceptedRevision': 'b' * 40}
        payload = {'configuration_repository': repository, 'configuration_revision': 'd' * 40,
                   'sources': [], 'observability': observability}
        def request(*args): return json.dumps({'items': []})
        read = lambda kind, name: copy.deepcopy(objects.get((kind, name)))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'identity-values-binding.json').write_text(json.dumps({'target': target, 'root_uid': 'root'}))
            with patch.object(verify_module, 'BASE', base), \
                    patch('private_verify.kube', side_effect=request), \
                    patch('private_verify.get', side_effect=read), \
                    patch('private_verify.consumer_declaration', return_value=declaration), \
                    patch('private_verify.credential_owner'), patch('private_verify.foundation_sample', return_value=()), \
                    patch('private_verify.fingerprint', return_value=()), \
                    patch('private_verify.wait', side_effect=lambda check, description: self.assertTrue(check())), \
                    patch('private_verify.time.sleep'), patch('private_verify.time.monotonic', side_effect=[0, 1, 61, 62]):
                self.assertTrue(run(payload)['private_access_verified'])
        self.assertFalse(declaration['paused'])
