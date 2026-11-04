import copy
from pathlib import Path
import unittest

import yaml
from fixtures import binding_fixture
from service_activation import guard, validate


class ServiceActivationTests(unittest.TestCase):
    def setUp(self):
        self.objects, _, self.target, checkpoint = binding_fixture()
        self.evidence = checkpoint['serviceActivation']
        self.evidence['catalog']['catalog'] = [{'definition': {}, 'publication': 'ready',
            'approval': {'name': 'synthetic', 'namespace': 'cloudlab-app-synthetic'}}]

    def read(self, kind, name):
        return self.objects.get((kind, name))

    def test_missing_resources_allow_initial_creation_without_any_write(self):
        self.assertEqual(guard(self.evidence, self.target, self.read), self.evidence)

    def test_foreign_tracked_or_untracked_namespace_project_and_set_refused(self):
        for kind, name in [('namespace', 'cloudlab-app-synthetic'), ('appproject.argoproj.io', 'synthetic'),
                           ('applicationset.argoproj.io', 'synthetic')]:
            for tracking in (None, 'foreign:argoproj.io/AppProject:argocd/synthetic'):
                with self.subTest(kind=kind, tracking=tracking):
                    obj = {'metadata': {'uid': 'foreign', 'labels': {'cloudlab.io/owner': 'foreign'}}}
                    if tracking: obj['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': tracking}
                    self.objects[kind, name] = obj
                    with self.assertRaises(RuntimeError): guard(self.evidence, self.target, self.read)
                    self.objects.pop((kind, name))

    def test_composition_requires_ready_admission_at_current_generation(self):
        self.evidence['catalog']['catalog'][0]['approval']['composition'] = {'approved': True}
        key = ('validatingpolicy.policies.kyverno.io', 'cloudlab-composition-namespace')
        with self.assertRaisesRegex(RuntimeError, 'admission'): guard(self.evidence, self.target, self.read)
        self.objects[key] = {'metadata': {'generation': 3}, 'status': {'conditionStatus': {
            'ready': True, 'conditions': [{'status': 'True', 'observedGeneration': 3}]}}}
        guard(self.evidence, self.target, self.read)
        self.objects[key]['status']['conditionStatus']['conditions'][0]['observedGeneration'] = 2
        with self.assertRaisesRegex(RuntimeError, 'admission'): guard(self.evidence, self.target, self.read)

    def test_snapshot_coordinates_and_catalog_scope_are_required(self):
        for field, value in [('private_revision', 'd' * 40), ('revision', 'main'),
                             ('private_repository', 'https://github.com/foreign/private.git'),
                             ('catalog', {'catalog': [], 'dataApprovals': []})]:
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate(dict(self.evidence, **{field: value}), self.target)
        foreign = copy.deepcopy(self.evidence)
        foreign['catalog']['catalog'][0]['approval']['namespace'] = 'kube-system'
        with self.assertRaises(RuntimeError): validate(foreign, self.target)

    def test_existing_catalog_requires_exact_uid_source_owner_and_idle_state(self):
        from service_activation import APP, OWNER
        evidence = self.evidence
        app = {'metadata': {'uid': 'catalog', 'labels': {'cloudlab.io/owner': OWNER},
                           'managedFields': [{'manager': OWNER, 'operation': 'Apply',
                                             'fieldsV1': {'f:spec': {'f:sources': {}}}}]},
               'spec': {'project': APP, 'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
                        'syncPolicy': {'automated': {'prune': False}}, 'sources': [
                    {'repoURL': evidence['repository'], 'targetRevision': evidence['revision'],
                     'path': 'platform/delivery/services', 'helm': {
                         'valueFiles': ['$values/services/catalog.json', '$values/identity/argo-values.yaml'],
                         'valuesObject': {'repository': evidence['repository'], 'revision': evidence['revision'], 'telemetry': False}}},
                    {'repoURL': evidence['private_repository'], 'targetRevision': 'main', 'ref': 'values'}]},
               'status': {'health': {'status': 'Healthy'}, 'sync': {'status': 'Synced'}}}
        self.objects['application.argoproj.io', APP] = app
        captured = guard(evidence, self.target, self.read)
        self.assertEqual(captured['existing']['uid'], 'catalog')
        for change in ('uid', 'source', 'owner', 'manager', 'operation', 'finalizer', 'deleting', 'health'):
            current = copy.deepcopy(app)
            if change == 'uid': current['metadata']['uid'] = 'replaced'
            if change == 'source': current['spec']['sources'][0]['targetRevision'] = 'd' * 40
            if change == 'owner': current['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            if change == 'manager': current['metadata']['managedFields'][0]['operation'] = 'Update'
            if change == 'operation': current['operation'] = {'sync': {}}
            if change == 'finalizer': current['metadata']['finalizers'] = ['foreign']
            if change == 'deleting': current['metadata']['deletionTimestamp'] = 'synthetic'
            if change == 'health': current['status']['health']['status'] = 'Progressing'
            self.objects['application.argoproj.io', APP] = current
            with self.subTest(change=change), self.assertRaises(RuntimeError): guard(captured, self.target, self.read)

        from service_activation import TRACKING
        progressing = copy.deepcopy(app)
        progressing['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': TRACKING}
        progressing['status'] = {'health': {'status': 'Progressing'}, 'sync': {'status': 'OutOfSync'},
                                 'conditions': [{'type': 'ComparisonError'}]}
        self.objects['application.argoproj.io', APP] = progressing
        tracked = guard(evidence, self.target, self.read)
        self.assertFalse(tracked['existing']['adoption'])
        with self.assertRaises(RuntimeError): guard(captured, self.target, self.read)
        for change in ('operation', 'running', 'uid', 'source', 'deleting'):
            current = copy.deepcopy(progressing)
            if change == 'operation': current['operation'] = {'sync': {'revision': 'foreign'}}
            if change == 'running': current['status']['operationState'] = {'phase': 'Running'}
            if change == 'uid': current['metadata']['uid'] = 'foreign'
            if change == 'source': current['spec']['sources'][0]['targetRevision'] = 'd' * 40
            if change == 'deleting': current['metadata']['deletionTimestamp'] = 'synthetic'
            self.objects['application.argoproj.io', APP] = current
            with self.subTest(tracked_change=change), self.assertRaises(RuntimeError):
                guard(tracked, self.target, self.read)

    def test_both_installed_source_transition_paths_include_activation_guard(self):
        root = Path(__file__).resolve().parents[4]
        for relative in ('ansible/playbooks/argocd/tasks/main.yml', 'ansible/playbooks/argocd/tasks/runtime.yml'):
            tasks = yaml.safe_load((root / relative).read_text())
            copies = [task for task in tasks if 'source_transition.py' in task.get('loop', [])]
            self.assertEqual(len(copies), 1)
            self.assertIn('service_activation.py', copies[0]['loop'])
            self.assertIn('private_activation.py', copies[0]['loop'])
