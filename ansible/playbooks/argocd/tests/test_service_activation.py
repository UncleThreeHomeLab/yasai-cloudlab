import copy
from pathlib import Path
import unittest

import yaml
from fixtures import binding_fixture, namespace_probe
from service_activation import guard, validate


class ServiceActivationTests(unittest.TestCase):
    def setUp(self):
        self.objects, _, self.target, checkpoint = binding_fixture()
        self.evidence = checkpoint['serviceActivation']
        self.evidence['catalog']['catalog'] = [{'definition': {}, 'publication': 'ready',
            'approval': {'name': 'synthetic', 'namespace': 'cloudlab-app-synthetic'}}]

    def guard(self, evidence, target, read, root=None, **kwargs):
        return guard(evidence, target, read, root, probe=kwargs.pop('probe', namespace_probe), **kwargs)

    def read(self, kind, name):
        return self.objects.get((kind, name))

    def test_missing_resources_allow_initial_creation_without_any_write(self):
        captured = self.guard(self.evidence, self.target, self.read)
        self.assertTrue(captured['namespaceAuthority'])
        self.assertEqual({key: value for key, value in captured.items() if key != 'namespaceAuthority'}, self.evidence)

    def test_foreign_tracked_or_untracked_namespace_project_and_set_refused(self):
        for kind, name in [('namespace', 'cloudlab-app-synthetic'), ('appproject.argoproj.io', 'synthetic'),
                           ('applicationset.argoproj.io', 'synthetic')]:
            for tracking in (None, 'foreign:argoproj.io/AppProject:argocd/synthetic'):
                with self.subTest(kind=kind, tracking=tracking):
                    obj = {'metadata': {'uid': 'foreign', 'labels': {'cloudlab.io/owner': 'foreign'}}}
                    if tracking: obj['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': tracking}
                    self.objects[kind, name] = obj
                    with self.assertRaises(RuntimeError): self.guard(self.evidence, self.target, self.read)
                    self.objects.pop((kind, name))

    def test_composition_requires_ready_admission_at_current_generation(self):
        self.evidence['catalog']['catalog'][0]['approval']['composition'] = {'approved': True}
        key = ('validatingpolicy.policies.kyverno.io', 'cloudlab-composition-namespace')
        with self.assertRaisesRegex(RuntimeError, 'admission'): self.guard(self.evidence, self.target, self.read)
        self.objects[key] = {'metadata': {'generation': 3}, 'status': {'conditionStatus': {
            'ready': True, 'conditions': [{'status': 'True', 'observedGeneration': 3}]}}}
        self.guard(self.evidence, self.target, self.read)
        self.objects[key]['status']['conditionStatus']['conditions'][0]['observedGeneration'] = 2
        with self.assertRaisesRegex(RuntimeError, 'admission'): self.guard(self.evidence, self.target, self.read)

    def test_snapshot_coordinates_and_catalog_scope_are_required(self):
        for field, value in [('private_revision', 'd' * 40), ('revision', 'main'),
                             ('private_repository', 'https://github.com/foreign/private.git'),
                             ('catalog', {'catalog': [], 'dataApprovals': []})]:
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate(dict(self.evidence, **{field: value}), self.target)
        foreign = copy.deepcopy(self.evidence)
        foreign['catalog']['catalog'][0]['approval']['namespace'] = 'kube-system'
        with self.assertRaises(RuntimeError): validate(foreign, self.target)
        for extra in ({'namespaceGuard': None}, {'namespaceAuthority': None}, {'namespaceAuthority': [{}]}):
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                validate(dict(self.evidence, **extra), self.target)
        for field, value in [('acceptanceCommitment', '0' * 64), ('acceptedRevision', 'd' * 40)]:
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate(dict(self.evidence, **{field: value}), self.target)
        dropped = dict(self.evidence); dropped.pop('applicationSet')
        with self.assertRaises(RuntimeError): validate(dropped, self.target)

    def test_prepare_without_acceptance_is_refused(self):
        from service_activation import prepare
        root = Path(__file__).resolve().parents[4]
        public = yaml.safe_load((root / 'gitops/roots/public/values.yaml').read_text())
        public['repository'] = 'https://github.com/example/platform.git'
        with self.assertRaisesRegex(RuntimeError, 'authenticated receipt'):
            prepare(public, self.target['valuesRepository'], self.target['valuesRevision'],
                    {'catalog': [], 'dataApprovals': {}})

    def catalog_objects(self):
        from service_activation import APP, OWNER, TRACKING
        evidence = self.evidence
        parent = {'metadata': {'uid': 'services-parent', 'labels': {'cloudlab.io/owner': OWNER},
                               'annotations': {'argocd.argoproj.io/tracking-id':
                                   'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + APP}},
                  'spec': copy.deepcopy(evidence['applicationSet'])}
        app = {'metadata': {'uid': 'catalog', 'labels': {'cloudlab.io/owner': OWNER},
                            'annotations': {'argocd.argoproj.io/tracking-id': TRACKING},
                            'ownerReferences': [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet',
                                'name': APP, 'uid': 'services-parent', 'controller': True, 'blockOwnerDeletion': True}]},
               'spec': {'project': APP, 'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'},
                        'syncPolicy': {'automated': {'prune': False}}, 'sources': [
                    {'repoURL': evidence['repository'], 'targetRevision': evidence['revision'],
                     'path': 'platform/delivery/services', 'helm': {
                         'valueFiles': ['$values/services/catalog.json', '$values/identity/argo-values.yaml'],
                         'valuesObject': {'repository': evidence['repository'], 'revision': evidence['revision'],
                                          'telemetry': evidence['telemetry']}}},
                    {'repoURL': evidence['private_repository'], 'targetRevision': evidence['acceptedRevision'], 'ref': 'values'}]},
               'status': {'health': {'status': 'Healthy'}, 'sync': {'status': 'Synced'}}}
        return parent, app

    def test_existing_catalog_requires_exact_uid_source_owner_and_idle_state(self):
        from service_activation import APP
        parent, app = self.catalog_objects()
        self.objects['applicationset.argoproj.io', APP] = parent
        self.objects['application.argoproj.io', APP] = app
        captured = self.guard(self.evidence, self.target, self.read)
        self.assertEqual(captured['existing']['uid'], 'catalog')
        self.assertEqual(captured['existing']['sources'], app['spec']['sources'])
        for change in ('uid', 'source', 'values', 'owner', 'operation', 'running', 'finalizer', 'deleting',
                       'health', 'tracking', 'ownerref', 'parentspec'):
            current = copy.deepcopy(app)
            if change == 'uid': current['metadata']['uid'] = 'replaced'
            if change == 'source': current['spec']['sources'][0]['targetRevision'] = 'd' * 40
            if change == 'values': current['spec']['sources'][1]['targetRevision'] = 'd' * 40
            if change == 'owner': current['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            if change == 'operation': current['operation'] = {'sync': {}}
            if change == 'running': current['status']['operationState'] = {'phase': 'Running'}
            if change == 'finalizer': current['metadata']['finalizers'] = ['foreign']
            if change == 'deleting': current['metadata']['deletionTimestamp'] = 'synthetic'
            if change == 'health': current['status']['health']['status'] = 'Progressing'
            if change == 'tracking': current['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
            if change == 'ownerref': current['metadata']['ownerReferences'][0]['uid'] = 'foreign'
            if change == 'parentspec': self.objects['applicationset.argoproj.io', APP]['spec'] = {}
            self.objects['application.argoproj.io', APP] = current
            with self.subTest(change=change), self.assertRaises(RuntimeError): self.guard(captured, self.target, self.read)
            self.objects['applicationset.argoproj.io', APP] = copy.deepcopy(parent)

    def test_catalog_without_native_parent_is_refused(self):
        from service_activation import APP
        _, app = self.catalog_objects()
        self.objects['application.argoproj.io', APP] = app
        with self.assertRaises(RuntimeError): self.guard(self.evidence, self.target, self.read)

    def test_both_installed_source_transition_paths_include_activation_guard(self):
        root = Path(__file__).resolve().parents[4]
        for relative in ('ansible/playbooks/argocd/tasks/main.yml', 'ansible/playbooks/argocd/tasks/runtime.yml'):
            tasks = yaml.safe_load((root / relative).read_text())
            expanded = []
            for task in tasks:
                if task.get('ansible.builtin.import_tasks') == 'runtime.yml':
                    expanded.extend(yaml.safe_load((root / 'ansible/playbooks/argocd/tasks/runtime.yml').read_text()))
                else:
                    expanded.append(task)
            destination = '/opt/cloudlab/gitops/{{ item }}' if relative.endswith('main.yml') else '/opt/cloudlab/playbooks/argocd/files/{{ item }}'
            copies = [task for task in expanded if 'source_transition.py' in task.get('loop', [])
                      and task.get('ansible.builtin.copy', {}).get('dest') == destination]
            self.assertEqual(len(copies), 1)
            self.assertIn('service_activation.py', copies[0]['loop'])
            self.assertIn('private_activation.py', copies[0]['loop'])
            self.assertIn('data_activation.py', copies[0]['loop'])
