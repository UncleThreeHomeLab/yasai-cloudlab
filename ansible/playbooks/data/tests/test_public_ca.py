"""Native public trust repair retains scope, adoption barriers and CAS semantics."""
import copy
import unittest

from playbooks.data.tests.fixtures import OWNER, PUBLIC, retained, run_native


class PublicCATests(unittest.TestCase):
    def assert_native(self, values, expected=0):
        result, output = run_native(values)
        self.assertEqual(result.returncode == 0, expected == 0, result.stdout + result.stderr)
        return output

    def test_noop_missing_namespace_and_create_only_public_trust(self):
        self.assertEqual(self.assert_native(retained()), {})
        values = retained()
        values['fixture_namespace'] = None
        self.assertEqual(self.assert_native(values), {})
        values = retained()
        values['fixture_current'] = None
        document = self.assert_native(values)['create']
        self.assertEqual(document, {'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': {
            'name': 'database-ca', 'namespace': 'cloudlab-app-notes',
            'labels': {'cloudlab.io/owner': OWNER}}, 'data': {'ca.crt': PUBLIC}})

    def test_rotation_uses_exact_uid_version_and_preserves_other_metadata(self):
        values = retained()
        values['fixture_current']['data']['ca.crt'] = 'old'
        patch = self.assert_native(values)['patch']
        self.assertEqual(patch[:2], [
            {'op': 'test', 'path': '/metadata/uid', 'value': 'retained-target'},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '7'}])
        self.assertEqual(patch[2], {'op': 'add', 'path': '/data', 'value': {'ca.crt': PUBLIC}})
        self.assertEqual(patch[3]['value'], {'cloudlab.io/owner': OWNER, 'retained-label': 'keep'})
        self.assertEqual(len(patch), 4)
        self.assertNotIn('never-project', str(patch))

    def test_ownership_maintenance_and_namespace_barriers_fail_without_writes(self):
        alterations = [
            lambda v: v['fixture_secret']['data'].update({'ca.crt': v['fixture_secret']['data']['ca.crt'] + '!'}),
            lambda v: v['fixture_cluster']['metadata'].update(uid='replacement'),
            lambda v: v['fixture_namespace']['metadata'].update(annotations={}),
            lambda v: v['fixture_namespace']['metadata'].update(ownerReferences=[{'uid': 'foreign'}]),
            lambda v: v['fixture_current']['metadata']['labels'].update({'cloudlab.io/owner': 'foreign'}),
            lambda v: v['fixture_current']['metadata'].update(ownerReferences=[{'uid': 'foreign'}]),
            lambda v: v['fixture_current']['data'].update(unrelated='preserve'),
            lambda v: v['fixture_application']['spec']['source']['helm']['valuesObject'].update(maintenance=True),
            lambda v: v['fixture_application']['spec']['source']['helm']['valuesObject'].update(serviceConsumers=['argocd']),
            lambda v: v['fixture_application']['metadata']['labels'].update({'cloudlab.io/owner': 'foreign'}),
        ]
        for alter in alterations:
            values = retained()
            alter(values)
            with self.subTest(alter=alter):
                self.assertEqual(self.assert_native(values, expected=1), {})

    def test_argo_handoff_waits_for_current_owner_and_accepts_noop_revision(self):
        values = retained()
        values['fixture_current']['metadata']['labels'].pop('cloudlab.io/owner')
        values['fixture_current']['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'notes-notes:/ConfigMap:cloudlab-app-notes/database-ca'
        alterations = [
            lambda v: v['fixture_prior']['status']['sync'].update(revision='b'*40),
            lambda v: v['fixture_prior']['status']['sync'].update(status='OutOfSync'),
            lambda v: v['fixture_prior']['status']['health'].update(status='Progressing'),
            lambda v: v['fixture_prior']['status']['operationState'].update(phase='Running'),
            lambda v: v['fixture_prior'].update(operation={'sync': {}}),
            lambda v: v['fixture_prior']['status'].update(conditions=[{'type': 'ComparisonError'}]),
            lambda v: v['fixture_prior']['spec']['source']['helm']['valuesObject'].update(definition={}),
            lambda v: v.update(fixture_prior=None),
        ]
        for alter in alterations:
            pending = copy.deepcopy(values)
            alter(pending)
            with self.subTest(alter=alter):
                self.assertEqual(self.assert_native(pending), {})
        patch = self.assert_native(values)['patch']
        self.assertEqual(patch[-1], {'op': 'remove', 'path': '/metadata/annotations/argocd.argoproj.io~1tracking-id'})
        values['fixture_current']['metadata']['labels']['cloudlab.io/owner'] = OWNER
        self.assertEqual(self.assert_native(values, expected=1), {})
