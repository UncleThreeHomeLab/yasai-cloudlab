import copy
import json
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

from playbooks.admission.files.chart import render

OWNER_POLICY = 'cloudlab-private-source-ownership'
SECRET_POLICY = 'cloudlab-private-source-credentials'


class PrivateSourcePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policies = {row['metadata']['name']: row for row in render(True)
                        if row['metadata']['name'] in (OWNER_POLICY, SECRET_POLICY)}

    def evaluate(self, policy, resource, *, old=None, accepted=True, operation=None):
        operation = operation or ('UPDATE' if old is not None else 'CREATE')
        original = self.policies[policy]
        tested = copy.deepcopy(original)
        if old is not None and old != resource:
            # The pinned CLI binds native UPDATE oldObject to object; inject only the distinct fixture binding.
            expressions = tested['spec']['variables'] + tested['spec']['validations']
            for row in expressions:
                row['expression'] = re.sub(r'\boldObject\b', 'variables.previousFixture', row['expression'])
            tested['spec']['variables'].insert(0, {'name': 'previousFixture',
                'expression': 'yaml.parse(' + json.dumps(json.dumps(old)) + ')'})
            restored = copy.deepcopy(tested)
            restored['spec']['variables'].pop(0)
            for row in restored['spec']['variables'] + restored['spec']['validations']:
                row['expression'] = row['expression'].replace('variables.previousFixture', 'oldObject')
            self.assertEqual(restored, original)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                'policy.yaml': tested, 'resource.yaml': resource,
                'values.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Values',
                    'globalValues': {'request.operation': operation, 'oldObject': old or {}}},
                'kyverno-test.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Test',
                    'metadata': {'name': 'private-source'}, 'policies': ['policy.yaml'],
                    'resources': ['resource.yaml'], 'variables': 'values.yaml',
                    'results': [{'isValidatingPolicy': True, 'kind': resource['kind'], 'policy': policy,
                        'resources': [resource['metadata']['name']], 'result': 'pass' if accepted else 'fail'}]}}
            for name, value in files.items(): (root / name).write_text(yaml.safe_dump(value))
            result = subprocess.run(['kyverno', 'test', str(root)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('error)', result.stdout)

    def registration(self, kind):
        group = '' if kind == 'Namespace' else 'external-secrets.io' if kind == 'ExternalSecret' else 'argoproj.io'
        namespace = 'argocd'
        metadata = {'name': 'cloudlab-private-fixture', 'labels': {'cloudlab.io/owner': 'private-gitops'},
                    'annotations': {'argocd.argoproj.io/tracking-id':
                        'cloudlab-private-sources:' + group + '/' + kind + ':' + namespace + '/cloudlab-private-fixture'}}
        if kind != 'Namespace': metadata['namespace'] = namespace
        return {'apiVersion': 'v1' if not group else group + ('/v1' if kind == 'ExternalSecret' else '/v1alpha1'),
                'kind': kind, 'metadata': metadata}

    def credential(self):
        return {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {
            'name': 'cloudlab-private-fixture', 'namespace': 'argocd', 'labels': {
                'cloudlab.io/owner': 'private-gitops', 'argocd.argoproj.io/secret-type': 'repository'},
            'ownerReferences': [{'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret',
                                 'name': 'cloudlab-private-fixture', 'uid': 'external-uid', 'controller': True}]},
            'type': 'Opaque', 'data': {}}

    def test_fresh_registration_and_same_owner_update_are_allowed(self):
        for kind in ('Namespace', 'AppProject', 'Application', 'ExternalSecret'):
            with self.subTest(kind=kind):
                resource = self.registration(kind)
                self.evaluate(OWNER_POLICY, resource)
                self.evaluate(OWNER_POLICY, resource, old=copy.deepcopy(resource))

    def test_untracked_and_foreign_updates_cannot_be_adopted(self):
        for kind in ('Namespace', 'AppProject', 'Application', 'ExternalSecret'):
            resource = self.registration(kind)
            for change in ('untracked', 'foreign'):
                old = copy.deepcopy(resource)
                if change == 'untracked': old['metadata'].pop('annotations')
                else: old['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
                with self.subTest(kind=kind, change=change):
                    self.evaluate(OWNER_POLICY, resource, old=old, accepted=False)

    def test_cluster_namespace_tracking_uses_only_catalog_destination_namespace(self):
        good = self.registration('Namespace')
        self.assertNotIn('namespace', good['metadata'])
        for namespace in ('', 'cloudlab-policy'):
            resource = copy.deepcopy(good)
            resource['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = (
                'cloudlab-private-sources:/Namespace:' + namespace + '/cloudlab-private-fixture')
            with self.subTest(namespace=namespace): self.evaluate(OWNER_POLICY, resource, accepted=False)

    def test_tracking_or_owner_removal_and_cascading_application_are_denied(self):
        old = self.registration('Application')
        for change in ('tracking', 'owner', 'both', 'finalizer'):
            new = copy.deepcopy(old)
            if change in ('tracking', 'both'): new['metadata'].pop('annotations')
            if change in ('owner', 'both'): new['metadata'].pop('labels')
            if change == 'finalizer': new['metadata']['finalizers'] = ['resources-finalizer.argocd.argoproj.io']
            with self.subTest(change=change): self.evaluate(OWNER_POLICY, new, old=old, accepted=False)

    def test_unrelated_resources_and_legacy_untracked_creation_are_unchanged(self):
        self.evaluate(OWNER_POLICY, {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'unrelated'}})
        legacy = self.registration('Namespace')
        legacy['metadata'].pop('annotations')
        self.evaluate(OWNER_POLICY, legacy)
        foreign = self.credential()
        foreign['metadata']['labels'] = {'cloudlab.io/owner': 'another-platform'}
        foreign['metadata'].pop('ownerReferences')
        self.evaluate(SECRET_POLICY, foreign, old=copy.deepcopy(foreign))

    def test_new_credential_and_same_owner_refresh_are_allowed(self):
        for central in (False, True):
            secret = self.credential()
            if central:
                secret['metadata']['name'] = 'cloudlab-private-sources-source'
                secret['metadata']['labels']['cloudlab.io/owner'] = 'private-source-platform'
                secret['metadata']['ownerReferences'][0]['name'] = secret['metadata']['name']
            with self.subTest(central=central):
                self.evaluate(SECRET_POLICY, secret)
                self.evaluate(SECRET_POLICY, secret, old=copy.deepcopy(secret))

    def test_unowned_foreign_or_replaced_eso_credential_cannot_be_adopted(self):
        secret = self.credential()
        for change in ('unowned', 'foreign-label', 'different-uid', 'different-name', 'not-controller'):
            old = copy.deepcopy(secret)
            if change == 'unowned': old['metadata'].pop('ownerReferences')
            if change == 'foreign-label': old['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            if change == 'different-uid': old['metadata']['ownerReferences'][0]['uid'] = 'replaced-uid'
            if change == 'different-name': old['metadata']['ownerReferences'][0]['name'] = 'foreign'
            if change == 'not-controller': old['metadata']['ownerReferences'][0]['controller'] = False
            with self.subTest(change=change): self.evaluate(SECRET_POLICY, secret, old=old, accepted=False)
