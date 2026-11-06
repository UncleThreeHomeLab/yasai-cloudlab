"""Native CEL coverage for namespace selectors and least-privilege labels."""
import copy
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml

from playbooks.admission.files.chart import render
from playbooks.admission.tests.fixtures import namespace
from playbooks.admission.files.verify import namespace_guard_desired, NAMESPACE_GUARD_NAME

POLICY = 'cloudlab-workload-namespace'


class NamespacePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = next(row for row in render(True) if row['metadata']['name'] == POLICY)

    def evaluate(self, resource, *, old=None, accepted=True):
        tested = copy.deepcopy(self.policy)
        if old is not None and old != resource:
            # The pinned CLI aliases native oldObject to object on UPDATE.
            sections = ('variables', 'validations', 'matchConditions')
            for section in sections:
                for row in tested['spec'].get(section, []):
                    row['expression'] = re.sub(r'\boldObject\b', 'variables.previousFixture', row['expression'])
            tested['spec']['variables'].insert(0, {'name': 'previousFixture',
                'expression': 'yaml.parse(' + json.dumps(json.dumps(old)) + ')'})
            restored = copy.deepcopy(tested)
            restored['spec']['variables'].pop(0)
            for section in sections:
                for row in restored['spec'].get(section, []):
                    row['expression'] = row['expression'].replace('variables.previousFixture', 'oldObject')
            self.assertEqual(restored, self.policy)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = {
                'policy.yaml': tested, 'resource.yaml': resource,
                'values.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Values',
                    'globalValues': {'request.operation': 'UPDATE' if old is not None else 'CREATE'}},
                'kyverno-test.yaml': {'apiVersion': 'cli.kyverno.io/v1alpha1', 'kind': 'Test',
                    'metadata': {'name': 'namespace'}, 'policies': ['policy.yaml'],
                    'resources': ['resource.yaml'], 'variables': 'values.yaml',
                    'results': [{'isValidatingPolicy': True, 'kind': 'Namespace', 'policy': POLICY,
                        'resources': [resource['metadata']['name']], 'result': 'pass' if accepted else 'fail'}]}}
            for name, value in files.items():
                (root / name).write_text(yaml.safe_dump(value))
            result = subprocess.run(['kyverno', 'test', str(root)], capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('error)', result.stdout)

    def test_fresh_ordinary_and_composition_namespaces_pass_the_identity_guard(self):
        for composition in (False, True):
            with self.subTest(composition=composition):
                resource = namespace(composition=composition)
                self.evaluate(resource)
                self.evaluate(resource, old=copy.deepcopy(resource))

    def test_baseline_label_removal_or_changes_are_denied(self):
        old = namespace()
        for key, wrong in (('cloudlab.io/owner', 'foreign'), ('istio.io/dataplane-mode', 'none'),
                           ('cloudlab.io/service-secrets', 'other'),
                           ('pod-security.kubernetes.io/enforce', 'privileged'),
                           ('pod-security.kubernetes.io/enforce-version', 'latest')):
            for action in ('remove', 'change'):
                resource = copy.deepcopy(old)
                if action == 'remove': resource['metadata']['labels'].pop(key)
                else: resource['metadata']['labels'][key] = wrong
                with self.subTest(key=key, action=action):
                    self.evaluate(resource, old=old, accepted=False)
        resource = copy.deepcopy(old)
        resource['metadata'].pop('labels')
        self.evaluate(resource, old=old, accepted=False)
        self.evaluate(resource, accepted=False)

    def test_composition_labels_cannot_leave_privileges_after_marker_removal(self):
        old = namespace(composition=True)
        for key, wrong in (('cloudlab.io/composition', 'anything'),
                           ('pod-security.kubernetes.io/audit', 'privileged'),
                           ('pod-security.kubernetes.io/warn', 'privileged')):
            for action in ('remove', 'change'):
                resource = copy.deepcopy(old)
                if action == 'remove': resource['metadata']['labels'].pop(key)
                else: resource['metadata']['labels'][key] = wrong
                with self.subTest(key=key, action=action):
                    self.evaluate(resource, old=old, accepted=False)
        resource = copy.deepcopy(old)
        resource['metadata'].pop('labels')
        self.evaluate(resource, old=old, accepted=False)
        self.evaluate(namespace(), old=old)

    def test_existing_foreign_or_unowned_namespace_cannot_be_adopted(self):
        resource = namespace()
        for owner in (None, 'foreign'):
            old = copy.deepcopy(resource)
            if owner is None: old['metadata'].pop('labels')
            else: old['metadata']['labels']['cloudlab.io/owner'] = owner
            with self.subTest(owner=owner): self.evaluate(resource, old=old, accepted=False)
        old = namespace()
        old['metadata']['labels'] = {'cloudlab.io/owner': 'service-platform'}
        self.evaluate(resource, old=old)

    def test_unrelated_platform_namespaces_are_unchanged_and_old_labels_still_select(self):
        resource = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'external-secrets',
                    'labels': {'cloudlab.io/service-secrets': 'approved'}}}
        self.evaluate(resource)
        self.evaluate(resource, old=copy.deepcopy(resource))
        resource['metadata'].pop('labels')
        self.evaluate(resource)
        for marker in ({'cloudlab.io/owner': 'service-platform'}, {'cloudlab.io/composition': 'approved'}):
            old = copy.deepcopy(resource)
            old['metadata']['labels'] = marker
            self.evaluate(resource, old=old, accepted=False)
            self.evaluate(old, accepted=False)

    def test_unrelated_metadata_and_finalizers_remain_mutable(self):
        old = namespace()
        resource = copy.deepcopy(old)
        resource['metadata'].update({'annotations': {'example.invalid/review': 'done'}, 'finalizers': ['example.invalid/cleanup']})
        resource['metadata']['labels']['example.invalid/team'] = 'payments'
        resource['spec'] = {'finalizers': ['kubernetes']}
        self.evaluate(resource, old=old)

    def test_guard_is_always_fail_closed_and_does_not_match_delete_or_subresources(self):
        for actions in (['Deny'], ['Audit', 'Warn']):
            policy = next(row for row in render(True, {'validationActions': actions}) if row['metadata']['name'] == POLICY)
            self.assertEqual(policy['spec']['validationActions'], ['Deny'])
            self.assertEqual(policy['spec']['failurePolicy'], 'Fail')
            self.assertNotIn('namespaceSelector', policy['spec']['matchConstraints'])
            self.assertEqual(policy['spec']['matchConstraints']['resourceRules'], [{
                'apiGroups': [''], 'apiVersions': ['v1'], 'operations': ['CREATE', 'UPDATE'], 'resources': ['namespaces']}])

    def test_native_companion_reuses_the_exact_namespace_contract_and_retains_legacy_guards(self):
        for actions in (['Deny'], ['Audit', 'Warn']):
            documents = render(True, {'validationActions': actions})
            native = [next(row for row in documents if row['kind'] == kind and
                row['metadata']['name'] == NAMESPACE_GUARD_NAME) for kind in
                ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding')]
            self.assertEqual(native, namespace_guard_desired())
            self.assertEqual(native[0]['spec']['variables'], self.policy['spec']['variables'])
            self.assertEqual(native[0]['spec']['validations'], self.policy['spec']['validations'])
            base = Path(__file__).resolve().parents[4] / 'platform/delivery/admission/policies/templates'
            for name in ('workload-namespace', 'composition-namespace'):
                source = yaml.safe_load((base / (name + '.yaml')).read_text())
                actual = next(row for row in documents if row['kind'] == 'ValidatingPolicy' and
                              row['metadata']['name'] == 'cloudlab-' + name)
                self.assertEqual(actual, source)
