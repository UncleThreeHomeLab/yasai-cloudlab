import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

from fixtures import binding_fixture, private_policies, private_probe
from private_activation import APP, OWNER, POLICIES, TRACKING, guard, prepare


class PrivateActivationTests(unittest.TestCase):
    def setUp(self):
        self.objects, _, self.target, _ = binding_fixture()
        self.public = {'repository': 'https://github.com/example/platform.git',
            'privateSources': {'enabled': True, 'revision': 'c' * 40},
            'admission': {'enabled': True}, 'externalSecrets': {'enabled': True, 'reconcile': True}}
        self.registry = {'sources': [{'name': 'fixture', 'repository': self.target['valuesRepository'],
                                     'revision': 'main', 'path': 'gitops'}]}
        self.evidence = prepare(self.public, self.target['valuesRepository'], self.target['valuesRevision'], self.registry)
        self.objects.update(private_policies(self.evidence))

    def read(self, kind, name): return self.objects.get((kind, name))

    def check(self, evidence=None, probe=None):
        return guard(evidence or self.evidence, self.target, self.read,
                     probe=probe or (lambda document: private_probe(self.evidence, document)))

    def test_missing_resources_allow_initial_creation_only_with_ready_policies(self):
        checked = self.check()
        self.assertEqual(checked['registry'], self.registry)
        policy = self.objects['validatingpolicy.policies.kyverno.io', POLICIES[0]]
        policy['status']['conditionStatus']['conditions'][0]['observedGeneration'] = 1
        with self.assertRaisesRegex(RuntimeError, 'ready webhook contract'): self.check()

    def test_foreign_or_untracked_entry_resources_and_credentials_are_refused(self):
        for kind in ('namespace', 'appproject.argoproj.io', 'application.argoproj.io',
                     'externalsecret.external-secrets.io', 'secret'):
            with self.subTest(kind=kind):
                key = kind, 'cloudlab-private-fixture'
                self.objects[key] = {'metadata': {'uid': 'foreign'}}
                with self.assertRaisesRegex(RuntimeError, 'another owner'): self.check()
                self.objects.pop(key)

    def test_central_catalog_resources_also_refuse_implicit_adoption(self):
        for kind, name in (('appproject.argoproj.io', APP),
                           ('externalsecret.external-secrets.io', APP + '-source'), ('secret', APP + '-source')):
            with self.subTest(kind=kind):
                self.objects[kind, name] = {'metadata': {'uid': 'foreign'}}
                with self.assertRaisesRegex(RuntimeError, 'another owner'): self.check()
                self.objects.pop((kind, name))

    def test_recognized_central_resource_uid_is_preserved_across_retry(self):
        metadata = {'uid': 'project', 'labels': {'cloudlab.io/owner': OWNER}, 'annotations': {
            'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APP}}
        self.objects['appproject.argoproj.io', APP] = {'metadata': metadata}
        captured = self.check()
        metadata['uid'] = 'changed'
        with self.assertRaisesRegex(RuntimeError, 'identity changed'): self.check(captured)

    def test_existing_registered_namespace_uid_is_preserved_across_retry(self):
        metadata = {'uid': 'namespace', 'labels': {'cloudlab.io/owner': 'private-gitops'}, 'annotations': {
            'argocd.argoproj.io/tracking-id': APP + ':/Namespace:argocd/cloudlab-private-fixture'}}
        self.objects['namespace', 'cloudlab-private-fixture'] = {'metadata': metadata}
        captured = self.check()
        metadata['uid'] = 'changed'
        with self.assertRaisesRegex(RuntimeError, 'identity changed'): self.check(captured)

    def test_cluster_namespace_tracking_requires_catalog_destination_namespace(self):
        for namespace in ('', 'cloudlab-policy'):
            metadata = {'uid': 'namespace', 'labels': {'cloudlab.io/owner': 'private-gitops'}, 'annotations': {
                'argocd.argoproj.io/tracking-id': APP + ':/Namespace:' + namespace + '/cloudlab-private-fixture'}}
            self.objects['namespace', 'cloudlab-private-fixture'] = {'metadata': metadata}
            self.assertNotIn('namespace', metadata)
            with self.subTest(namespace=namespace), self.assertRaisesRegex(RuntimeError, 'another owner'): self.check()

    def test_cluster_policy_tracking_requires_admission_destination_namespace(self):
        policy = self.objects['validatingpolicy.policies.kyverno.io', POLICIES[0]]
        for namespace in ('', 'argocd'):
            policy['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = (
                'cloudlab-workload-policy:policies.kyverno.io/ValidatingPolicy:' + namespace + '/' + POLICIES[0])
            with self.subTest(namespace=namespace), self.assertRaisesRegex(RuntimeError, 'ready webhook contract'): self.check()

    def test_disabled_or_mismatched_inputs_do_not_read_or_retarget(self):
        disabled = prepare({'repository': self.public['repository']}, self.target['valuesRepository'], self.target['valuesRevision'])
        guard(disabled, self.target, lambda *args: self.fail('Disabled guard must not read'))
        for change in ({'private_revision': 'd' * 40}, {'revision': 'main'}, {'registry': None}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.check(self.evidence | change)

    def test_ready_conditions_do_not_substitute_for_expected_spec_owner_or_named_webhooks(self):
        original = copy.deepcopy(self.objects['validatingpolicy.policies.kyverno.io', POLICIES[0]])
        for change in ('spec', 'owner', 'missing-webhook', 'failed-rbac', 'deleting'):
            policy = copy.deepcopy(original)
            if change == 'spec': policy['spec']['failurePolicy'] = 'Ignore'
            if change == 'owner': policy['metadata']['annotations'] = {}
            if change == 'missing-webhook': policy['status']['conditionStatus']['conditions'].pop(0)
            if change == 'failed-rbac': policy['status']['conditionStatus']['conditions'][1]['status'] = 'False'
            if change == 'deleting': policy['metadata']['deletionTimestamp'] = 'now'
            self.objects['validatingpolicy.policies.kyverno.io', POLICIES[0]] = policy
            with self.subTest(change=change), self.assertRaisesRegex(RuntimeError, 'ready webhook contract'): self.check()

    def test_six_nonpersistent_controls_require_expected_denials_and_stable_policy(self):
        calls = []
        def positive(document):
            calls.append(document)
            return private_probe(self.evidence, document)
        self.check(probe=positive)
        self.assertEqual(len(calls), 6)
        self.assertEqual([row['kind'] for row in calls], ['Namespace', 'Namespace', 'AppProject', 'AppProject', 'Secret', 'Secret'])
        self.assertNotIn('namespace', calls[0]['metadata'])
        self.assertEqual(calls[0]['metadata']['annotations']['argocd.argoproj.io/tracking-id'],
                         APP + ':/Namespace:argocd/' + calls[0]['metadata']['name'])
        self.assertEqual(calls[-1]['data'], {})
        for error in ('connection refused', 'RBAC denied', 'no such key: labels'):
            def negative(document):
                code, message = private_probe(self.evidence, document)
                return (code, message + '; ' + error) if code else (code, message)
            with self.subTest(error=error), self.assertRaisesRegex(RuntimeError, 'negative control'): self.check(probe=negative)
        def changed(document):
            self.objects['validatingpolicy.policies.kyverno.io', POLICIES[0]]['metadata']['generation'] += 1
            return private_probe(self.evidence, document)
        with self.assertRaisesRegex(RuntimeError, 'changed during admission controls'): self.check(probe=changed)

    def test_positive_control_failure_never_counts_as_policy_enforcement(self):
        with self.assertRaisesRegex(RuntimeError, 'positive control'): self.check(probe=lambda document: (1, 'RBAC denied'))

    def test_server_probe_can_only_issue_server_dry_run_create(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        import private_activation
        with patch.object(private_activation.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stderr='')) as run:
            self.assertEqual(private_activation.server_probe({'apiVersion': 'v1', 'kind': 'Secret', 'data': {}}), (0, ''))
        self.assertIn('--dry-run=server', run.call_args.args[0])
        self.assertIn('create', run.call_args.args[0])

    def test_both_installed_callback_closures_work_without_runner_packages(self):
        root = Path(__file__).resolve().parents[4]
        for relative, packaged in (('tasks/main.yml', False), ('tasks/runtime.yml', True)):
            tasks = yaml.safe_load((root / 'ansible/playbooks/argocd' / relative).read_text())
            files = next(task['loop'] for task in tasks if 'source_transition.py' in task.get('loop', []))
            self.assertIn('private_activation.py', files)
            self.assertIn('access_activation.py', files)
            self.assertIn('private_sources.py', files)
            with self.subTest(packaged=packaged), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'playbooks/argocd/files' if packaged else Path(directory)
                target.mkdir(parents=True, exist_ok=True)
                for name in files:
                    (target / name).write_bytes((root / 'ansible/playbooks/argocd/files' / name).read_bytes())
                module = 'playbooks.argocd.files.' if packaged else ''
                code = ('import importlib; '
                    f'm=importlib.import_module({module + "source_transition"!r}); '
                    f'a=importlib.import_module({module + "private_activation"!r}); '
                    f'p=importlib.import_module({module + "private_sources"!r}); '
                    'assert m.private_server_probe is a.server_probe; '
                    'e=a.prepare({"repository":"https://github.com/example/platform.git"},'
                    '"https://github.com/example/private.git","b"*40); '
                    'assert not a.guard(e,{"valuesRepository":"https://github.com/example/private.git",'
                    '"valuesRevision":"b"*40},lambda *args:None)["required"]; assert p.PEM_TEMPLATE')
                result = subprocess.run([sys.executable, '-S', '-c', code], cwd=directory,
                    env=dict(os.environ, PYTHONPATH=directory), capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
