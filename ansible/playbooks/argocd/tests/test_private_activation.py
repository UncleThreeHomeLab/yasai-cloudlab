import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml
from jinja2 import Template
from unittest.mock import patch

from fixtures import binding_fixture, private_policies, private_probe, source_approval
from private_activation import APP, OWNER, POLICIES, TRACKING, guard, prepare


class PrivateActivationTests(unittest.TestCase):
    def setUp(self):
        self.objects, _, self.target, _ = binding_fixture()
        self.public = {'repository': 'https://github.com/example/platform.git',
            'privateSources': {'enabled': True, 'revision': 'c' * 40},
            'admission': {'enabled': True}, 'externalSecrets': {'enabled': True, 'reconcile': True}}
        self.registry = {'sources': [{'name': 'fixture', 'repository': self.target['valuesRepository'],
                                     'revision': 'main', 'path': 'gitops'}]}
        acceptance = source_approval(self.public, self.target['valuesRepository'])
        self.evidence = prepare(self.public, self.target['valuesRepository'], self.target['valuesRevision'], self.registry, acceptance=acceptance)
        self.objects['application.argoproj.io', 'cloudlab-public-root']['spec']['source']['helm']['valuesObject']['identity'] = {'enabled': True, 'argo': self.target}
        from playbooks.data.files import native
        chart = Path(__file__).resolve().parents[4] / 'gitops/roots/public'
        files = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        for mock in (patch.object(native, 'published_source', side_effect=lambda *args, **kwargs: (self.public, 'a' * 40)),
                patch.object(native.source_snapshot, 'chart_files', return_value=files)):
            mock.start(); self.addCleanup(mock.stop)
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
        original = self.public; self.public = {'privateSources': {'enabled': False}}
        guard(disabled, self.target, self.read)
        self.public = original
        for change in ({'private_revision': 'd' * 40}, {'revision': 'main'}, {'registry': None}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.check(self.evidence | change)

    def test_forged_disabled_evidence_cannot_bypass_current_public_enabled_intent(self):
        from private_activation import preflight
        disabled = prepare({'repository': self.public['repository']}, self.target['valuesRepository'], self.target['valuesRevision'])
        with self.assertRaisesRegex(RuntimeError, 'protected public intent'):
            guard(disabled, self.target, self.read)
        with self.assertRaisesRegex(RuntimeError, 'protected public intent'):
            preflight(disabled, self.target, self.read)
        self.public = {'privateSources': {'enabled': False, 'acceptanceCommitment': self.evidence['acceptanceCommitment']}}
        def public_only(kind, name):
            self.assertEqual((kind, name), ('application.argoproj.io', 'cloudlab-public-root'))
            return self.read(kind, name)
        self.assertFalse(guard(disabled, self.target, public_only)['required'])
        self.assertIsNone(preflight(disabled, self.target, public_only))

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
            expanded = []
            for task in tasks:
                expanded.extend(yaml.safe_load((root / 'ansible/playbooks/argocd/tasks/runtime.yml').read_text())
                                if task.get('ansible.builtin.import_tasks') == 'runtime.yml' else [task])
            destination = '/opt/cloudlab/playbooks/argocd/files/{{ item }}' if packaged else '/opt/cloudlab/gitops/{{ item }}'
            files = next(task['loop'] for task in expanded if 'source_transition.py' in task.get('loop', [])
                         and task.get('ansible.builtin.copy', {}).get('dest') == destination)
            self.assertIn('private_activation.py', files)
            self.assertIn('access_activation.py', files)
            self.assertIn('data_activation.py', files)
            self.assertIn('private_sources.py', files)
            with self.subTest(packaged=packaged), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                for task in expanded:
                    asset = task.get('ansible.builtin.copy', {})
                    if not asset.get('src', '').startswith('/workspace/'):
                        continue
                    for item in task.get('loop', [None]):
                        source = root / Path(Template(asset['src']).render(item=item)).relative_to('/workspace')
                        target = base / Path(Template(asset['dest']).render(item=item)).relative_to('/opt/cloudlab')
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(source.read_bytes())
                module = 'playbooks.argocd.files.' if packaged else ''
                code = ('import importlib; '
                    f'm=importlib.import_module({module + "source_transition"!r}); '
                    f'a=importlib.import_module({module + "private_activation"!r}); '
                    f'p=importlib.import_module({module + "private_sources"!r}); '
                    f'd=importlib.import_module({module + "data_activation"!r}); '
                    f's=importlib.import_module({module + "service_activation"!r}); '
                    'assert m.data_guard is d.guard; '
                    'assert m.activation_preflight is s.namespace_preflight; '
                    'from playbooks.admission.files import namespace_guard; '
                    'assert namespace_guard.qualify.__module__ == \'playbooks.admission.files.namespace_guard\'; '
                    'assert m.private_server_probe is a.server_probe; '
                    'e=a.prepare({"repository":"https://github.com/example/platform.git"},'
                    '"https://github.com/example/private.git","b"*40); '
                    'assert not a.validate(e,{"valuesRepository":"https://github.com/example/private.git",'
                    '"valuesRevision":"b"*40})["required"]; assert p.PEM_TEMPLATE')
                result = subprocess.run([sys.executable, '-S', '-c', code], cwd=directory,
                    env=dict(os.environ, PYTHONPATH=directory + os.pathsep + str(base / 'gitops')), capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_installed_early_resume_uses_data_fence_before_data_bootstrap(self):
        root = Path(__file__).resolve().parents[4]
        for relative, prefix in (('tasks/main.yml', ''), ('tasks/runtime.yml', 'playbooks.argocd.files.')):
            tasks = yaml.safe_load((root / 'ansible/playbooks/argocd' / relative).read_text())
            expanded = []
            for task in tasks:
                if task.get('ansible.builtin.import_tasks') == 'runtime.yml':
                    expanded.extend(yaml.safe_load((root / 'ansible/playbooks/argocd/tasks/runtime.yml').read_text()))
                else:
                    expanded.append(task)
            with self.subTest(layout=relative), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                for task in expanded:
                    asset = task.get('ansible.builtin.copy', {})
                    if not asset.get('dest', '').startswith('/opt/cloudlab/'):
                        continue
                    for item in task.get('loop', [None]):
                        source = Template(asset['src']).render(item=item)
                        target = base / Path(Template(asset['dest']).render(item=item)).relative_to('/opt/cloudlab')
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes((root / Path(source).relative_to('/workspace')).read_bytes())
                code = '''import importlib,json,pathlib,sys
base=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(base));sys.path.insert(0,str(base/'gitops'))
b=importlib.import_module(PREFIX+'bootstrap')
from playbooks.data.files import control,native,handoff
control.BASE=base/'data-state';control.BASE.mkdir(mode=0o700)
b.BASE=base/'gitops-state';b.BASE.mkdir(mode=0o700)
native.receipt=lambda p,**kwargs:json.loads(p.read_text()) if p.exists() else {}
owner=control.BASE/'ownership.json';control.atomic(owner,{'applications':{}})
checkpoint={'phase':'paused','root_uid':'root','project_uid':'project','controller_uid':'controller'}
(b.BASE/'identity-values-binding.json').write_text(json.dumps(checkpoint))
objects={'application.argoproj.io':{'metadata':{'uid':'root'},'spec':{'source':{'repoURL':'public'}}},
'appproject.argoproj.io':{'metadata':{'uid':'project'}},
'statefulset':{'metadata':{'uid':'controller'},'spec':{'replicas':0}}}
b.get=lambda kind,name:objects[kind]
writes=[];b.kube=lambda *args,**kwargs:writes.append(args)
assert b.resume_identity_binding();assert len(writes)==1
target={'valuesRepository':'https://github.com/example/private.git','valuesRevision':'b'*40}
control.atomic(owner,{'applications':{},'handoff':{'phase':'armed','target':target,
'pins':{'revision':'a'*40,'seaweedfsRevision':'c'*40},'owners':{},
'specs':{native.APP:{},native.SEAWEED:{}},'settings':{},'resources':{},
'absence':[native.SETTINGS,native.APP+'-source']}})
try:b.resume_identity_binding()
except RuntimeError as error:assert 'different private binding' in str(error)
else:raise AssertionError('Armed source fence was skipped')
assert len(writes)==1;assert 'dotenv' not in sys.modules
'''.replace('PREFIX', repr(prefix))
                result = subprocess.run([sys.executable, '-I', '-c', code, str(base)], cwd=base,
                    env={key: value for key, value in os.environ.items() if key != 'PYTHONPATH'},
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
