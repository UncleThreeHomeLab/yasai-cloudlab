"""Dormant native receipt approval; execute its exact GoTemplate with Helm/Sprig."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml
from jinja2 import Template
from fixtures import binding_fixture, private_policies, private_probe
from private_activation import APP, OWNER, TRACKING, catalog_owner, guard, prepare, sources_match
from private_sources import ACCEPTANCE_VERSION, acceptance_spec, accepted_source, registry, verification_payload
import private_verify

ROOT = Path(__file__).resolve().parents[4]
REPOSITORY = 'https://github.com/example/private.git'
RECEIPT = {'version': ACCEPTANCE_VERSION, 'consumer': 'private-sources', 'revision': 'c' * 40, 'nonce': 'd' * 64}


def commitment(receipt=RECEIPT, repository=REPOSITORY):
    return hashlib.sha256(('\n'.join([receipt['version'], receipt['consumer'], repository, 'platform/sources.yaml',
        receipt['revision'], receipt['nonce'], ''])).encode()).hexdigest()


def public():
    return {'repository': 'https://github.com/example/platform.git',
        'privateSources': {'enabled': True, 'revision': 'f' * 40, 'acceptanceCommitment': commitment()},
        'admission': {'enabled': True}, 'externalSecrets': {'enabled': True, 'reconcile': True}}


def document(value):
    raw = value if isinstance(value, bytes) else yaml.safe_dump(value).encode()
    return {'type': 'file', 'encoding': 'base64', 'size': len(raw), 'content': base64.b64encode(raw).decode()}


class PrivateAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = acceptance_spec(public(), REPOSITORY, 'b' * 40)

    def template(self, receipt):
        # This is the exact production GoTemplate string, not a Python hash-policy mirror.
        policy = self.spec['template']['spec']['sources'][1]['targetRevision']
        with tempfile.TemporaryDirectory() as directory:
            chart = Path(directory); (chart / 'templates').mkdir()
            (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: acceptance-template-proof\nversion: 1.0.0\n')
            (chart / 'templates/proof.yaml').write_text('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: acceptance-template-proof}\ndata:\n  revision: {{ tpl .Values.policy .Values.receipt | quote }}\n')
            return subprocess.run(['helm', 'template', 'proof', str(chart), '-f', '-'],
                input=json.dumps({'policy': policy, 'receipt': receipt}), capture_output=True, text=True, timeout=30)

    def test_exact_native_hash_accepts_only_approved_immutable_receipt(self):
        receipt = dict(RECEIPT, path={'path': 'platform/acceptance', 'filename': 'private-sources.yaml'})
        result = self.template(receipt)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(yaml.safe_load(result.stdout)['data']['revision'], RECEIPT['revision'])
        invalid = [dict(RECEIPT, revision='e' * 40), dict(RECEIPT, nonce='e' * 64), dict(RECEIPT, version='other'),
            dict(RECEIPT, consumer='data'), dict(RECEIPT, revision='main'), dict(RECEIPT, nonce=True),
            dict(RECEIPT, nonce={'nonce': 'd' * 64}), dict(RECEIPT, extra='foreign'),
            dict(RECEIPT, revision='{{ fail "untrusted-template" }}'), {k: v for k, v in RECEIPT.items() if k != 'nonce'},
            {'consumer': 'private-sources'}]
        for value in invalid:
            with self.subTest(value=value):
                result = self.template(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Private source acceptance refused', result.stderr)
                self.assertNotIn(RECEIPT['nonce'], result.stderr)

    def test_replayed_receipt_requires_explicit_public_reapproval(self):
        prior = dict(RECEIPT, revision='a' * 40, nonce='a' * 64)
        self.assertNotEqual(self.template(prior).returncode, 0)
        approved = public(); approved['privateSources']['acceptanceCommitment'] = commitment(prior)
        with patch.object(self, 'spec', acceptance_spec(approved, REPOSITORY, 'b' * 40)):
            self.assertEqual(self.template(prior).returncode, 0)

    def test_native_parent_contract_fixes_scope_and_declares_retention(self):
        spec = self.spec
        self.assertTrue(spec['goTemplate']); self.assertEqual(spec['goTemplateOptions'], ['missingkey=error'])
        self.assertEqual(spec['generators'], [{'merge': {'mergeKeys': ['consumer'], 'generators': [
            {'list': {'elements': [{'consumer': 'private-sources'}]}}, {'git': {'repoURL': REPOSITORY, 'revision': 'main',
            'files': [{'path': 'platform/acceptance/private-sources.yaml'}]}}]}}])
        self.assertEqual(spec['syncPolicy'], {'applicationsSync': 'create-update', 'preserveResourcesOnDeletion': True})
        child = spec['template']
        self.assertEqual(child['metadata']['name'], APP); self.assertEqual(child['spec']['project'], APP)
        self.assertEqual(child['spec']['sources'][0], {'repoURL': public()['repository'], 'targetRevision': 'f' * 40,
            'path': 'platform/delivery/private-sources', 'helm': {'valueFiles': ['$values/platform/sources.yaml']}})
        self.assertEqual(child['spec']['destination'], {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'})

    def test_authenticated_reader_has_generic_failures_and_never_falls_back_to_identity_pin(self):
        client = Mock(request=Mock(return_value=document(RECEIPT)))
        accepted = accepted_source(client, REPOSITORY, 'e' * 40, public())
        self.assertEqual(accepted, {'acceptanceCommitment': commitment(), 'acceptedRevision': 'c' * 40, 'acceptanceReceipt': RECEIPT})
        with self.assertRaisesRegex(ValueError, '^Private source acceptance refused$'):
            accepted_source(client, 'https://github.com/example/other.git', 'e' * 40, public())
        with self.assertRaisesRegex(ValueError, 'accepted immutable'):
            registry(client, {}, public(), 'b' * 40, acceptance=accepted)
        client.request.reset_mock()
        with self.assertRaisesRegex(ValueError, '^Private source registry requires its accepted immutable revision$'):
            registry(client, {'PRIVATE_CONFIG_REPOSITORY': REPOSITORY}, public(), 'e' * 40,
                acceptance=dict(accepted, acceptedRevision='e' * 40))
        client.request.assert_not_called()
        for value in ({}, dict(RECEIPT, revision='e' * 40), dict(RECEIPT, extra='foreign'),
                      b'version: wrong\nversion: repeated\n', b'receipt: &r {revision: secret}\nnonce: *r\n'):
            client.request.return_value = document(value)
            with self.assertRaisesRegex(ValueError, '^Private source acceptance refused$') as failure:
                accepted_source(client, REPOSITORY, 'e' * 40, public())
            self.assertNotIn(RECEIPT['nonce'], str(failure.exception)); self.assertNotIn(REPOSITORY, str(failure.exception))

    def test_verification_reads_receipt_at_head_but_catalog_at_accepted_revision(self):
        paths = []
        def request(method, path):
            paths.append(path)
            if 'platform/acceptance/private-sources.yaml?ref=' + 'e' * 40 in path: return document(RECEIPT)
            if 'platform/sources.yaml?ref=' + 'c' * 40 in path: return document({'sources': []})
            raise AssertionError('Unapproved source read')
        client = Mock(request=Mock(side_effect=request))
        with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=lambda values, read: read(client, 'e' * 40)):
            payload = verification_payload({'PRIVATE_CONFIG_REPOSITORY': REPOSITORY}, public())
        self.assertEqual(payload['configuration_revision'], 'e' * 40)
        self.assertEqual(payload['acceptedRevision'], 'c' * 40)
        self.assertEqual(len(paths), 2); self.assertEqual(payload['sources'], [])

    def test_activation_requires_exact_parent_uid_and_approved_child_revision(self):
        objects, _, target, _ = binding_fixture()
        receipt = accepted_source(Mock(request=Mock(return_value=document(RECEIPT))), REPOSITORY, 'e' * 40, public())
        evidence = prepare(public(), REPOSITORY, target['valuesRevision'], {'sources': []}, acceptance=receipt)
        objects.update(private_policies(evidence))
        objects['applicationset.argoproj.io', APP] = {'metadata': {'uid': 'accepted-parent', 'labels': {'cloudlab.io/owner': OWNER},
            'annotations': {'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + APP}},
            'spec': evidence['applicationSet']}
        spec = copy.deepcopy(self.spec['template']['spec']); spec['sources'][1]['targetRevision'] = RECEIPT['revision']
        app = {'metadata': {'uid': 'retained-child', 'labels': {'cloudlab.io/owner': OWNER},
            'annotations': {'argocd.argoproj.io/tracking-id': TRACKING}, 'ownerReferences': [{'apiVersion': 'argoproj.io/v1alpha1',
                'kind': 'ApplicationSet', 'name': APP, 'uid': 'accepted-parent', 'controller': True, 'blockOwnerDeletion': True}]}, 'spec': spec}
        objects['application.argoproj.io', APP] = app
        root = objects['application.argoproj.io', 'cloudlab-public-root']
        root['spec']['source'].setdefault('helm', {}).setdefault('valuesObject', {})['identity'] = {'argo': target}
        read = lambda kind, name: objects.get((kind, name))
        chart = ROOT / 'gitops/roots/public'
        files = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        with patch('playbooks.data.files.native.published_source', return_value=(public(), 'a' * 40)), \
                patch('playbooks.data.files.native.source_snapshot.chart_files', return_value=files):
            checked = guard(evidence, target, read, probe=lambda row: private_probe(evidence, row))
        self.assertEqual(checked['private_revision'], target['valuesRevision'])
        self.assertNotEqual(checked['acceptedRevision'], target['valuesRevision'])
        self.assertTrue(sources_match(app, checked))
        for change in ('uid', 'contract', 'revision', 'legacy-owner'):
            with self.subTest(change=change):
                altered = copy.deepcopy(objects)
                if change == 'uid': altered['application.argoproj.io', APP]['metadata']['ownerReferences'][0]['uid'] = 'foreign'
                if change == 'contract': altered['applicationset.argoproj.io', APP]['spec']['generators'][0]['merge']['generators'][1]['git']['revision'] = 'foreign'
                if change == 'revision': altered['application.argoproj.io', APP]['spec']['sources'][1]['targetRevision'] = target['valuesRevision']
                if change == 'legacy-owner': altered['application.argoproj.io', APP]['metadata'].pop('ownerReferences')
                self.assertFalse(catalog_owner(altered['application.argoproj.io', APP], checked, lambda kind, name: altered.get((kind, name)))
                    and sources_match(altered['application.argoproj.io', APP], checked))
        for change in ('forged-approval', 'forged-policy', 'root-override', 'nonce'):
            with self.subTest(change=change):
                forged = copy.deepcopy(evidence); live = copy.deepcopy(objects)
                if change == 'forged-approval':
                    receipt = dict(RECEIPT, revision='a' * 40)
                    forged.update(acceptanceReceipt=receipt, acceptedRevision=receipt['revision'], acceptanceCommitment=commitment(receipt))
                if change == 'forged-policy': forged['applicationSet']['generators'][0]['merge']['generators'][1]['git']['files'] = [{'path': '*'}]
                if change == 'root-override': live['application.argoproj.io', 'cloudlab-public-root']['spec']['source']['helm']['valuesObject']['privateSources'] = {'acceptanceCommitment': 'a' * 64}
                if change == 'nonce': forged['acceptanceReceipt']['nonce'] = 'a' * 64
                with patch('playbooks.data.files.native.published_source', return_value=(public(), 'a' * 40)), \
                        patch('playbooks.data.files.native.source_snapshot.chart_files', return_value=files), self.assertRaises((RuntimeError, ValueError)):
                    guard(forged, target, lambda kind, name: live.get((kind, name)), probe=lambda row: private_probe(evidence, row))

    def test_installed_prepared_contract_has_no_checkout_or_dotenv_dependency(self):
        proof = accepted_source(Mock(request=Mock(return_value=document(RECEIPT))), REPOSITORY, 'e' * 40, public())
        evidence = prepare(public(), REPOSITORY, 'b' * 40, {'sources': []}, acceptance=proof)
        root = {'metadata': {'uid': 'accepted-root'}, 'spec': {'project': 'cloudlab-root', 'source': {
            'repoURL': public()['repository'], 'targetRevision': 'main', 'path': 'gitops/roots/public',
            'helm': {'valuesObject': {'identity': {'argo': {'valuesRepository': REPOSITORY, 'valuesRevision': 'b' * 40}}}}}}}
        chart = ROOT / 'gitops/roots/public'
        payload = {'evidence': evidence, 'root': root, 'public': public(),
            'files': {path.relative_to(chart).as_posix(): base64.b64encode(path.read_bytes()).decode() for path in chart.rglob('*') if path.is_file()}}
        for flat in (False, True):
            with self.subTest(flat=flat), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                tasks = yaml.safe_load((ROOT / 'ansible/playbooks/argocd/tasks/runtime.yml').read_text())
                if flat: tasks += yaml.safe_load((ROOT / 'ansible/playbooks/argocd/tasks/main.yml').read_text())
                for task in tasks:
                    item = task.get('ansible.builtin.copy', {})
                    if not item.get('src', '').startswith('/workspace/ansible/playbooks/') or not item.get('dest', '').startswith('/opt/cloudlab/'):
                        continue
                    for entry in task.get('loop', [None]):
                        source = Template(item['src']).render(item=entry)
                        target = base / Path(Template(item['dest']).render(item=entry)).relative_to('/opt/cloudlab')
                        source = ROOT / Path(source).relative_to('/workspace')
                        if source.is_file():
                            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(source.read_bytes())
                code = '''import base64,importlib,json,pathlib,sys
base=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(base));sys.path.insert(0,str(base/'gitops'))
p=importlib.import_module(sys.argv[2]);from playbooks.data.files import native
data=json.load(sys.stdin)
native.published_source=lambda *a,**k:(data['public'],'a'*40)
native.source_snapshot.chart_files=lambda *a,**k:{name:base64.b64decode(raw) for name,raw in data['files'].items()}
p.prepared_contract(data['evidence'],lambda *args:data['root'])
assert not (base/'gitops/roots/public').exists();assert 'dotenv' not in sys.modules
'''
                result = subprocess.run([sys.executable, '-I', '-c', code, str(base),
                    'private_activation' if flat else 'playbooks.argocd.files.private_activation'], input=json.dumps(payload),
                    cwd=base, env={key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_prepared_verification_uses_approved_revision_and_exact_parent(self):
        proof = accepted_source(Mock(request=Mock(return_value=document(RECEIPT))), REPOSITORY, 'e' * 40, public())
        payload = dict(proof, applicationSet=self.spec, configuration_repository=REPOSITORY, configuration_revision='e' * 40,
            catalog_enabled=True, sources=[], objects=[], public_repository=public()['repository'], platform_revision='f' * 40)
        parent = {'metadata': {'uid': 'parent', 'labels': {'cloudlab.io/owner': OWNER}, 'annotations': {
            'argocd.argoproj.io/tracking-id': 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + APP}}, 'spec': self.spec}
        app = {'metadata': {'name': APP, 'labels': {'cloudlab.io/owner': OWNER}, 'annotations': {'argocd.argoproj.io/tracking-id': TRACKING},
            'ownerReferences': [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': APP,
                'uid': 'parent', 'controller': True, 'blockOwnerDeletion': True}]}, 'spec': copy.deepcopy(self.spec['template']['spec']),
            'status': {'sync': {'status': 'Synced', 'revisions': ['f' * 40, RECEIPT['revision']]}, 'health': {'status': 'Healthy'}}}
        app['spec']['sources'][1]['targetRevision'] = RECEIPT['revision']
        for foreign in (False, True):
            candidate = copy.deepcopy(parent)
            if foreign: candidate['spec']['syncPolicy']['applicationsSync'] = 'sync'
            def read(kind, name): return candidate if kind == 'applicationset.argoproj.io' else app
            with self.subTest(foreign=foreign), patch.object(private_verify, 'get', side_effect=read), \
                    patch.object(private_verify, 'kube', side_effect=lambda *args: json.dumps({'items': [app] if args[1] == 'applications.argoproj.io' else []})), \
                    patch.object(private_verify, 'prepared_contract') as authenticate, patch.object(private_verify, 'credential_owner'), \
                    patch.object(private_verify, 'wait', side_effect=lambda check, description: self.assertTrue(check())), \
                    patch.object(private_verify, 'foundation_sample', return_value=()), patch.object(private_verify, 'fingerprint', return_value=()), \
                    patch.object(private_verify.time, 'monotonic', side_effect=[0, 61, 62]):
                if foreign:
                    with self.assertRaisesRegex(RuntimeError, 'ownership or source'): private_verify.run(payload)
                else:
                    self.assertTrue(private_verify.run(payload)['private_access_verified'])
                authenticate.assert_called_once()

    def test_dormant_public_defaults_preserve_legacy_owner_and_reject_invalid_commitment(self):
        values = public(); values['privateSources']['acceptanceCommitment'] = ''
        values['identity'] = {'enabled': True, 'argo': {'valuesRepository': REPOSITORY, 'valuesRevision': 'b' * 40}}
        for value in ('', False, None, 'short', 'A' * 64):
            values['privateSources']['acceptanceCommitment'] = value
            result = subprocess.run(['helm', 'template', 'root', str(ROOT / 'gitops/roots/public'), '-f', '-'],
                input=json.dumps(values), capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode == 0, value == '' and isinstance(value, str))
            if value == '' and isinstance(value, str):
                objects = [row for row in yaml.safe_load_all(result.stdout) if row]
                catalog = next(row for row in objects if row['metadata']['name'] == APP and row['kind'] == 'Application')
                self.assertEqual(catalog['spec']['sources'][1]['targetRevision'], 'main')
                self.assertFalse(any(row['kind'] == 'ApplicationSet' and row['metadata']['name'] == APP for row in objects))
