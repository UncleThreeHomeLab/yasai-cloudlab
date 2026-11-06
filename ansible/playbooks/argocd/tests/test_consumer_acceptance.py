"""Consumer proof validation and exact native gate; no controller qualification."""
import base64
import copy
from contextlib import contextmanager, nullcontext
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
from private_sources import CONSUMER_ACCEPTANCE_VERSION, consumer_contract, validate_consumer_acceptance, accepted_consumer

ROOT = Path(__file__).resolve().parents[4]
REPOSITORY = 'https://github.com/example/private.git'


def fixture(consumer='observability', path='services/catalog-v2.yaml'):
    paths = [path, 'platform/observability.yaml'] if consumer == 'observability' else ['platform/permissions.yaml']
    receipt = {'version': CONSUMER_ACCEPTANCE_VERSION, 'consumer': consumer, 'paths': paths, 'revision': 'b' * 40, 'nonce': '1' * 64}
    digest = hashlib.sha256(('\n'.join([receipt['version'], consumer, REPOSITORY, str(len(paths)), *paths,
        receipt['revision'], receipt['nonce'], ''])).encode()).hexdigest()
    public = {'repository': 'https://github.com/example/platform.git', 'revision': 'main',
        'identity': {'enabled': True}, 'externalSecrets': {'enabled': True, 'reconcile': True}, 'admission': {'enabled': True},
        'services': {'enabled': True, 'revision': 'd' * 40, 'catalogPath': path},
        'observability': {'enabled': True, 'configuration': {'enabled': True, 'paused': False, 'revision': 'e' * 40}},
        'permissions': {'enabled': True, 'revision': 'f' * 40}}
    settings = public['observability']['configuration'] if consumer == 'observability' else public['permissions']
    settings['acceptanceCommitment'] = digest
    return public, receipt


def document(raw, path):
    return {'type': 'file', 'path': path, 'encoding': 'base64', 'size': len(raw),
        'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), 'content': base64.b64encode(raw).decode()}


class ConsumerAcceptanceTests(unittest.TestCase):
    def test_acceptance_spec_selects_fixed_consumer_targets_and_preserves_render_contract(self):
        from private_sources import acceptance_spec
        chart = ROOT / 'gitops/roots/public'
        files = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        permissions, _ = fixture('permissions')
        for consumer, public in (('private-sources', yaml.safe_load(files['values.yaml'])), ('permissions', permissions)):
            before = copy.deepcopy(public)
            spec = acceptance_spec(public, REPOSITORY, 'a' * 40, files=files, consumer=consumer)
            self.assertEqual(spec['template']['metadata']['name'], 'cloudlab-' + consumer)
            self.assertEqual(public, before)
        public, _ = fixture('observability'); before = copy.deepcopy(public)
        selected = {'kind': 'ApplicationSet', 'metadata': {'name': 'cloudlab-observability-gitops'}, 'spec': {'selected': True}}
        unrelated = {'kind': 'ApplicationSet', 'metadata': {'name': 'cloudlab-observability'}, 'spec': {'selected': False}}
        with patch('playbooks.data.files.native.render_objects', return_value=[unrelated, selected]) as render:
            self.assertEqual(acceptance_spec(public, REPOSITORY, 'a' * 40, files=files, consumer='observability'), selected['spec'])
            self.assertIs(render.call_args.args[0], files)
            expected = copy.deepcopy(public)
            expected['identity'].update(enabled=True, argo={'valuesRepository': REPOSITORY, 'valuesRevision': 'a' * 40})
            self.assertEqual(render.call_args.args[1], [expected])
            self.assertEqual(public, before)
            for objects in ([], [selected, selected], [unrelated]):
                render.return_value = objects
                with self.assertRaisesRegex(ValueError, 'declaration is missing'):
                    acceptance_spec(public, REPOSITORY, 'a' * 40, files=files, consumer='observability')
            render.reset_mock()
            with self.assertRaisesRegex(ValueError, 'declaration is unsupported'):
                acceptance_spec(public, REPOSITORY, 'a' * 40, files=files, consumer='other')
            render.assert_not_called()
            render.side_effect = RuntimeError('synthetic renderer schema rejection')
            with self.assertRaisesRegex(RuntimeError, 'renderer schema rejection'):
                acceptance_spec(public, REPOSITORY, 'a' * 40, files=files, consumer='observability')
            self.assertEqual(public, before)

    def gate(self, contract, params, *, repository=REPOSITORY, policy=None):
        policy = policy if policy is not None else (ROOT / 'gitops/roots/public/consumer-source-acceptance.tmpl').read_text()
        constants = {'VERSION': contract['version'], 'CONSUMER': contract['consumer'], 'PRIVATE_REPOSITORY': repository,
            'COMMITMENT': contract['acceptanceCommitment'], 'PATHS_LF': '\n'.join(contract['paths'])}
        for key, value in constants.items(): policy = policy.replace('@@' + key + '@@', json.dumps(value))
        with tempfile.TemporaryDirectory() as directory:
            chart = Path(directory); (chart / 'templates').mkdir()
            (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: consumer-proof\nversion: 1.0.0\n')
            (chart / 'templates/proof.yaml').write_text('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: consumer-proof}\ndata:\n  revision: {{ tpl .Values.policy .Values.params | quote }}\n')
            return subprocess.run(['helm', 'template', 'proof', str(chart), '-f', '-'],
                input=json.dumps({'policy': policy, 'params': params}), text=True, capture_output=True, timeout=30)

    def params(self, receipt):
        # Git-files GoTemplate mode preserves the array and injects this path map.
        return dict(copy.deepcopy(receipt), path={'path': 'platform/acceptance', 'basename': 'acceptance',
            'basenameNormalized': 'acceptance', 'filename': str(receipt['consumer']) + '.yaml',
            'filenameNormalized': str(receipt['consumer']) + '.yaml', 'segments': ['platform', 'acceptance']})

    def test_production_permissions_parent_uses_the_qualified_exact_gate(self):
        from private_sources import acceptance_spec
        public, receipt = fixture('permissions')
        spec = acceptance_spec(public, REPOSITORY, 'a' * 40, consumer='permissions')
        gate = spec['generators'][0]['matrix']['generators'][1]['git']['revision']
        contract = consumer_contract(public, 'permissions')
        result = self.gate(contract, self.params(receipt), policy=gate)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(yaml.safe_load(result.stdout)['data']['revision'], receipt['revision'])
        for params in ({'consumer': 'permissions'}, self.params(dict(receipt, revision='c' * 40))):
            self.assertNotEqual(self.gate(contract, params, policy=gate).returncode, 0)

    def test_verification_captures_authenticated_permissions_snapshot_once_and_disabled_skips_it(self):
        from private_sources import verification_payload, acceptance_spec
        public, receipt = fixture('permissions')
        chart = ROOT / 'gitops/roots/public'
        files = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        public = yaml.safe_load(files['values.yaml']) | {'repository': public['repository'], 'permissions': public['permissions']}
        files['values.yaml'] = yaml.safe_dump(public).encode()
        evidence = {'publicRevision': 'c' * 40, 'acceptedRevision': receipt['revision'],
            'acceptanceCommitment': public['permissions']['acceptanceCommitment'], 'acceptanceReceipt': receipt}
        values = {'PRIVATE_CONFIG_REPOSITORY': REPOSITORY}
        baseline = {'configuration_revision': 'a' * 40}
        with patch('playbooks.argocd.files.github_app.configuration_revision', side_effect=lambda *args, **kwargs: baseline.copy()), \
                patch('playbooks.services.files.source.read_consumer', return_value=evidence) as read, \
                patch('playbooks.services.files.source.public_source_metadata', side_effect=lambda *a, **k: nullcontext(Mock())), \
                patch('playbooks.data.files.native.source_snapshot.chart_files', return_value=files) as snapshot:
            result = verification_payload(values, public)
            read.assert_called_once_with(values, 'permissions', public=public)
            self.assertEqual(snapshot.call_args.args[0]['revision'], 'c' * 40)
            self.assertEqual(result['permissions']['applicationSet'], acceptance_spec(public, REPOSITORY, 'a' * 40, files=files, consumer='permissions'))
            read.return_value = dict(evidence, acceptedRevision='d' * 40)
            with self.assertRaisesRegex(ValueError, 'differs from its receipt'):
                verification_payload(values, public)
            read.reset_mock(); snapshot.reset_mock()
            public['permissions']['enabled'] = False
            self.assertEqual(verification_payload(values, public), baseline)
            read.assert_not_called(); snapshot.assert_not_called()

    def test_verification_payload_authenticates_chart_metadata_and_revokes_before_render(self):
        from private_sources import verification_payload, acceptance_spec
        from playbooks.services.files import source
        public, receipt = fixture('permissions')
        private = 'https://github.com/UncleThreeHomeLab/private.git'
        public['repository'] = source.PUBLIC_REPOSITORY
        public['permissions']['acceptanceCommitment'] = hashlib.sha256(('\n'.join([
            receipt['version'], receipt['consumer'], private, '1', *receipt['paths'], receipt['revision'], receipt['nonce'], ''])).encode()).hexdigest()
        chart = ROOT / 'gitops/roots/public'
        files = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        public = yaml.safe_load(files['values.yaml']) | {'repository': public['repository'], 'permissions': public['permissions']}
        files['values.yaml'] = yaml.safe_dump(public).encode()
        evidence = {'publicRevision': 'c' * 40, 'acceptedRevision': receipt['revision'],
            'acceptanceCommitment': public['permissions']['acceptanceCommitment'], 'acceptanceReceipt': receipt}
        tree_sha = 'e' * 40
        tree = {'sha': tree_sha, 'truncated': False, 'tree': [{'path': 'gitops/roots/public/' + name,
            'type': 'blob', 'mode': '100644', 'size': len(raw), 'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
            for name, raw in files.items()]}
        events = []
        def fetch(path, deadline):
            events.append('metadata')
            if '/git/commits/' in path: return {'sha': 'c' * 40, 'tree': {'sha': tree_sha}}
            self.assertTrue(path.endswith('/git/trees/' + tree_sha + '?recursive=1')); return tree
        fetch.deadline = 60
        @contextmanager
        def session(credentials, *, deadline):
            self.assertEqual(credentials, {'synthetic': True}); events.append('issued')
            yield fetch
            events.append('revoked')
        def render(*args, **kwargs):
            self.assertEqual(events[-1], 'revoked')
            return acceptance_spec(*args, **kwargs)
        import playbooks.argocd.files.source_snapshot as snapshot
        real_chart_files = snapshot.chart_files
        def chart_files(selected, **kwargs):
            def raw(source, name, size, deadline):
                self.assertEqual(deadline, 60); return files[name]
            return real_chart_files(selected, read_file=raw, **kwargs)
        with patch('playbooks.argocd.files.github_app.configuration_revision', return_value={'configuration_revision': 'a' * 40}), \
                patch.object(source, 'read_consumer', return_value=evidence), \
                patch.object(source, 'fields', return_value={'synthetic': True}) as fields, \
                patch.object(source, 'public_metadata', side_effect=session), \
                patch.object(source.time, 'monotonic', return_value=0), \
                patch.object(snapshot, 'request', side_effect=AssertionError('Anonymous metadata unavailable')), \
                patch.object(snapshot, 'chart_files', side_effect=chart_files), patch('private_sources.acceptance_spec', side_effect=render):
            result = verification_payload({'PRIVATE_CONFIG_REPOSITORY': private}, public)
        fields.assert_called_once_with('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
        self.assertEqual(events, ['issued', 'metadata', 'metadata', 'revoked'])
        self.assertEqual(result['permissions']['acceptedRevision'], receipt['revision'])

    def test_both_consumers_match_exact_native_effective_input_and_alternate_catalog_paths(self):
        for consumer, path in (('observability', 'services/catalog.json'), ('observability', 'services/catalog-selected.yaml'), ('permissions', 'services/catalog.json')):
            public, receipt = fixture(consumer, path); contract = consumer_contract(public, consumer)
            validate_consumer_acceptance(receipt, REPOSITORY, contract)
            result = self.gate(contract, self.params(receipt))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(yaml.safe_load(result.stdout)['data']['revision'], receipt['revision'])
            self.assertEqual(contract['receiptPath'], 'platform/acceptance/' + consumer + '.yaml')

    def test_python_and_native_refuse_cross_scope_types_replay_and_unknown_effective_fields(self):
        for consumer in ('observability', 'permissions'):
            public, receipt = fixture(consumer); contract = consumer_contract(public, consumer)
            for case in ('consumer', 'version', 'path', 'order', 'count', 'duplicate', 'path-type', 'paths-type', 'revision', 'nonce', 'unknown', 'revision-type', 'nonce-type'):
                invalid = copy.deepcopy(receipt)
                if case == 'consumer': invalid['consumer'] = 'permissions' if consumer == 'observability' else 'observability'
                if case == 'version': invalid['version'] = 'cloudlab-private-source-acceptance/v1'
                if case == 'path': invalid['paths'][0] = 'platform/private.yaml'
                if case == 'order': invalid['paths'] = list(reversed(invalid['paths'])) if consumer == 'observability' else []
                if case == 'count': invalid['paths'].append('platform/extra.yaml')
                if case == 'duplicate': invalid['paths'] = [invalid['paths'][0]] * (len(invalid['paths']) + 1)
                if case == 'path-type': invalid['paths'][0] = True
                if case == 'paths-type': invalid['paths'] = 'platform/permissions.yaml'
                if case == 'revision': invalid['revision'] = 'a' * 40
                if case == 'nonce': invalid['nonce'] = '2' * 64
                if case == 'unknown': invalid['unexpected'] = True
                if case == 'revision-type': invalid['revision'] = 123
                if case == 'nonce-type': invalid['nonce'] = False
                with self.subTest(consumer=consumer, case=case):
                    with self.assertRaisesRegex(ValueError, '^Consumer source acceptance refused$'):
                        validate_consumer_acceptance(invalid, REPOSITORY, contract)
                    self.assertNotEqual(self.gate(contract, self.params(invalid)).returncode, 0)
            with self.assertRaises(ValueError): validate_consumer_acceptance(receipt, 'https://github.com/example/foreign.git', contract)
            self.assertNotEqual(self.gate(contract, self.params(receipt), repository='https://github.com/example/foreign.git').returncode, 0)

    def test_strict_python_receipt_reader_denies_alias_duplicate_keys_integrity_and_foreign_paths(self):
        public, receipt = fixture(); contract = consumer_contract(public, 'observability'); path = contract['receiptPath']
        raw = yaml.safe_dump(receipt).encode()
        client = Mock(request=Mock(return_value=document(raw, path)))
        self.assertEqual(accepted_consumer(client, REPOSITORY, 'a' * 40, public, 'observability')['acceptedRevision'], 'b' * 40)
        self.assertTrue(client.request.call_args.args[1].endswith(path + '?ref=' + 'a' * 40))
        for invalid in (raw + b'nonce: "' + b'1' * 64 + b'"\n', raw + b'other: &x []\npaths: *x\n'):
            client.request.return_value = document(invalid, path)
            with self.assertRaises(ValueError): accepted_consumer(client, REPOSITORY, 'a' * 40, public, 'observability')
        for change in ({'path': 'platform/acceptance/permissions.yaml'}, {'sha': '0' * 40}, {'type': 'symlink'}, {'size': 4097}):
            client.request.return_value = document(raw, path) | change
            with self.assertRaises(ValueError): accepted_consumer(client, REPOSITORY, 'a' * 40, public, 'observability')

    def test_finite_contracts_require_typed_enabled_approval_and_keep_disabled_reads_empty(self):
        for consumer in ('observability', 'permissions'):
            public, receipt = fixture(consumer)
            for case in ('enabled-type', 'missing-approval', 'pin', 'prerequisite', 'unsafe-path'):
                invalid = copy.deepcopy(public)
                settings = invalid['observability']['configuration'] if consumer == 'observability' else invalid['permissions']
                if case == 'enabled-type': settings['enabled'] = 1
                if case == 'missing-approval': settings.pop('acceptanceCommitment')
                if case == 'pin': settings['revision'] = 'main'
                if case == 'prerequisite': invalid['externalSecrets']['reconcile'] = False
                if case == 'unsafe-path':
                    if consumer == 'observability': invalid['services']['catalogPath'] = 'services/../identity.yaml'
                    else: settings['enabled'] = 'false'
                with self.subTest(consumer=consumer, case=case), self.assertRaises(ValueError): consumer_contract(invalid, consumer)
            settings = public['observability']['configuration'] if consumer == 'observability' else public['permissions']
            settings['enabled'] = False
            client = Mock(request=Mock(side_effect=AssertionError('Disabled receipt must not read private Git')))
            self.assertIsNone(accepted_consumer(client, '', 'not-a-sha', public, consumer))
            with self.assertRaises(ValueError): validate_consumer_acceptance(receipt, REPOSITORY, consumer_contract(public, consumer))
            client.request.assert_not_called()
        with self.assertRaises(ValueError): consumer_contract(public, 'private-sources')

    def test_gate_asset_does_not_change_current_root_objects(self):
        from playbooks.data.files.native import render_objects
        chart = ROOT / 'gitops/roots/public'
        files = {path.relative_to(chart).as_posix(): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        old = dict(files); old.pop('consumer-source-acceptance.tmpl')
        for bound in (False, True):
            values = {} if not bound else {'identity': {'argo': {'valuesRepository': REPOSITORY, 'valuesRevision': 'a' * 40}}}
            self.assertEqual(render_objects(files, [values]), render_objects(old, [values]))

    def test_installed_flat_and_packaged_validators_need_no_checkout_or_dotenv(self):
        cases = []
        for consumer in ('observability', 'permissions'):
            public, receipt = fixture(consumer)
            cases.append({'public': public, 'receipt': receipt, 'document': document(json.dumps(receipt).encode(), 'platform/acceptance/' + consumer + '.yaml')})
        for flat in (False, True):
            with self.subTest(flat=flat), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                tasks = yaml.safe_load((ROOT / 'ansible/playbooks/argocd/tasks/runtime.yml').read_text())
                if flat: tasks += yaml.safe_load((ROOT / 'ansible/playbooks/argocd/tasks/main.yml').read_text())
                for task in tasks:
                    asset = task.get('ansible.builtin.copy', {})
                    if not asset.get('src', '').startswith('/workspace/ansible/playbooks/') or not asset.get('dest', '').startswith('/opt/cloudlab/'): continue
                    for item in task.get('loop', [None]):
                        source = ROOT / Path(Template(asset['src']).render(item=item)).relative_to('/workspace')
                        target = base / Path(Template(asset['dest']).render(item=item)).relative_to('/opt/cloudlab')
                        if source.is_file(): target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(source.read_bytes())
                code = '''import importlib,json,pathlib,sys
base=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(base));sys.path.insert(0,str(base/'gitops'))
m=importlib.import_module(sys.argv[2]);data=json.load(sys.stdin)
for case in data['cases']:
 consumer=case['receipt']['consumer'];contract=m.consumer_contract(case['public'],consumer)
 m.validate_consumer_acceptance(case['receipt'],data['repository'],contract)
 class Client:
  def request(self,method,path):
   assert method=='GET' and path.endswith(contract['receiptPath']+'?ref='+'a'*40);return case['document']
 assert m.accepted_consumer(Client(),data['repository'],'a'*40,case['public'],consumer)['acceptedRevision']=='b'*40
assert not (base/'gitops/roots/public').exists();assert 'dotenv' not in sys.modules
'''
                result = subprocess.run([sys.executable, '-I', '-c', code, str(base), 'private_sources' if flat else 'playbooks.argocd.files.private_sources'],
                    input=json.dumps({'cases': cases, 'repository': REPOSITORY}), text=True, capture_output=True,
                    cwd=base, env={key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
