"""Finite Harbor installation authority and operational delegation boundaries."""
import base64
import copy
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml

from playbooks.harbor.files import native, recovery
from playbooks.harbor.tests.fixtures import native_installation


class NativeTests(unittest.TestCase):
    def test_expected_application_uses_authenticated_template_without_legacy_constructor(self):
        snapshot, _, _ = native_installation()
        for name in native.APPS:
            expected = native.expected_app(snapshot, name)
            declared = copy.deepcopy(snapshot['contracts'][0][('ApplicationSet', name)]['spec']['template']['spec'])
            declared['source']['helm']['valuesObject'] = native.values(snapshot['profile'], name)
            self.assertEqual(expected['spec'], declared)
        self.assertFalse(hasattr(native, 'application'))
        snapshot['contracts'][0][('ApplicationSet', native.APPS[0])]['spec']['template']['spec']['source']['targetRevision'] = 'b' * 40
        with self.assertRaisesRegex(RuntimeError, 'fixed installation scope'):
            native.expected_app(snapshot, native.APPS[0])

    def test_retirement_refuses_foreign_paths_and_removes_bytecode_before_writer_repeatably(self):
        from contextlib import nullcontext
        import importlib.util
        import os
        import py_compile
        # /var/lib has the same non-writable root ancestry required by the host guard.
        with tempfile.TemporaryDirectory(dir='/var/lib') as directory:
            base = Path(directory); runtime = base / 'files'; runtime.mkdir(mode=0o700)
            cache = runtime / '__pycache__'; cache.mkdir(mode=0o700)
            writer = runtime / 'bootstrap.py'; old = b"raise RuntimeError('retired writer must never run')\n"
            writer.write_bytes(old); writer.chmod(0o600)
            bytecode = Path(importlib.util.cache_from_source(str(writer)))
            py_compile.compile(str(writer), cfile=str(bytecode), doraise=True)
            unrelated = cache / 'native.cpython-other.pyc'; unrelated.write_bytes(b'preserved')
            with patch.object(recovery, 'BASE', base), patch.object(native, 'BASE', base), patch.object(native, 'RUNTIME', runtime), patch.object(native, 'LOCK', base / 'owner.lock'), \
                    patch.object(native, 'RETIRED_BOOTSTRAP_SHA256', hashlib.sha256(old).hexdigest()), \
                    patch.object(native, 'operation', return_value=nullcontext({'authenticated': True})), \
                    patch.object(native, 'receipt', return_value={'phase': 'accepted'}), patch.object(native, 'observe') as observe:
                writer.write_bytes(b'foreign')
                with self.assertRaisesRegex(RuntimeError, 'published H1 checksum'): native.run({'retire': True})
                self.assertTrue(bytecode.exists()); self.assertEqual(writer.read_bytes(), b'foreign')
                writer.write_bytes(old); py_compile.compile(str(writer), cfile=str(bytecode), doraise=True)
                bytecode.write_bytes(b'unknown bytecode')
                with self.assertRaisesRegex(RuntimeError, 'unknown interpreter header'): native.run({'retire': True})
                self.assertTrue(writer.exists())
                py_compile.compile(str(writer), cfile=str(bytecode), doraise=True)
                bytecode.write_bytes(bytecode.read_bytes()[:16] + b'foreign body')
                with self.assertRaisesRegex(RuntimeError, 'body is foreign or invalid'): native.run({'retire': True})
                self.assertTrue(writer.exists())
                py_compile.compile(str(writer), cfile=str(bytecode), doraise=True)
                original_cache = base / 'original-cache'; cache.rename(original_cache)
                cache.symlink_to(original_cache, target_is_directory=True)
                with self.assertRaisesRegex(RuntimeError, 'unsafe ancestors'): native.run({'retire': True})
                self.assertTrue(writer.exists()); self.assertTrue(bytecode.exists())
                cache.unlink(); original_cache.rename(cache)
                reference = base / 'outside.py'; reference.write_bytes(old); reference.chmod(0o600)
                writer.unlink(); writer.symlink_to(reference)
                with self.assertRaisesRegex(RuntimeError, 'owned regular'): native.run({'retire': True})
                self.assertTrue(bytecode.exists()); self.assertTrue(reference.exists())
                writer.unlink(); writer.write_bytes(old); writer.chmod(0o600)
                py_compile.compile(str(writer), cfile=str(bytecode), doraise=True)
                (base / 'maintenance.json').write_text('{}'); (base / 'maintenance.json').chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, 'active Harbor recovery'): native.run({'retire': True})
                self.assertTrue(bytecode.exists()); (base / 'maintenance.json').unlink()
                witness = {'manifest': 'captured-monthly-witness'}
                with patch.object(recovery, 'handoff_pending', side_effect=[witness, RuntimeError('Harbor pending recovery changed during installation handoff')]) as pending:
                    with self.assertRaisesRegex(RuntimeError, 'pending recovery changed'): native.run({'retire': True})
                    self.assertEqual(pending.call_args.kwargs, {'expected': witness})
                self.assertTrue(bytecode.exists()); self.assertEqual(writer.read_bytes(), old)
                observe.side_effect = [None, RuntimeError('Interrupted before source removal')]
                with self.assertRaisesRegex(RuntimeError, 'Interrupted'): native.run({'retire': True})
                self.assertFalse(bytecode.exists()); self.assertEqual(writer.read_bytes(), old)
                observe.side_effect = None
                self.assertTrue(native.run({'retire': True})['changed'])
                self.assertFalse(writer.exists()); self.assertTrue(unrelated.exists())
                self.assertFalse(native.run({'retire': True})['changed'])

    def test_read_budget_cannot_extend_nested_context_and_reserves_acknowledged_revocation(self):
        from contextlib import nullcontext
        from playbooks.harbor.files import verify
        snapshot = {'read_deadline': 140, 'profile': {'harborHost': 'harbor.internal.example.invalid'}}
        token = native.ACTIVE.set(snapshot)
        try:
            with patch.object(native.time, 'monotonic', return_value=100), patch.object(native, 'observe'), patch.object(native, 'receipt', return_value={'phase': 'accepted'}):
                with native.operation(deadline=120):
                    self.assertEqual(native.ACTIVE.get()['read_deadline'], 120)
                    with native.operation(deadline=160):
                        self.assertEqual(native.ACTIVE.get()['read_deadline'], 120)
                self.assertEqual(native.ACTIVE.get()['read_deadline'], 140)
            with patch.object(native.time, 'monotonic', return_value=141), patch.object(native, 'observe') as observe:
                with self.assertRaisesRegex(RuntimeError, 'exceeded'):
                    with native.operation(deadline=160): pass
                observe.assert_not_called()
        finally:
            native.ACTIVE.reset(token)
        with patch.object(native, 'operation', return_value=nullcontext(snapshot)) as operation, patch.object(verify.time, 'monotonic', return_value=100):
            self.assertEqual(verify.inputs(), {'configuration': {'harborHost': snapshot['profile']['harborHost']}})
            operation.assert_called_once_with(deadline=140)
        with patch.object(native.time, 'monotonic', return_value=100), patch.object(native.source, 'GitHub') as issue:
            with self.assertRaisesRegex(RuntimeError, 'reserve token revocation'):
                native.read_profiles([{'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'a' * 40}], {}, 110)
            issue.assert_not_called()
        import shlex
        from playbooks.infrastructure.files import harbor as provider
        root = Path(__file__).resolve().parents[4]
        response = {'harborHost': snapshot['profile']['harborHost'], 'loginHost': 'login.example.invalid',
            'images': sorted(json.loads((root / 'platform/harbor/images.lock.json').read_text()).values()),
            'repositories': [native.PUBLIC]}
        with patch.object(provider, 'ssh', return_value=json.dumps(response)) as remote:
            self.assertEqual(provider.metadata({'VM_HOST': 'synthetic'}), response)
            self.assertEqual(remote.call_args.kwargs['timeout'], 60)
            script = shlex.split(remote.call_args.args[2])[2]
            self.assertIn('with operation(deadline=time.monotonic()+40):', script)

    def test_pending_binding_uses_only_recorded_parent_contracts_and_equal_profile(self):
        snapshot, resources, state = native_installation()
        old = snapshot['targets'][0]; new = dict(old, valuesRevision='b' * 40)
        original = {'repoURL': native.PUBLIC, 'helm': {'valuesObject': {'identity': {'argo': old}}}}
        patched = copy.deepcopy(original); patched['helm']['valuesObject']['identity']['argo'] = new
        binding = dict(state['authority'], target=new, originalSource=original, patchedSource=patched)
        root = {'metadata': {'uid': 'root'}, 'spec': {'source': patched}}
        chart = Path(__file__).resolve().parents[4] / 'gitops/roots/public'
        root_files = {str(path.relative_to(chart)): path.read_bytes() for path in chart.rglob('*') if path.is_file()}
        def chart_files(coordinates, **kwargs):
            if coordinates['path'] == 'gitops/roots/public': return root_files
            self.assertEqual(coordinates['revision'], native.REVISION)
            return snapshot['charts'][native.APPS[0] if coordinates['path'].endswith('/server') else native.APPS[1]]
        from playbooks.argocd.files import source_transition
        with patch.object(native, 'receipt', return_value=state), patch.object(native, 'get', side_effect=lambda kind, name, *args: copy.deepcopy(resources.get((kind, name)))), \
                patch.object(native.source, 'published_source', return_value=(snapshot['public'], snapshot['head'])), \
                patch.object(native.source.source_snapshot, 'chart_files', side_effect=chart_files), \
                patch.object(source_transition, 'pending_root_context', return_value=(root, [old, new])) as pending, \
                patch.object(native.source, 'source_credentials'), patch.object(native, 'read_profiles', return_value=snapshot['profile']) as read, \
                patch.object(native.source, 'root_guard', side_effect=RuntimeError('Ordinary acceptance requires accepted binding')) as ordinary:
            native.binding_guard(binding, root)
            self.assertEqual(read.call_args.args[0], [old, new]); ordinary.assert_not_called()
            changed = dict(snapshot['profile'], gatewayIP='10.43.0.101'); read.return_value = changed
            with self.assertRaisesRegex(RuntimeError, 'intent changed'): native.binding_guard(binding, root)
            read.return_value = snapshot['profile']; pending.side_effect = RuntimeError('Recorded context changed')
            with self.assertRaisesRegex(RuntimeError, 'Recorded context changed'): native.binding_guard(binding, root)
            with self.assertRaisesRegex(RuntimeError, 'Ordinary acceptance'): native.context()

    def test_installed_native_and_shared_pending_interfaces_work_in_both_layouts(self):
        import os
        import shutil
        import sys
        from jinja2 import Template
        root = Path(__file__).resolve().parents[4]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            def install(path):
                for task in yaml.safe_load(path.read_text()):
                    imported = task.get('ansible.builtin.import_tasks')
                    if imported:
                        reference = Path(imported)
                        resolved = root / reference.relative_to('/workspace') if reference.is_absolute() else path.parent / reference
                        resolved = resolved.resolve()
                        if not resolved.is_relative_to(root): raise AssertionError('Task import leaves fixture checkout')
                        install(resolved)
                    declaration = task.get('ansible.builtin.copy', {})
                    if not declaration.get('dest', '').startswith('/opt/cloudlab/'): continue
                    for item in task.get('loop', [None]):
                        src = Template(declaration['src']).render(item=item)
                        if not src.startswith('/workspace/'): continue
                        target = base / Template(declaration['dest']).render(item=item).removeprefix('/opt/cloudlab/')
                        target.parent.mkdir(parents=True, exist_ok=True)
                        src = root / src.removeprefix('/workspace/')
                        if src.is_dir(): shutil.copytree(src, target, dirs_exist_ok=True)
                        else: shutil.copyfile(src, target)
            for path in ('argocd/tasks/main.yml', 'harbor/tasks/runtime.yml', 'keycloak/tasks/runtime.yml'):
                install(root / 'ansible/playbooks' / path)
            self.assertFalse((base / 'playbooks/harbor/files/bootstrap.py').exists())
            cli = subprocess.run([sys.executable, '-I', str(base / 'playbooks/harbor/files/native.py')], input='{"bogus":true}',
                cwd=base, env={key: value for key, value in os.environ.items() if key != 'PYTHONPATH'},
                capture_output=True, text=True, timeout=30)
            self.assertNotEqual(cli.returncode, 0)
            self.assertIn('Harbor native ownership incomplete', cli.stderr)
            self.assertNotIn('Traceback', cli.stderr)
            for module in ('source_transition', 'playbooks.argocd.files.source_transition'):
                code = '''import sys, importlib
sys.path[:0] = [sys.argv[1], sys.argv[1] + "/gitops"]
m = importlib.import_module(sys.argv[2])
from playbooks.harbor.files import native, recovery, verify
assert callable(verify.oidc_discovery)
import json
assert json.loads((recovery.ARTIFACTS / "cosign.lock.json").read_text())["image"]
assert native.REVISION == "d3d639cf80e8cfecebeb756d666a24db92a6bb74"
assert callable(m.pending_root_context)
try:
    m.pending_root_context({}, {})
except RuntimeError:
    pass
else:
    raise AssertionError()
assert "dotenv" not in sys.modules
'''
                result = subprocess.run([sys.executable, '-I', '-c', code, str(base), module], cwd=base,
                    env={key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_render_keeps_single_sources_and_refuses_missing_or_untyped_profile(self):
        snapshot, resources, _ = native_installation()
        with tempfile.TemporaryDirectory() as directory:
            chart = Path(directory); (chart / 'templates').mkdir()
            (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: harbor-patch-proof\nversion: 1.0.0\n')
            (chart / 'templates/patch.yaml').write_text('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: proof}\ndata:\n  patch: {{ tpl .Values.policy .Values.input | quote }}\n')
            for name in native.APPS:
                parent = resources[('applicationset.argoproj.io', name)]['spec']
                generators = parent['generators'][0]['merge']['generators']
                self.assertEqual(generators[0]['list']['elements'], [{'installationRevision': native.REVISION}])
                self.assertEqual(generators[1]['git']['files'], [{'path': 'platform/harbor.yaml'}])
                self.assertNotIn('sources', parent['template']['spec'])
                self.assertEqual(parent['template']['spec']['source']['targetRevision'], native.REVISION)
                self.assertEqual(parent['ignoreApplicationDifferences'], [{'jsonPointers': [
                    '/spec/source/helm/valuesObject/' + '/'.join(path) for path in native.paths(name)]}])
                for change in ('valid', 'missing', 'pin', 'foreign', 'gateway'):
                    candidate = copy.deepcopy(snapshot['profile'])
                    if change == 'missing': candidate = generators[0]['list']['elements'][0]
                    if change == 'pin': candidate['installationRevision'] = 'b' * 40
                    if change == 'foreign': candidate['metadata'] = {'name': 'foreign'}
                    if change == 'gateway': candidate['gatewayIP'] = '127.0.0.1'
                    candidate = dict(candidate, path={'path': 'platform', 'filename': 'harbor.yaml', 'segments': ['platform']})
                    result = subprocess.run(['helm', 'template', 'proof', str(chart), '-f', '-'],
                        input=json.dumps({'policy': parent['templatePatch'], 'input': candidate}), capture_output=True, text=True, timeout=30)
                    if change == 'valid':
                        self.assertEqual(result.returncode, 0, result.stderr)
                        actual = yaml.safe_load(yaml.safe_load(result.stdout)['data']['patch'])['spec']['source']['helm']['valuesObject']
                        self.assertEqual(actual, native.values(snapshot['profile'], name))
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('Harbor installation input refused', result.stderr)
        root = Path(__file__).resolve().parents[4] / 'gitops/roots/public'
        disabled = subprocess.run(['helm', 'template', 'root', str(root)], capture_output=True, text=True, timeout=30, check=True)
        self.assertFalse(any(obj['kind'] == 'ApplicationSet' and obj['metadata']['name'] in native.APPS
            for obj in yaml.safe_load_all(disabled.stdout) if obj))

    def test_private_read_is_two_immutable_profiles_and_revokes_before_return_or_refusal(self):
        document = {'installationRevision': native.REVISION, 'harborHost': 'harbor.internal.example.invalid',
            'loginHost': 'login.example.invalid', 'gatewayIP': '10.43.0.100'}
        targets = [{'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': revision * 40} for revision in ('a', 'b')]
        for changed in (False, True):
            api, client = Mock(), Mock(); events = []
            api.request.side_effect = lambda method, *args: {'token': 'synthetic'} if method == 'POST' else {}
            def request(method, path, body=None):
                events.append((method, path))
                if method == 'DELETE': return None
                if '/contents/' not in path: return {'full_name': 'example/private', 'private': True, 'default_branch': 'main'}
                value = dict(document)
                if changed and path.endswith('b' * 40): value['gatewayIP'] = '10.43.0.101'
                raw = yaml.safe_dump(value).encode()
                return {'type': 'file', 'path': 'platform/harbor.yaml', 'encoding': 'base64', 'size': len(raw),
                    'content': base64.b64encode(raw).decode(), 'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
            client.request.side_effect = request
            with patch.object(native.source, 'GitHub', side_effect=[api, client]), patch.object(native.source, 'app_token', return_value='app'), \
                    patch.object(native.source, 'verify_installation'):
                if changed:
                    with self.assertRaisesRegex(RuntimeError, 'changes the Harbor'): native.read_profiles(targets, {'INSTALLATION_ID': '2', 'APP_ID': '1'}, native.time.monotonic() + 60)
                else:
                    self.assertEqual(native.read_profiles(targets, {'INSTALLATION_ID': '2', 'APP_ID': '1'}, native.time.monotonic() + 60), document)
                self.assertEqual(events[-1], ('DELETE', 'installation/token'))
                self.assertEqual([path for method, path in events if '/contents/' in path], [
                    'repos/example/private/contents/platform/harbor.yaml?ref=' + target['valuesRevision'] for target in targets])

    def test_registration_preserves_captured_children_and_replaced_owner_never_becomes_initial(self):
        snapshot, resources, state = native_installation()
        prepared = {key: copy.deepcopy(value) for key, value in state.items() if key not in ('parents', 'reader_uid', 'secret_uid')}
        prepared['phase'] = 'prepared'
        refresh = 0
        def read(kind, name, *args):
            nonlocal refresh
            obj = copy.deepcopy(resources.get((kind, name)))
            if obj and name == native.READER:
                refresh += 1; obj['metadata']['resourceVersion'] = str(refresh)
                obj['status'] = {'refreshTime': refresh}
            return obj
        with patch.object(native, 'get', side_effect=read), patch.object(native.source, 'root_guard', return_value=snapshot['targets'][0]), \
                patch.object(native.source, 'receipt', return_value=dict(state['authority'], phase='accepted', target=snapshot['targets'][0])), \
                patch.object(native.source, 'source_credentials'), patch.object(native, 'application_ready', return_value=True), \
                patch.object(recovery, 'atomic') as write:
            self.assertTrue(native.observe(snapshot, prepared, register=True))
            self.assertEqual(write.call_args.args[1]['applications'], state['applications'])
            write.reset_mock()
            self.assertFalse(native.observe(snapshot, state, register=True))
            write.assert_not_called()
            with tempfile.TemporaryDirectory() as directory, patch.object(native, 'LOCK', Path(directory) / 'owner.lock'), \
                    patch.object(native, 'receipt', return_value=state), patch.object(native, 'context', return_value=snapshot), \
                    patch.object(native.source, 'kube') as effects:
                self.assertFalse(native.run({})['changed']); effects.assert_not_called()
                with patch.object(native, 'receipt', return_value=prepared):
                    with self.assertRaisesRegex(RuntimeError, 'registration before operations'): native.run({})
                with patch.object(native, 'receipt', return_value={}):
                    with self.assertRaisesRegex(RuntimeError, 'protected accepted'): native.run({})
                effects.assert_not_called()
            resources[('application.argoproj.io', native.APPS[0])]['metadata']['uid'] = 'replaced'
            with self.assertRaisesRegex(RuntimeError, 'identity changed'): native.observe(snapshot, state)
            write.assert_not_called()
            with self.assertRaises(RuntimeError): native.observe(snapshot, {})

    def test_initial_intent_checks_absence_and_cannot_adopt_retained_references(self):
        from playbooks.harbor.files.configuration import client
        snapshot, resources, _ = native_installation(); snapshot['enabled'] = False
        project = copy.deepcopy(resources[('appproject.argoproj.io', native.APPS[0])]); project['spec']['sourceRepos'] = [native.PUBLIC]
        expected_client = client('https://' + snapshot['profile']['loginHost'] + '/realms/platform', 'https://' + snapshot['profile']['harborHost'])
        def initial_read(kind, name=None, namespace=None):
            if kind == 'appproject.argoproj.io': return project
            if kind == 'configmap': return {'data': {'desired_state': json.dumps({'realms': {'platform': {'clients': [expected_client]}}})}}
            return {'items': []} if name is None and kind in ('pv', 'volumes.longhorn.io') else None
        with tempfile.TemporaryDirectory() as directory, patch.object(native, 'BASE', Path(directory)), \
                patch.object(native, 'context', return_value=snapshot), patch.object(native, 'get', side_effect=initial_read), \
                patch.object(native.source, 'root_guard', return_value=snapshot['targets'][0]), \
                patch.object(native, 'receipt', side_effect=lambda: json.loads((Path(directory) / native.RECORD).read_text()) if (Path(directory) / native.RECORD).exists() else {}), \
                patch('playbooks.keycloak.files.ownership.accepted_application', return_value='526891f62eb9b9a50a0ffaf6ef020269d09e7746'):
            self.assertTrue(native.prepare(initial=True))
            recorded = json.loads((Path(directory) / native.RECORD).read_text())
            self.assertEqual(recorded['phase'], 'initial'); self.assertEqual(recorded['applications'], {})
            self.assertEqual(recorded['authority'], snapshot['authority'])
            self.assertEqual((Path(directory) / native.RECORD).stat().st_mode & 0o777, 0o600)
            self.assertFalse(native.prepare(initial=True))
        with tempfile.TemporaryDirectory() as directory, patch.object(native, 'BASE', Path(directory)):
            def read(kind, name=None, namespace=None): return {'items': []} if name is None and kind in ('pv', 'volumes.longhorn.io') else None
            with patch.object(native, 'get', side_effect=read):
                native.safe_absence()
                (Path(directory) / 'maintenance.json').write_text('{}')
                with self.assertRaisesRegex(RuntimeError, 'ownership files'): native.safe_absence()
            (Path(directory) / 'maintenance.json').unlink()
            with patch.object(native, 'get', side_effect=lambda kind, name=None, namespace=None:
                    {'items': [{'spec': {'claimRef': {'namespace': native.NAMESPACE}}}]} if kind == 'pv' else read(kind, name, namespace)):
                with self.assertRaisesRegex(RuntimeError, 'storage references'): native.safe_absence()
            with patch.object(native, 'get', side_effect=lambda kind, name=None, namespace=None: {} if kind == 'pv' else read(kind, name, namespace)):
                with self.assertRaisesRegex(RuntimeError, 'discovery is incomplete'): native.safe_absence()

    def test_historical_full_values_resume_only_eight_operational_fields(self):
        snapshot, resources, state = native_installation()
        for name in native.APPS:
            actual = resources[('application.argoproj.io', name)]
            historical = copy.deepcopy(native.values(snapshot['profile'], name))
            if name == native.APPS[0]:
                historical = json.loads(snapshot['charts'][name]['values.json'])
                historical['harbor']['externalURL'] = native.values(snapshot['profile'], name)['harbor']['externalURL']
                historical['harbor']['core']['hostAliases'] = native.values(snapshot['profile'], name)['harbor']['core']['hostAliases']
            else: historical.pop('maintenance')
            self.assertEqual(native.normalize(name, historical, snapshot['profile'], snapshot['charts']), native.values(snapshot['profile'], name))
            wrong_type = copy.deepcopy(historical)
            if name == native.APPS[0]: wrong_type['harbor']['persistence']['enabled'] = 1
            else: wrong_type['enabled'] = 1
            with self.assertRaisesRegex(RuntimeError, 'immutable installation values'):
                native.normalize(name, wrong_type, snapshot['profile'], snapshot['charts'])
            with patch.object(recovery, 'application', return_value=copy.deepcopy(actual)), \
                    patch.object(native, 'guard', return_value=(snapshot, native.values(snapshot['profile'], name))), patch.object(recovery, 'kube') as write:
                recovery.patch_values(name, historical, actual['metadata']['uid'])
                operations = json.loads(write.call_args.args[-1])
                self.assertEqual(operations[2], {'op': 'test', 'path': '/spec', 'value': actual['spec']})
                self.assertEqual([row['path'] for row in operations[3:]], ['/spec/source/helm/valuesObject/' + '/'.join(path) for path in native.paths(name)])
                write.reset_mock()
                if name == native.APPS[0]: historical['harbor']['core']['existingSecret'] = 'foreign'
                else: historical['loginHost'] = 'login.foreign.invalid'
                with self.assertRaisesRegex(RuntimeError, 'immutable installation values'): recovery.patch_values(name, historical, actual['metadata']['uid'])
                write.assert_not_called()

    def test_existing_handoff_compares_authenticated_effective_resources_before_intent(self):
        from playbooks.harbor.files.configuration import client
        snapshot, resources, _ = native_installation(); snapshot['enabled'] = False
        active = 'a0a42ac02b0d351a4c56cf40e88f697f3537f19a'
        snapshot['public']['identity']['application']['installationRevision'] = active
        resources = {key: value for key, value in resources.items() if key[0] not in ('applicationset.argoproj.io', 'externalsecret.external-secrets.io', 'secret')}
        resources[('appproject.argoproj.io', native.APPS[0])]['spec']['sourceRepos'] = [native.PUBLIC]
        for name in native.APPS:
            app = resources[('application.argoproj.io', name)]; app['metadata'].pop('ownerReferences')
            if name == native.APPS[0]:
                historical = json.loads(snapshot['charts'][name]['values.json'])
                historical['harbor']['externalURL'] = native.values(snapshot['profile'], name)['harbor']['externalURL']
                historical['harbor']['core']['hostAliases'] = native.values(snapshot['profile'], name)['harbor']['core']['hostAliases']
                app['spec']['source']['helm']['valuesObject'] = historical
            else: app['spec']['source']['helm']['valuesObject'].pop('maintenance')
        expected_client = client('https://' + snapshot['profile']['loginHost'] + '/realms/platform', 'https://' + snapshot['profile']['harborHost'])
        resources[('configmap', 'identity-private-state')] = {'data': {'desired_state': json.dumps({'realms': {'platform': {'clients': [expected_client]}}}), 'revocations': '{}'}}
        with tempfile.TemporaryDirectory() as directory, patch.object(native, 'BASE', Path(directory)), patch.object(native, 'context', return_value=snapshot), \
                patch.object(native, 'receipt', return_value={}), patch.object(native, 'get', side_effect=lambda kind, name, *args: copy.deepcopy(resources.get((kind, name)))), \
                patch.object(native.source, 'authority_path', side_effect=lambda path, missing=False: path.stat() if path.exists() else None), \
                patch('playbooks.keycloak.files.ownership.accepted_application', return_value=active), \
                patch.object(native.source, 'root_guard', return_value=snapshot['targets'][0]), patch.object(native, 'application_ready', return_value=True), \
                patch.object(recovery, 'atomic') as write:
            (Path(directory) / 'deployment-proof.json').write_text('{"phase":"ready"}')
            (Path(directory) / 'verification-failure.json').write_text('{"type":"HistoricalFailure"}')
            self.assertTrue(native.prepare())
            self.assertEqual(write.call_args.args[1]['revision'], native.REVISION)
            self.assertEqual(write.call_args.args[1]['applications'], {name: 'app-' + name for name in native.APPS})
            write.reset_mock()
            resources[('application.argoproj.io', native.APPS[0])]['spec']['source']['helm']['valuesObject']['harbor']['core']['replicas'] = 0
            with self.assertRaisesRegex(RuntimeError, 'idle ownerless'): native.prepare()
            write.assert_not_called()
