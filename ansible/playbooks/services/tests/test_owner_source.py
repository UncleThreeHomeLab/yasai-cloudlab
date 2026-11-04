"""Selected native owner validation and credential-free source boundaries."""
import copy
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import MagicMock, Mock, patch

from playbooks.services.files import gitops, inputs, owner
from playbooks.services.tests.fixtures import approval, definition, owner_api, owner_files, owner_contract


class OwnerSourceTests(unittest.TestCase):
    def public(self, revision='a' * 40):
        return {'repository': 'https://github.com/example/platform.git', 'revision': 'd' * 40,
                'services': {'revision': revision, 'catalogPath': 'services/catalog-v2.yaml'}}

    def test_exact_commit_tree_and_blob_bytes_need_only_two_rest_calls(self):
        files = owner_files()
        api, raw, _ = owner_api(files)
        source = owner.configuration(self.public())
        for _ in range(2):
            self.assertEqual(owner.chart_files(source, fetch=api, read_file=raw), files)
        self.assertEqual(api.call_count, 4)
        self.assertEqual(raw.call_count, 2 * len(files))
        self.assertFalse(any('/blobs/' in call.args[0] for call in api.call_args_list))
        with owner.chart(self.public(), fetch=api, read_file=raw) as root:
            self.assertEqual((root / 'Chart.yaml').read_bytes(), files['Chart.yaml'])
            self.assertFalse(any(path.is_symlink() for path in root.rglob('*')))
        self.assertFalse(root.exists())

    def test_wrong_commit_incomplete_tree_unsafe_modes_paths_and_bytes_fail(self):
        files = owner_files()
        source = owner.configuration(self.public())
        for change in ('commit', 'tree', 'truncated', 'link', 'path', 'duplicate', 'size', 'missing', 'bytes'):
            api, raw, documents = owner_api(files)
            commit, tree = list(documents.values())
            if change == 'commit': commit['sha'] = 'c' * 40
            if change == 'tree': tree['sha'] = 'c' * 40
            if change == 'truncated': tree['truncated'] = True
            if change == 'link': tree['tree'][0]['mode'] = '120000'
            if change == 'path': tree['tree'][0]['path'] = owner.CHART + '../escape'
            if change == 'duplicate': tree['tree'].append(copy.deepcopy(tree['tree'][0]))
            if change == 'size': tree['tree'][0]['size'] = owner.MAX_FILE + 1
            if change == 'missing': tree['tree'] = []
            if change == 'bytes': raw.side_effect = lambda *args: b'wrong bytes'
            with self.subTest(change=change), self.assertRaises(ValueError):
                owner.chart_files(source, fetch=api, read_file=raw)

    def test_unavailable_owner_never_uses_checkout_chart(self):
        catalog = {'catalog': [{'definition': definition(), 'approval': approval(), 'publication': 'ready'}],
                   'dataApprovals': {}}
        with patch.object(owner, 'chart', side_effect=ValueError('owner unavailable')), \
                patch.object(inputs, 'resources') as render:
            with self.assertRaisesRegex(ValueError, 'owner unavailable'):
                inputs.validate_catalog(catalog, public=self.public())
            render.assert_not_called()

    def test_source_response_bytes_deadline_and_redirects_are_bounded(self):
        response = MagicMock()
        response.read1.side_effect = [b'oversized']
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(owner.urllib.request, 'build_opener', return_value=opener) as build:
            with self.assertRaisesRegex(ValueError, 'bound'):
                owner.read_url('https://api.github.com/synthetic', time.monotonic() + 5, 2)
            self.assertEqual(build.call_args.args[0].proxies, {})
            self.assertIsInstance(build.call_args.args[1], owner.NoRedirect)
            self.assertIsNone(build.call_args.args[1].redirect_request(None, None, None, None, None, None))
            self.assertEqual(opener.open.call_args.args[0].header_items(), [('User-agent', 'cloudlab-service-owner')])
        with self.assertRaisesRegex(ValueError, 'deadline'):
            owner.read_url('https://api.github.com/synthetic', time.monotonic() - 1, 2)

    def test_legacy_and_current_inputs_use_selected_native_schema_once_per_catalog(self):
        old, current = owner_contract(current=False), owner_contract(current=True)
        catalog = {'catalog': [{'definition': definition(), 'approval': approval(), 'publication': 'ready'}],
                   'dataApprovals': {}}
        catalog['catalog'][0]['approval'].pop('egress')
        second = copy.deepcopy(catalog['catalog'][0])
        second['definition']['name'] = second['approval']['name'] = 'second'
        second['approval'].update(namespace='cloudlab-app-second', valuesPath='apps/second.yaml')
        catalog['catalog'].append(second)
        prepared = copy.deepcopy(catalog)
        for entry in prepared['catalog']:
            entry['approval']['egress'] = []
        acquisitions = []
        @contextmanager
        def selected(public):
            acquisitions.append(public['services']['revision'])
            files = old if public['services']['revision'] == 'a' * 40 else current
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name, contents in files.items():
                    target = root / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(contents)
                yield root
        render = gitops._render
        def native_only(args, payload, **kwargs):
            self.assertNotEqual(args[3], str(owner.ROOT / 'platform/delivery/services'))
            return render(args, payload, **kwargs)
        with patch.object(owner, 'chart', side_effect=selected), patch.object(gitops, '_render', side_effect=native_only):
            self.assertEqual(inputs.validate_catalog(catalog, public=self.public()), catalog)
            self.assertEqual(inputs.validate_catalog(prepared, public=self.public('c' * 40)), prepared)
            for value, revision in ((catalog, 'c' * 40), (prepared, 'a' * 40)):
                with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, 'catalog failed'):
                    inputs.validate_catalog(value, public=self.public(revision))
        self.assertEqual(acquisitions, ['a' * 40, 'c' * 40, 'c' * 40, 'a' * 40])

    def test_native_renderer_does_not_inherit_provider_credentials(self):
        spawn = subprocess.Popen
        with patch.dict(os.environ, {'OP_SERVICE_ACCOUNT_TOKEN': 'synthetic-reader', 'VM_PASSWORD': 'synthetic-password',
                                     'KUBECONFIG': '/untrusted/config', 'HELM_PLUGINS': '/untrusted/plugins'}), \
                patch.object(gitops.subprocess, 'Popen', side_effect=spawn) as run:
            gitops.resources(definition(), approval(), 'https://github.com/example/platform.git', 'a' * 40)
        for key in ('OP_SERVICE_ACCOUNT_TOKEN', 'VM_PASSWORD', 'KUBECONFIG', 'HELM_PLUGINS'):
            self.assertNotIn(key, run.call_args.kwargs['env'])

    def test_declared_coordinates_cannot_be_replaced_by_operation_bundle(self):
        with patch.object(owner, 'chart') as acquire:
            with self.assertRaisesRegex(ValueError, 'declared public owner'):
                gitops.resources(definition(), approval(), self.public()['repository'], 'd' * 40, public=self.public())
            acquire.assert_not_called()
