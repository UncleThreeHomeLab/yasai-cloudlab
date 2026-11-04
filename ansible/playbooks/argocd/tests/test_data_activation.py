"""Authenticated data preparation, historical absence and pinned owner failures."""
import base64
from contextlib import nullcontext
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import data_activation
from playbooks.argocd.files.github_setup import GitHubHTTPError
from playbooks.data.files import native

ROOT = Path(__file__).resolve().parents[4]


class DataActivationTests(unittest.TestCase):
    def setUp(self):
        self.public = {'repository': 'https://github.com/example/platform.git',
            'data': {'enabled': True, 'configuration': {'enabled': False, 'revision': 'a' * 40, 'seaweedfsRevision': 'c' * 40}},
            'services': {'enabled': True, 'revision': 'd' * 40}}
        self.target = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}
        self.profile = {'database': 'notes', 'applicationRole': 'notes_app', 'migrationRole': 'notes_migration',
            'backupRole': 'backup', 'bucket': 'notes', 'identity': {'enabled': True, 'database': 'keycloak', 'role': 'keycloak'}}
        self.documents = {'platform/data.yaml': self.profile, 'platform/certificates.yaml': {'zone': 'example.invalid', 'production': True},
                          'services/catalog.json': {'catalog': [], 'dataApprovals': {}}}
        self.client = Mock(side_effect=AssertionError('No callable client'))
        def read(method, path, **kwargs):
            for filename, obj in self.documents.items():
                if path == 'repos/example/private/contents/' + filename + '?ref=' + 'b' * 40:
                    if obj is None:
                        self.assertEqual(kwargs, {'missing': True})
                        return None
                    raw = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
                    return {'type': 'file', 'path': filename, 'encoding': 'base64', 'size': len(raw),
                        'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
                        'content': base64.b64encode(raw).decode()}
            raise AssertionError('Unexpected source coordinate')
        self.client.request.side_effect = read
        metadata = {'cnpg-notes-production': {'username': 'notes_app', 'database': 'notes'},
            'cnpg-notes-migration': {'username': 'notes_migration', 'database': 'notes'},
            'cnpg-keycloak': {'username': 'keycloak', 'database': 'keycloak'}, 'cnpg-backup': {'username': 'backup'},
            's3-notes-production': {'BUCKET': 'notes'}}
        self.lookup = Mock(side_effect=lambda item, fields: {key: metadata[item][key] for key in fields})
        chart = ROOT / 'platform/data/configuration'
        self.files = {str(path.relative_to(chart)): path.read_bytes() for path in chart.rglob('*') if path.is_file()}

    def prepare(self):
        return data_activation.prepare(self.public, self.target['valuesRepository'], self.target['valuesRevision'], self.client, lookup=self.lookup)

    def test_preparation_uses_exact_private_commit_and_both_selected_native_owners(self):
        with patch('playbooks.argocd.files.source_snapshot.chart_files', return_value=self.files) as chart, \
                patch('playbooks.services.files.owner.chart', return_value=nullcontext(ROOT / 'platform/delivery/services')) as service:
            evidence = self.prepare()
        self.assertEqual(chart.call_args.args[0], {'repository': self.public['repository'], 'revision': 'a' * 40, 'path': 'platform/data/configuration'})
        service.assert_called_once_with(self.public)
        self.assertEqual(evidence['settings']['identity'], self.profile['identity'])
        self.assertEqual(evidence['settings']['s3Host'], 's3.internal.example.invalid')
        self.assertFalse(evidence['required'])
        self.assertEqual(self.client.request.call_count, 3)
        self.assertTrue(all(call.args[1].endswith('?ref=' + 'b' * 40) for call in self.client.request.call_args_list))

    def test_historical_absence_is_exact_authenticated_404_only_when_disabled(self):
        self.documents['platform/data.yaml'] = None
        with patch('playbooks.argocd.files.source_snapshot.chart_files') as chart:
            evidence = self.prepare()
            self.assertEqual(evidence['absence'], {'path': 'platform/data.yaml', 'revision': 'b' * 40, 'authenticated404': True})
            self.public['data']['configuration']['enabled'] = True
            with self.assertRaisesRegex(RuntimeError, 'authenticated private profile'): self.prepare()
            chart.assert_not_called(); self.lookup.assert_not_called()
        for error in (RuntimeError('transport unavailable'), GitHubHTTPError(403)):
            self.client.request.side_effect = error
            with self.subTest(error=type(error).__name__), self.assertRaises(RuntimeError): self.prepare()

    def test_unavailable_pinned_data_or_service_owner_never_uses_checkout_fallback(self):
        with patch('playbooks.services.files.owner.chart', side_effect=ValueError('Selected service owner unavailable')):
            with self.assertRaisesRegex(ValueError, 'Selected service owner'): self.prepare()
        with patch('playbooks.services.files.owner.chart', return_value=nullcontext(ROOT / 'platform/delivery/services')), \
                patch('playbooks.argocd.files.source_snapshot.chart_files', side_effect=ValueError('Selected data owner unavailable')):
            with self.assertRaisesRegex(ValueError, 'Selected data owner'): self.prepare()
        self.lookup.assert_not_called()

    def test_wrong_profile_scope_or_vault_metadata_cannot_prepare_binding(self):
        self.profile['serviceRequests'] = []
        with self.assertRaisesRegex(RuntimeError, 'raw schema'): self.prepare()
        self.profile.pop('serviceRequests')
        self.profile['applicationRole'] = 'other_app'
        with patch('playbooks.services.files.owner.chart', return_value=nullcontext(ROOT / 'platform/delivery/services')), \
                patch('playbooks.argocd.files.source_snapshot.chart_files', return_value=self.files):
            with self.assertRaisesRegex(RuntimeError, 'scoped vault metadata'): self.prepare()

    def test_private_contents_reject_wrong_blob_or_path(self):
        read = self.client.request.side_effect
        for change in ('path', 'sha'):
            def forged(method, path, **kwargs):
                document = read(method, path, **kwargs)
                document[change] = 'foreign'
                return document
            self.client.request.side_effect = forged
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                native.private_file(self.client, self.target['valuesRepository'], self.target['valuesRevision'], 'platform/data.yaml')

    def test_raw_profile_and_wrong_file_fields_cannot_prepare_source_binding(self):
        original = copy.deepcopy(self.documents)
        cases = []
        for field, value in (('identity', {}), ('identity', {'enabled': True, 'database': 'keycloak'}),
                             ('identity', {'enabled': 'true', 'database': 'keycloak', 'role': 'keycloak'}),
                             ('maintenance', True), ('sharedInputs', False)):
            profile = copy.deepcopy(self.profile); profile[field] = value
            cases.append(('platform/data.yaml', profile))
        certificate = copy.deepcopy(original['platform/certificates.yaml']); certificate['database'] = 'foreign'
        cases.append(('platform/certificates.yaml', certificate))
        catalog = copy.deepcopy(original['services/catalog.json']); catalog['sharedInputs'] = False
        cases.append(('services/catalog.json', catalog))
        catalog = {'catalog': [], 'dataApprovals': {'scope': {'kind': 'bucket', 'service': 'synthetic', 'name': 1, 'item': 's3-synthetic-production'}}}
        cases.append(('services/catalog.json', catalog))
        encoded = json.dumps(self.profile)
        cases.extend([('platform/data.yaml', (encoded[:-1] + ', "database": "notes"}').encode()),
                      ('platform/data.yaml', encoded.replace('"enabled": true', '"enabled": false, "enabled": true').encode()),
                      ('platform/data.yaml', (encoded + '\n---\n' + encoded).encode())])
        for path, invalid in cases:
            with self.subTest(path=path, input=repr(invalid)), \
                    patch('playbooks.services.files.owner.chart', return_value=nullcontext(ROOT / 'platform/delivery/services')), \
                    patch('playbooks.argocd.files.source_snapshot.chart_files') as chart, \
                    patch.object(native, 'render_settings') as render, patch('source_transition.kube') as binding, \
                    patch('playbooks.data.files.control.sql') as sql, patch('playbooks.data.files.control.s3') as s3:
                self.documents = copy.deepcopy(original); self.documents[path] = invalid
                with self.assertRaisesRegex(RuntimeError, 'raw schema'): self.prepare()
                chart.assert_not_called(); render.assert_not_called(); binding.assert_not_called()
                sql.assert_not_called(); s3.assert_not_called(); self.lookup.assert_not_called()
