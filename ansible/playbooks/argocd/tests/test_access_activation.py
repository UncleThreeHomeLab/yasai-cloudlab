"""Immutable identity approvals cannot expand administrator authority."""
import base64
import copy
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.error

import access_activation as access
from github_setup import GitHub
from fixtures import access_evidence, access_authority


class AccessActivationTests(unittest.TestCase):
    def setUp(self):
        self.repository = 'https://github.com/example/platform.git'
        self.target = {'valuesRepository': 'https://github.com/example/private.git', 'valuesRevision': 'b' * 40}
        self.public = {'repository': self.repository, 'access': {'enabled': True,
            'configuration': {'enabled': False, 'revision': 'e' * 40}}}
        self.administrator, self.receipt, self.objects = access_authority(self.repository)
        self.evidence = access_evidence(self.repository, self.target, self.administrator)

    def read(self, kind, name): return self.objects.get((kind, name))

    def guard(self, evidence=None, root=None):
        with patch.object(access, 'receipt', return_value=self.receipt):
            return access.guard(self.evidence if evidence is None else evidence, self.target, self.read, root)

    def prepare(self, response):
        client = Mock(request=Mock(return_value=response))
        result = access.prepare(self.public, self.target['valuesRepository'], self.target['valuesRevision'], client)
        client.request.assert_called_once_with('GET', 'repos/example/private/contents/platform/access.yaml?ref=' + 'b' * 40, missing=True)
        return result

    def document(self, raw):
        return {'type': 'file', 'encoding': 'base64', 'size': len(raw), 'content': base64.b64encode(raw).decode()}

    def test_present_is_checked_even_disabled_and_captures_exact_authority(self):
        selected = self.prepare(self.document(b'administrator: admin@example.invalid\n'))
        self.assertEqual(selected, self.evidence)
        captured = self.guard(selected)
        self.assertEqual(captured['authority'], {'application_uid': 'access-app', 'binding_uid': 'access-binding'})
        self.objects['clusterrolebinding.rbac.authorization.k8s.io', access.BINDING]['metadata']['uid'] = 'replacement'
        with self.assertRaises(RuntimeError): self.guard(captured)

    def test_only_authenticated_not_found_is_absence_not_transport_or_other_http_failure(self):
        client = GitHub('synthetic')
        for status in (404, 403, 500):
            error = urllib.error.HTTPError('https://api.github.com/example', status, 'synthetic', {}, None)
            with patch.object(client.opener, 'open', side_effect=error):
                if status == 404:
                    evidence = access.prepare(self.public, self.target['valuesRepository'], self.target['valuesRevision'], client)
                    self.assertIsNone(evidence['administratorHash'])
                else:
                    with self.assertRaises(RuntimeError): access.prepare(self.public, self.target['valuesRepository'], self.target['valuesRevision'], client)
        with self.assertRaises(RuntimeError):
            access.prepare(self.public, self.target['valuesRepository'], self.target['valuesRevision'], Mock(request=Mock(side_effect=RuntimeError('offline'))))

    def test_invalid_nonregular_oversize_unicode_byte_size_and_yaml_schema_fail_closed(self):
        raw = '# comment ?\nadministrator: admin@example.invalid\n'.encode()
        self.assertEqual(self.prepare(self.document(raw)), self.evidence)
        bad = [[], {}, {'type': 'symlink'}, self.document(b'administrator: false'),
            self.document(b'administrator: admin@example.invalid\nextra: value'),
            self.document(b'administrator: first@example.invalid\nadministrator: admin@example.invalid'),
            self.document(b'administrator: admin@example.invalid\n---\nadministrator: other@example.invalid'),
            self.document(b'administrator: "not an email"'), self.document(raw) | {'size': len(raw) - 1},
            self.document(b'x' * 4097), self.document(b'{}') | {'size': True}]
        for document in bad:
            with self.subTest(document_type=type(document).__name__), self.assertRaises(RuntimeError): self.prepare(document)

    def test_absence_requires_explicit_disabled_evidence_and_no_ambiguous_native_consumer(self):
        absent = self.prepare(None)
        self.guard(absent)
        for change in ('missing', 'required', 'tracking', 'sources', 'empty-sources', 'foreign-owner'):
            evidence = copy.deepcopy(absent); objects = copy.deepcopy(self.objects)
            app = self.objects['application.argoproj.io', access.APP]
            if change == 'missing': evidence.pop('required')
            if change == 'required': evidence['required'] = True
            if change == 'tracking': app['metadata']['annotations'] = {'argocd.argoproj.io/tracking-id': access.TRACKING}
            if change == 'sources': app['spec']['sources'] = [{'ref': 'values'}]
            if change == 'empty-sources': app['spec']['sources'] = []
            if change == 'foreign-owner': app['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            with self.subTest(change=change), self.assertRaises(RuntimeError): self.guard(evidence)
            self.objects = objects
        with self.assertRaises(RuntimeError): access.validate(None, self.target)

    def test_disabled_root_override_cannot_enable_or_change_the_native_source(self):
        root = {'spec': {'source': {'repoURL': self.repository, 'path': 'gitops/roots/public', 'helm': {'valuesObject': {}}}}}
        for config in ({'enabled': True}, {'enabled': 'false'}, {'revision': 'f' * 40}):
            root['spec']['source']['helm']['valuesObject']['access'] = {'configuration': config}
            with self.subTest(config=config), self.assertRaises(RuntimeError): self.guard(root=root)

    def test_receipt_rbac_subject_role_owner_or_uid_mismatch_cannot_authorize(self):
        baseline = copy.deepcopy(self.objects)
        for change in ('receipt', 'app-uid', 'app-owner', 'subject', 'second-subject', 'role', 'tracking'):
            self.objects = copy.deepcopy(baseline)
            app = self.objects['application.argoproj.io', access.APP]
            binding = self.objects['clusterrolebinding.rbac.authorization.k8s.io', access.BINDING]
            receipt = copy.deepcopy(self.receipt)
            if change == 'receipt': self.receipt['administrator'] = '0' * 64
            if change == 'app-uid': app['metadata']['uid'] = 'replacement'
            if change == 'app-owner': app['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            if change == 'subject': binding['subjects'][0]['name'] = 'foreign@example.invalid'
            if change == 'second-subject': binding['subjects'].append(copy.deepcopy(binding['subjects'][0]))
            if change == 'role': binding['roleRef']['name'] = 'edit'
            if change == 'tracking': binding['metadata']['annotations'] = {}
            with self.subTest(change=change), self.assertRaises(RuntimeError): self.guard()
            self.receipt = receipt

    def test_receipt_permissions_and_root_ownership_are_required(self):
        def metadata(path):
            return SimpleNamespace(st_uid=0, st_mode=(stat.S_IFREG | 0o600) if path == access.RECEIPT else (stat.S_IFDIR | 0o755))
        for change in (None, 'uid', 'mode', 'symlink', 'directory'):
            def inspect(path):
                result = metadata(path)
                if path == access.RECEIPT:
                    if change == 'uid': result.st_uid = 1000
                    if change == 'mode': result.st_mode = stat.S_IFREG | 0o644
                    if change == 'symlink': result.st_mode = stat.S_IFLNK | 0o600
                elif path == access.RECEIPT.parent and change == 'directory': result.st_mode |= 0o020
                return result
            with patch.object(Path, 'lstat', inspect), patch.object(Path, 'read_text', return_value=json.dumps(self.receipt)):
                if change is None: self.assertEqual(access.receipt(), self.receipt)
                else:
                    with self.subTest(change=change), self.assertRaises(RuntimeError): access.receipt()
