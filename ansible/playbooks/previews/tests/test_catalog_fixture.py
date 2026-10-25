import base64
import copy
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

import catalog_fixture as fixture
from fixtures import approval, catalog


class CatalogFixtureTests(unittest.TestCase):
    def snapshot(self, settings):
        return {'catalog': settings, 'revision': 'c' * 40, 'blob': None,
                'raw': base64.b64encode(json.dumps({'catalog': settings}).encode()).decode()}

    def test_inspection_captures_exact_revision_blob_bytes_or_absence(self):
        raw = json.dumps({'catalog': catalog([])}, indent=2).encode()
        blob = {'type': 'file', 'encoding': 'base64', 'content': base64.b64encode(raw).decode(),
                'size': len(raw), 'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
        api = Mock(request=Mock(side_effect=[{'object': {'sha': 'c' * 40}}, blob]))
        result = fixture.inspect(api, 'example/private')
        self.assertEqual(base64.b64decode(result['raw']), raw)
        self.assertEqual(result['blob'], blob['sha'])
        api.request.side_effect = [{'object': {'sha': 'c' * 40}}, None]
        self.assertIsNone(fixture.inspect(api, 'example/private')['catalog'])
        api.request.side_effect = [{'object': {'sha': 'c' * 40}}, dict(blob, sha='d' * 40)]
        with self.assertRaises(ValueError): fixture.inspect(api, 'example/private')

    def test_owned_updates_preserve_concurrent_user_fields_and_authorization_until_absent(self):
        row, other = approval(), approval('b' * 32)
        original = self.snapshot(catalog([row]))
        expected = fixture.entries(original['catalog'], [row['instance']])
        current = self.snapshot(catalog([row, other]))
        current['catalog']['hostname'] = 'changed.internal.example.invalid'
        result = fixture.update(current, expected, {row['instance']: None})
        self.assertEqual(result['catalog']['approvals'], [other])
        self.assertEqual(result['catalog']['ownership'], current['catalog']['ownership'])
        self.assertEqual(result['catalog']['hostname'], current['catalog']['hostname'])
        result = fixture.restoration(original, current, expected, absent=[row['instance']])
        restored = json.loads(base64.b64decode(result['raw']))['catalog']
        self.assertEqual(restored['approvals'], [other])
        self.assertEqual(set(restored['ownership']), {'cloudlab-preview-' + other['instance']})
        changed = copy.deepcopy(current)
        changed['catalog']['approvals'][0]['definition']['message'] = 'changed owned data'
        with self.assertRaises(ValueError): fixture.update(changed, expected, {row['instance']: None})
        with self.assertRaises(ValueError): fixture.require_fixture_only(current['catalog'], {row['instance']})

    def test_empty_restoration_retains_exact_bytes_and_absent_file_cannot_delete_user_data(self):
        row = approval()
        original = self.snapshot(catalog([]))
        current = self.snapshot(catalog())
        expected = fixture.entries(current['catalog'], [row['instance']])
        self.assertEqual(fixture.restoration(original, current, expected, absent=[row['instance']])['raw'], original['raw'])
        original.update(catalog=None, raw=None)
        result = fixture.restoration(original, current, expected, absent=[row['instance']])
        self.assertIsNotNone(result['raw'])
        self.assertEqual(json.loads(base64.b64decode(result['raw']))['catalog']['approvals'], [])

    def test_review_requires_same_main_and_exact_reviewed_pr_head(self):
        snapshot = self.snapshot(catalog([]))
        pull = {'state': 'open', 'draft': False, 'base': {'sha': snapshot['revision']}, 'head': {'sha': 'd' * 40}}
        fixture.reviewed(snapshot, copy.deepcopy(snapshot), pull, 'd' * 40)
        for current, proposed in ((dict(snapshot, revision='e' * 40), pull),
                                  (snapshot, dict(pull, head={'sha': 'f' * 40}))):
            with self.assertRaises(ValueError): fixture.reviewed(snapshot, current, proposed, 'd' * 40)

    def test_journal_is_durable_private_and_confined(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / ('a' * 32) / 'journal.json'
            with patch.object(fixture, 'JOURNALS', root):
                observed = fixture.journal(target, {'private': 'synthetic'})
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
                self.assertEqual(json.loads(target.read_text()), {'private': 'synthetic'})
                with self.assertRaises(ValueError): fixture.journal(target, {'overwrite': True})
                updated = fixture.journal(target, {'updated': True}, expected=observed)
                self.assertNotEqual(observed, updated)
                with self.assertRaises(ValueError): fixture.journal(target, {}, expected=observed)
                self.assertEqual(json.loads(target.read_text()), {'updated': True})
                with self.assertRaises(ValueError): fixture.journal(root / 'public.json', {})
