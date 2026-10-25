"""Application workflow pins form one independently verified human-delivered patch."""
from pathlib import Path
import io
import json
import tempfile
import unittest
from unittest.mock import patch

from playbooks.dependencies.files import actions


class ActionTests(unittest.TestCase):
    def source(self, *, release_commit='a' * 40, annotated=False, runtime='node24'):
        def response(request, **kwargs):
            url = request.full_url if hasattr(request, 'full_url') else request
            if url.endswith('/releases/latest'):
                value = {'tag_name': 'v6.0.3', 'draft': False, 'prerelease': False,
                         'html_url': 'https://github.com/actions/checkout/releases/tag/v6.0.3'}
            elif '/git/ref/tags/' in url:
                value = {'ref': 'refs/tags/v6.0.3', 'object': {
                    'type': 'tag' if annotated else 'commit', 'sha': 'c' * 40 if annotated else release_commit}}
            elif '/git/tags/' in url:
                value = {'object': {'type': 'commit', 'sha': release_commit}}
            elif '/git/commits/' in url:
                # GitHub can expose this unmerged fork-network object upstream.
                value = {'sha': 'b' * 40, 'html_url': 'https://github.com/actions/checkout/commit/' + 'b' * 40}
            else:
                return io.BytesIO(('runs:\n  using: ' + runtime + '\n').encode())
            return io.BytesIO(json.dumps(value).encode())
        return response

    def test_fork_network_commit_endpoint_cannot_grant_release_provenance(self):
        with patch('urllib.request.urlopen', side_effect=self.source()), self.assertRaises(ValueError):
            actions.official('b' * 40)

    def test_current_annotated_stable_release_resolves_to_exact_supported_commit(self):
        with patch('urllib.request.urlopen', side_effect=self.source(annotated=True)):
            self.assertEqual(actions.official('a' * 40), 'a' * 40)
        with patch('urllib.request.urlopen', side_effect=self.source(runtime='node20')), self.assertRaises(ValueError):
            actions.official('a' * 40)

    def test_exact_three_checkout_uses_change_together_without_other_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, relative in enumerate(actions.FILES):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(('uses: actions/checkout@' + 'a' * 40 + '\n') * (index + 1) + 'persist-credentials: false\n')
            with patch.object(actions, 'official', return_value='b' * 40):
                result = actions.update(root, 'b' * 40)
            self.assertEqual(result['revision'], 'b' * 40)
            self.assertEqual(result['delivery'], 'authorized-maintainer')
            self.assertEqual(sum((root / relative).read_text().count('actions/checkout@' + 'b' * 40)
                                 for relative in actions.FILES), 3)
            self.assertTrue(all('persist-credentials: false' in (root / relative).read_text() for relative in actions.FILES))

    def test_incomplete_companion_inventory_does_not_write_either_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in actions.FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('uses: actions/checkout@' + 'a' * 40 + '\n')
            before = {path: (root / path).read_bytes() for path in actions.FILES}
            with patch.object(actions, 'official', return_value='b' * 40), self.assertRaises(ValueError):
                actions.update(root, 'b' * 40)
            self.assertEqual(before, {path: (root / path).read_bytes() for path in actions.FILES})

    def test_nonimmutable_revision_is_rejected_before_public_lookup(self):
        for revision in ('main', 'v6', 'a' * 40 + '\nrun: bad'):
            with self.assertRaises(ValueError):
                actions.official(revision)
