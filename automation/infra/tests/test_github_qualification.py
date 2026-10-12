import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from automation.infra import github_qualification as qualification


class GitHubQualificationTests(unittest.TestCase):
    def test_recovery_cannot_switch_backend_key_or_governance_credential(self):
        values = {'backend': {'PROJECT_ID': '123'}, 'encryption': {'PASSPHRASE': 'synthetic-key'}, 'token': 'synthetic-token'}
        fixture = {'backend_project_id': '123', 'encryption_hash': qualification.digest(b'synthetic-key'),
                   'credential_hash': qualification.digest(b'synthetic-token')}
        qualification.bound_values(fixture, values)
        for field in ('backend_project_id', 'encryption_hash', 'credential_hash'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'changed'):
                qualification.bound_values(fixture | {field: 'foreign'}, values)

    def fixture(self, directory):
        work = Path(directory)
        name = 'qualification-' + 'a' * 32
        root = work / 'github' / name
        root.mkdir(parents=True)
        fixture = {'name': name, 'base': name + '-base', 'head': name + '-head', 'rule_name': name, 'phase': 'prepared'}
        (root / 'fixture.json').write_text(json.dumps(fixture))
        return work, root, fixture

    def test_disposable_rule_has_exact_branch_scope_and_no_bypass(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, fixture = self.fixture(temporary)
            rule = qualification.fixture_rule(fixture)
            self.assertEqual(rule['conditions']['ref_name'], {'include': ['refs/heads/' + fixture['base']], 'exclude': []})
            self.assertEqual(rule['bypass_actors'], [])
            self.assertEqual(rule['rules'][0]['parameters']['required_approving_review_count'], 1)
            self.assertEqual(rule['rules'][1]['parameters']['required_status_checks'][0]['context'], fixture['name'])

    def test_cleanup_rejects_directory_escape_unknown_phase_and_changed_namespace(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, root, fixture = self.fixture(temporary)
            with patch.object(qualification, 'WORK', work):
                self.assertEqual(qualification.recorded(root), fixture)
                for key, value in (('base', 'main'), ('phase', 'foreign'), ('rule_name', 'production')):
                    with self.subTest(key=key):
                        (root / 'fixture.json').write_text(json.dumps(fixture | {key: value}))
                        with self.assertRaises(ValueError):
                            qualification.recorded(root)
                with self.assertRaises(ValueError):
                    qualification.recorded(root.parent / '..' / root.name)


if __name__ == '__main__':
    unittest.main()
