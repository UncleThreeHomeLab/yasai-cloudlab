"""Check policy preservation and enrollment isolation without changing a tailnet."""
import unittest
from control import candidate, HOST_TAG, TEST_TAG


class PolicyTests(unittest.TestCase):
    def test_implicit_allow_all_preserves_existing_destinations(self):
        original = {'tagOwners': {'tag:other': ['autogroup:admin']}}
        devices = [{'user': 'owner@example.test'}, {'user': 'other@example.test'}]
        value = candidate(original, 'owner@example.test', [22], devices)
        self.assertEqual(value['grants'][0]['dst'], ['other@example.test', 'owner@example.test', 'tag:other'])
        self.assertNotIn(HOST_TAG, value['grants'][0]['dst'])
        self.assertEqual(value['tagOwners']['tag:other'], original['tagOwners']['tag:other'])
        self.assertEqual(candidate(value, 'owner@example.test', [22], devices), value)
        self.assertEqual(set(original), {'tagOwners'})

    def test_explicit_unrelated_rules_survive_unchanged(self):
        rule = {'src': ['tag:other'], 'dst': ['tag:another'], 'ip': ['tcp:443']}
        value = candidate({'grants': [rule]}, 'owner@example.test', [2222])
        self.assertEqual(value['grants'][0], rule)
        self.assertEqual(value['grants'][1]['ip'], ['tcp:2222'])
        self.assertTrue(any(t['src'] == TEST_TAG and HOST_TAG + ':2222' in t['deny'] for t in value['tests']))

    def test_existing_tag_owner_conflict_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'different owners'):
            candidate({'acls': [], 'tagOwners': {HOST_TAG: ['someone@example.test']}}, 'owner@example.test', [22])


if __name__ == '__main__':
    unittest.main()
