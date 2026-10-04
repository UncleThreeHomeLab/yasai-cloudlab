"""Read-only lifecycle review must account for hidden data and nested rules."""
import unittest

from review_b2 import inventory, lifecycle


class ReviewTests(unittest.TestCase):
    def test_nested_expiry_cannot_be_hidden_by_a_safe_parent_rule(self):
        rules = [{'fileNamePrefix': '', 'daysFromHidingToDeleting': 1},
                 {'fileNamePrefix': 'k3s-restic/data/', 'daysFromUploadingToHiding': 30},
                 {'fileNamePrefix': 'unrelated/', 'daysFromUploadingToHiding': 1}]
        result = lifecycle(rules, 'k3s-restic/')
        self.assertTrue(result['current_objects_expire'])
        self.assertEqual(result['overlapping_rules'], 2)
        self.assertEqual(result['hidden_version_delete_days'], [1])

    def test_hidden_versions_still_count_toward_storage(self):
        files = [{'fileName': 'a/deleted', 'action': 'hide'},
                 {'fileName': 'a/deleted', 'action': 'upload', 'contentLength': 20},
                 {'fileName': 'a/retained', 'action': 'upload', 'contentLength': 30},
                 {'fileName': 'a/retained', 'action': 'upload', 'contentLength': 10}]
        result = inventory(files, {'owned': 'a/'})['owned']
        self.assertEqual(result['stored_bytes'], 60)
        self.assertEqual(result['noncurrent_bytes'], 30)
        self.assertEqual(result['hide_markers'], 1)


if __name__ == '__main__':
    unittest.main()
