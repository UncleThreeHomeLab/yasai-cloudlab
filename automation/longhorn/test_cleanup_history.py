"""Version cleanup preserves visible objects and never removes hide markers."""
from datetime import datetime, timezone
import unittest
from unittest.mock import Mock

from cleanup_history import POLICY, one_time_window, plan, run


def row(name, version, action='upload', size=10):
    return {'fileName': POLICY['prefix'] + name, 'fileId': version, 'action': action,
            'contentLength': size, 'uploadTimestamp': 1}


class HistoryTests(unittest.TestCase):
    def test_plan_protects_current_objects_and_delete_markers(self):
        rows = [row('a', 'new'), row('a', 'old'), row('b', 'marker', 'hide'), row('b', 'deleted')]
        current, hidden = plan(rows, POLICY['prefix'])
        self.assertEqual([r['fileId'] for r in hidden], ['old', 'deleted'])
        self.assertEqual(len(current), 2)

    def test_scope_escape_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'escaped'):
            plan([dict(row('a', 'v'), fileName='k3s-restic/data')], POLICY['prefix'])

    def test_apply_deletes_only_old_versions_and_verifies_visible_objects(self):
        api = Mock()
        current = row('a', 'new')
        marker = row('b', 'marker', 'hide')
        old = [row('a', 'old'), row('b', 'deleted')]
        api.versions.side_effect = [[current, old[0], marker, old[1]], [current, marker]]
        result = run(api, True, Mock(return_value=3600))
        self.assertEqual([c.args[0] for c in api.delete_version.call_args_list], old)
        self.assertTrue(result['current_uploads_unchanged'])
        self.assertEqual(result['remaining_historical_versions'], 0)

    def test_dry_run_never_deletes(self):
        api = Mock()
        api.versions.return_value = [row('a', 'new'), row('a', 'old')]
        run(api)
        api.delete_version.assert_not_called()

    def test_expired_exception_fails(self):
        with self.assertRaises(RuntimeError):
            one_time_window(now=datetime(2026, 10, 5, tzinfo=timezone.utc))

    def test_concurrent_visible_change_is_not_reported_as_success(self):
        api = Mock()
        api.versions.side_effect = [[row('a', 'new'), row('a', 'old')], [row('a', 'concurrent')]]
        with self.assertRaisesRegex(RuntimeError, 'changed during cleanup'):
            run(api, True, Mock(return_value=3600))


if __name__ == '__main__':
    unittest.main()
