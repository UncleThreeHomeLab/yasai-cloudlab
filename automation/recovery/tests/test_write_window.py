"""The initial exception cannot change monthly jobs or survive its expiry."""
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

import write_window
from monthly_window import seconds_remaining
from repository import Repository


class WindowTests(unittest.TestCase):
    def test_replacement_exception_expires_and_does_not_change_monthly_window(self):
        with patch.object(write_window, '_replacement', True):
            self.assertGreater(write_window.require_window(now=datetime(2026, 10, 4, 1, tzinfo=timezone.utc)), 3600)
            for now in (datetime(2026, 10, 3, 22, tzinfo=timezone.utc),
                        datetime(2026, 10, 4, 4, tzinfo=timezone.utc)):
                with self.assertRaises(RuntimeError):
                    write_window.require_window(now=now)
        self.assertEqual(seconds_remaining(datetime(2026, 10, 4, 1, tzinfo=timezone.utc)), 0)

    def test_verified_replacement_marker_blocks_replay_before_writes(self):
        repository = object.__new__(Repository)
        repository.values = {}
        snapshot = {'id': 'previous', 'time': '2026-10-04', 'tags': ['owned', 'verified', write_window.REPLACEMENT_TAG]}
        with patch('repository.require_window', return_value=7200), \
             patch('repository.replacement_active', return_value=True), \
             patch.object(repository, 'initialize'), \
             patch.object(repository, 'snapshots', return_value=[snapshot]), \
             patch.object(repository, 'run') as command, patch('b2.S3') as backend:
            with self.assertRaisesRegex(RuntimeError, 'unused exception'):
                repository.export(None, {'tag': 'owned'}, None)
            command.assert_not_called()
            backend.return_value.cleanup.assert_not_called()

    def test_remote_verified_generation_blocks_another_initial_export(self):
        repository = object.__new__(Repository)
        repository.values = {}
        with patch('repository.require_window', return_value=7200), \
             patch('repository.initial_active', return_value=True), \
             patch.object(repository, 'initialize'), \
             patch.object(repository, 'snapshots', return_value=[{'tags': ['verified']}]), \
             patch.object(repository, 'run') as command, patch('b2.S3') as backend:
            with self.assertRaisesRegex(RuntimeError, 'already consumed'):
                repository.export(None, {}, None)
            command.assert_not_called()
            backend.return_value.cleanup.assert_not_called()

    def test_normal_job_remains_monthly(self):
        now = datetime(2026, 10, 3, 21, tzinfo=timezone.utc)
        with patch.object(write_window, '_initial', False):
            with self.assertRaises(RuntimeError):
                write_window.require_window(now=now)
        self.assertEqual(seconds_remaining(now), 0)

    def test_explicit_initial_window_is_bounded(self):
        with patch.object(write_window, '_initial', True):
            self.assertEqual(write_window.require_window(now=datetime(2026, 10, 3, 21, tzinfo=timezone.utc)), 10800)
            for now in (datetime(2026, 10, 2, tzinfo=timezone.utc),
                        datetime(2026, 10, 4, tzinfo=timezone.utc),
                        datetime(2026, 11, 1, tzinfo=timezone.utc)):
                with self.assertRaises(RuntimeError):
                    write_window.require_window(now=now)
            with self.assertRaises(RuntimeError):
                write_window.require_window(reserve=3600, now=datetime(2026, 10, 3, 23, tzinfo=timezone.utc))


if __name__ == '__main__':
    unittest.main()
