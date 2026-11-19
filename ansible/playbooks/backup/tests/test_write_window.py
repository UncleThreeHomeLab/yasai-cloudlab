"""Monthly jobs run only inside the shared day-1 UTC window."""
from datetime import datetime, timezone
import unittest

import write_window
from monthly_window import seconds_remaining


class WindowTests(unittest.TestCase):
    def test_normal_job_remains_monthly(self):
        now = datetime(2026, 10, 3, 21, tzinfo=timezone.utc)
        with self.assertRaises(RuntimeError):
            write_window.require_window(now=now)
        self.assertEqual(seconds_remaining(now), 0)

    def test_day_one_window_reports_remaining_time(self):
        now = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.assertEqual(write_window.require_window(now=now), seconds_remaining(now))
        self.assertGreater(write_window.require_window(now=now), 0)
        with self.assertRaises(RuntimeError):
            write_window.require_window(reserve=seconds_remaining(now), now=now)


if __name__ == '__main__':
    unittest.main()
