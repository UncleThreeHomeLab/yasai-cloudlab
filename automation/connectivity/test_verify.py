"""Recovery must satisfy its deadline even when the eventual response succeeds."""
import unittest
from unittest.mock import patch

from automation.connectivity import verify


class RecoveryDeadlineTests(unittest.TestCase):
    def test_late_success_cannot_reset_exceeded_recovery_deadline(self):
        with patch.object(verify, 'remote', return_value={}), \
                patch.object(verify.time, 'monotonic', side_effect=[0, 0, 31]), \
                patch.object(verify.concurrent.futures, 'ThreadPoolExecutor') as executor:
            executor.return_value.__enter__.return_value.submit.return_value.done.return_value = True
            with self.assertRaisesRegex(RuntimeError, '30-second failure recovery limit'):
                verify.disruption('fixture', lambda: True)
