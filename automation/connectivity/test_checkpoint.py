"""A second process cannot mutate provider receipts while their owner is active."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from automation.connectivity.checkpoint import SERVER, Receipts


class ReceiptTests(unittest.TestCase):
    def test_durable_resume_and_concurrent_owner_rejection(self):
        with tempfile.TemporaryDirectory() as folder:
            script = SERVER.replace("'/var/lib/cloudlab/connectivity/receipts'", repr(folder))

            def start():
                return subprocess.Popen([sys.executable, '-u', '-c', script], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

            first = start()
            try:
                receipts = Receipts(first)
                self.assertTrue(receipts.response()['ready'])
                receipts.save('external', {'binding': 'fixture', 'objects': {'app': {'id': 'retained'}}})
                second = start()
                second.communicate(timeout=5)
                self.assertNotEqual(second.returncode, 0)
            finally:
                first.communicate(timeout=5)
            resumed = start()
            try:
                receipts = Receipts(resumed)
                self.assertTrue(receipts.response()['ready'])
                self.assertEqual(receipts.load('external')['objects']['app']['id'], 'retained')
                self.assertEqual((Path(folder) / 'external.json').stat().st_mode & 0o777, 0o600)
            finally:
                resumed.communicate(timeout=5)
