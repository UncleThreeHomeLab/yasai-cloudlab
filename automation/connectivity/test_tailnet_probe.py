"""Temporary API transport cannot survive interrupted tests or erase unrelated grants."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from automation.connectivity import tailnet_probe


class Provider:
    def __init__(self):
        self.policy = {'grants': [{'src': ['existing'], 'dst': ['existing'], 'ip': ['tcp:22']}]}
        self.interrupt = False

    def request(self, method, path, body=None, etag=None):
        if path.endswith('/validate'): return {}, None
        if method == 'POST':
            self.policy = copy.deepcopy(body)
            if self.interrupt:
                self.interrupt = False
                raise RuntimeError('response lost after commit')
        return copy.deepcopy(self.policy), 'fixture-etag'


class TailnetProbeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'receipt.json'
        self.api = Provider()
        self.before = copy.deepcopy(self.api.policy)
        for item in (patch.object(tailnet_probe, 'API', return_value=self.api),
                     patch.object(tailnet_probe, 'GRANT_RECEIPT', self.path)):
            item.start()
            self.addCleanup(item.stop)

    def test_failed_rbac_probe_removes_only_its_temporary_grant(self):
        with self.assertRaises(RuntimeError):
            with tailnet_probe.rbac_transport('100.64.0.1', '100.64.0.2'):
                self.assertTrue(self.path.exists())
                raise RuntimeError('probe failed')
        self.assertEqual(self.api.policy, self.before)
        self.assertFalse(self.path.exists())

    def test_lost_write_response_cleans_up_using_fresh_provider_state(self):
        self.api.interrupt = True
        with self.assertRaises(RuntimeError):
            with tailnet_probe.rbac_transport('100.64.0.1', '100.64.0.2'): pass
        self.assertEqual(self.api.policy, self.before)
        self.assertFalse(self.path.exists())

    def test_rerun_recovers_grant_retained_after_process_termination(self):
        grant = {'src': ['100.64.0.1'], 'dst': ['100.64.0.2'], 'ip': ['tcp:443']}
        self.api.policy['grants'].append(grant)
        self.path.write_text(json.dumps(grant))
        with tailnet_probe.rbac_transport('100.64.0.3', '100.64.0.2'):
            self.assertNotIn(grant, self.api.policy['grants'])
        self.assertEqual(self.api.policy, self.before)

    def test_receipt_cannot_authorize_unrelated_grant_deletion(self):
        self.path.write_text(json.dumps(self.before['grants'][0]))
        with self.assertRaises(RuntimeError): tailnet_probe.remove_retained_grant(self.api)
        self.assertEqual(self.api.policy, self.before)
