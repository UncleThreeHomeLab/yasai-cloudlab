"""Prove resolver retention, generation rollback and restart-safe convergence."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from automation.connectivity import dns_host


class HostDNSTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.base, self.state, self.resolver = root / 'etc', root / 'state', root / 'resolv.conf'
        self.base.mkdir()
        self.state.mkdir()
        self.original = 'nameserver 1.1.1.1\n'
        self.resolver.write_text(self.original)
        self.payload = dict(zone='internal.example.invalid', names=['app'], tailnet_address='100.64.0.1',
                            host_address='10.44.0.1', cluster_gateway='10.43.0.10', tailnet_gateway='100.64.0.5',
                            nameservers=['100.64.0.1', '100.64.0.2'], artifact='fixture')
        self.patches = [patch.object(dns_host, 'BASE', self.base), patch.object(dns_host, 'STATE', self.state),
                        patch.object(dns_host, 'RESOLVER', self.resolver), patch.object(dns_host.time, 'sleep'),
                        patch.object(dns_host.subprocess, 'run', return_value=Mock(returncode=0)),
                        patch.object(dns_host.subprocess, 'Popen', return_value=Mock(poll=Mock(return_value=None))),
                        patch.object(dns_host, 'command'), patch.object(dns_host, 'validate_answers')]
        results = [p.start() for p in self.patches]
        for p in self.patches:
            self.addCleanup(p.stop)
        self.command, self.validate = results[-2:]

    def apply(self):
        return dns_host.configure(copy.deepcopy(self.payload))

    def test_candidate_failure_never_changes_host_resolver_or_active_generation(self):
        self.validate.side_effect = RuntimeError('candidate failed')
        with self.assertRaises(RuntimeError):
            self.apply()
        self.assertEqual(self.resolver.read_text(), self.original)
        self.assertFalse((self.base / 'current').exists())
        self.command.assert_not_called()

    def test_live_failure_rolls_back_to_last_verified_generation(self):
        self.apply()
        previous = (self.base / 'current').resolve()
        self.payload['tailnet_gateway'] = '100.64.0.6'
        self.validate.side_effect = lambda payload, port=53: None if port == 1053 else (_ for _ in ()).throw(RuntimeError('live failed'))
        self.command.reset_mock()
        with self.assertRaises(RuntimeError):
            self.apply()
        self.assertEqual((self.base / 'current').resolve(), previous)
        self.assertEqual(self.command.call_count, 2)
        self.assertEqual(self.resolver.read_text(), self.original)

    def test_repeat_apply_does_not_restart_or_change_generation(self):
        self.assertTrue(self.apply()['changed'])
        self.command.reset_mock()
        self.assertFalse(self.apply()['changed'])
        self.command.assert_not_called()

    def test_interruption_before_receipt_requires_restart_and_readback(self):
        self.apply()
        (self.state / 'generation').unlink()
        self.command.reset_mock()
        self.assertTrue(self.apply()['changed'])
        self.command.assert_called_once()

    def test_transient_unchanged_generation_failure_does_not_restart(self):
        self.apply()
        self.command.reset_mock()
        self.validate.side_effect = [TimeoutError(), None]
        self.assertFalse(self.apply()['changed'])
        self.command.assert_not_called()

    def test_activation_requires_both_resolvers_before_replacing_original(self):
        self.apply()
        with patch.object(dns_host, 'private_answer', side_effect=RuntimeError('second resolver failed')):
            with self.assertRaises(RuntimeError):
                dns_host.activate()
        self.assertEqual(self.resolver.read_text(), self.original)


if __name__ == '__main__':
    unittest.main()
