"""Host and Tailscale rules survive scoped cleanup of stopped Kubernetes."""
import unittest
from k3s_network import cleanup_transaction


class NetworkCleanupTests(unittest.TestCase):
    def test_only_owned_chains_and_their_references_are_removed(self):
        def chain(name, table='filter', family='ip'):
            return {'chain': dict(family=family, table=table, name=name)}
        def rule(name, handle, target, table='filter', family='ip'):
            return {'rule': dict(family=family, table=table, chain=name,
                                 handle=handle, expr=[{'jump': {'target': target}}])}
        entries = [chain('KUBE-ROUTER-FORWARD'), chain('KUBE-POD-FW-ABC'),
                   chain('ts-forward'), chain('forward', 'cloudlab', 'inet'),
                   rule('FORWARD', 1, 'KUBE-ROUTER-FORWARD'),
                   rule('FORWARD', 2, 'ts-forward'),
                   rule('KUBE-ROUTER-FORWARD', 3, 'KUBE-POD-FW-ABC')]
        commands = cleanup_transaction({'nftables': entries})['nftables']
        self.assertEqual(commands[0]['delete']['rule']['handle'], 1)
        self.assertEqual(len(commands), 5)
        self.assertEqual([next(iter(c)) for c in commands], ['delete', 'flush', 'flush', 'delete', 'delete'])
        self.assertNotIn('ts-forward', str(commands))
        self.assertNotIn('cloudlab', str(commands))

    def test_unrelated_and_misnamed_chains_are_preserved(self):
        entries = [{'chain': dict(family=f, table=t, name=n)} for f, t, n in (
            ('inet', 'cloudlab', 'KUBE-FORWARD'), ('ip', 'private', 'KUBE-FORWARD'),
            ('ip', 'filter', 'ts-input'), ('ip', 'filter', 'KUBE-;flush ruleset'))]
        self.assertEqual(cleanup_transaction({'nftables': entries})['nftables'], [])


if __name__ == '__main__':
    unittest.main()
