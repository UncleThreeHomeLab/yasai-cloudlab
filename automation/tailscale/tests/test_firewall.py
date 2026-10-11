import unittest
from firewall import transaction


class FirewallTests(unittest.TestCase):
    def test_only_tailscale_chains_and_standard_references_are_removed(self):
        def chain(table, name, family='ip'):
            return {'chain': {'family': family, 'table': table, 'name': name}}
        entries = [chain('filter', 'ts-input'), chain('filter', 'ts-forward'),
                   chain('filter', 'KUBE-POD-FW-fixture'), chain('cloudlab', 'input', 'inet'),
                   {'rule': {'family': 'ip', 'table': 'filter', 'chain': 'INPUT', 'handle': 7,
                             'expr': [{'jump': {'target': 'ts-input'}}]}}]
        result = transaction({'nftables': entries})['nftables']
        self.assertEqual(len(result), 5)
        self.assertEqual(result[0]['delete']['rule']['handle'], 7)
        for item in result[1:]:
            chain = next(iter(item.values()))['chain']
            self.assertTrue(chain['name'].startswith('ts-'))
        self.assertEqual(transaction({'nftables': entries[2:4]})['nftables'], [])

    def test_unexpected_reference_is_not_removed(self):
        entries = [{'chain': {'family': 'ip', 'table': 'filter', 'name': 'ts-input'}},
                   {'rule': {'family': 'ip', 'table': 'filter', 'chain': 'OTHER-OWNER', 'handle': 8,
                             'expr': [{'jump': {'target': 'ts-input'}}]}}]
        with self.assertRaisesRegex(RuntimeError, 'cleanup refused'):
            transaction({'nftables': entries})
