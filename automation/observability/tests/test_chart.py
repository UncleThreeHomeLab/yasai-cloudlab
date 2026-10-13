import hashlib
import json
from pathlib import Path
import unittest
import yaml

from automation.observability.chart import check


class ChartTests(unittest.TestCase):
    def test_isolated_native_proof_uses_identical_pins_and_no_external_network(self):
        root = Path(__file__).resolve().parents[3]
        pins = json.loads((root / 'platform/observability/images.lock.json').read_text())
        compose = yaml.safe_load((root / 'automation/observability/compose.proof.yaml').read_text())
        self.assertTrue(compose['networks']['fixture']['internal'])
        for service, pin in (('loki', 'loki'), ('tempo', 'tempo'), ('alloy', 'alloy'), ('promtool', 'prometheus')):
            self.assertEqual(compose['services'][service]['image'], pins[pin])
            self.assertIn('cpus', compose['services'][service])
            self.assertIn('mem_limit', compose['services'][service])
        self.assertEqual(compose['services']['promtool']['network_mode'], 'none')

    def test_pinned_private_bounded_telemetry_and_disjoint_owners(self):
        result = check()
        self.assertEqual(result['crds'], 10)
        self.assertLessEqual(result['cpu_limit_millicores'], 3000)
        self.assertLessEqual(result['memory_limit_mib'], 6144)
        self.assertEqual(result['offsite_backups'], 0)
