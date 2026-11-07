"""Certificate inputs resolve their private-source helpers from live modules."""
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve()
for extra in ('argocd/files', 'istio/files'):
    sys.path.insert(0, str(HERE.parents[2] / extra))
sys.path.insert(0, str(HERE.parents[4] / 'ansible'))
sys.path.insert(0, str(HERE.parents[1] / 'files'))
spec = importlib.util.spec_from_file_location(
    'certificates_inputs', HERE.parents[1] / 'files/inputs.py')
cert_inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cert_inputs)


class HelperResolutionTests(unittest.TestCase):
    def test_prepare_imports_resolve_to_live_modules(self):
        with self.assertRaises(ValueError):
            cert_inputs.prepare({}, {}, {}, '0' * 40)

    def test_no_reference_to_retired_keycloak_playbook(self):
        source = (HERE.parents[1] / 'files/inputs.py').read_text()
        self.assertNotIn('playbooks.keycloak', source)


if __name__ == '__main__':
    unittest.main()
