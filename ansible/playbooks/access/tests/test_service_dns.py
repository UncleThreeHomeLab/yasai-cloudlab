import unittest
from pathlib import Path
import subprocess
import sys
import tempfile

from playbooks.access.files.service_dns import desired


class ServiceDnsTests(unittest.TestCase):
    def test_host_helper_uses_only_its_installed_contract_dependency(self):
        root = Path(__file__).resolve().parents[1] / 'files'
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)
            for name in ('service_dns.py', 'contract.py'):
                (target / name).write_bytes((root / name).read_bytes())
            result = subprocess.run([sys.executable, '-I', '-c',
                "import sys;sys.path.insert(0,sys.argv[1]);from service_dns import desired;"
                "assert desired({'zone':'internal.example.invalid','names':['cd']},"
                "{'class':'private','access':'tailnet','hostname':'notes.internal.example.invalid'},"
                "['cd'],published=True)['names']==['cd','notes']", folder], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_private_publication_and_removal_preserve_unrelated_records(self):
        payload = {'zone': 'internal.example.invalid', 'names': ['cd', 's3'], 'unchanged': 'retained'}
        exposure = {'class':'private','access':'tailnet','hostname':'fixture.internal.example.invalid'}
        published = desired(payload, exposure, ['cd'], published=True)
        self.assertEqual(published['names'], ['cd','fixture','s3'])
        self.assertEqual(desired(published, exposure, ['cd'], published=False), payload)
        self.assertEqual(payload['names'], ['cd','s3'])
        for hostname in ('cd.internal.example.invalid','fixture.internal.other.invalid','s3.internal.example.invalid'):
            with self.assertRaises(ValueError): desired(payload, dict(exposure,hostname=hostname), ['cd'], published=False)
