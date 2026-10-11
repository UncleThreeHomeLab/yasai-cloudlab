import base64
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import yaml

from private_sources import PEM_TEMPLATE


class PemTemplateTests(unittest.TestCase):
    def test_go_template_preserves_key_material_with_folded_or_multiline_pem(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for form in (serialization.PrivateFormat.TraditionalOpenSSL, serialization.PrivateFormat.PKCS8):
            original = key.private_bytes(serialization.Encoding.PEM, form, serialization.NoEncryption()).decode()
            for text in (original, ' '.join(original.splitlines()), original.replace('\n', '\r\n')):
                with self.subTest(format=form, folded=len(text.splitlines()) == 1), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / 'Chart.yaml').write_text('apiVersion: v2\nname: pem-test\nversion: 0.1.0\n')
                    (root / 'values.yaml').write_text(yaml.safe_dump({'PRIVATE_KEY': text}))
                    (root / 'templates').mkdir()
                    template = '{{ define "pem" }}' + PEM_TEMPLATE.replace('.PRIVATE_KEY', '.Values.PRIVATE_KEY') + '{{ end }}'
                    template += '\napiVersion: v1\nkind: Secret\nmetadata: {name: fixture}\ndata:\n  key: {{ include "pem" . | b64enc | quote }}\n'
                    (root / 'templates/key.yaml').write_text(template)
                    result = subprocess.run(['helm', 'template', 'fixture', str(root)], capture_output=True, check=True)
                    normalized = base64.b64decode(yaml.safe_load(result.stdout)['data']['key'])
                    self.assertEqual(len(normalized.splitlines()), 3)
                    parsed = serialization.load_pem_private_key(normalized, password=None)
                    self.assertTrue(parsed.private_numbers() == key.private_numbers())
