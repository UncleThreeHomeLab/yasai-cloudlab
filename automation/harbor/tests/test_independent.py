import base64
import hashlib
import json
import unittest
from unittest.mock import patch

from lz4.frame import compress

from automation.harbor import independent, remote
from automation.harbor.tests.fixtures import manifest


class IndependentTests(unittest.TestCase):
    def test_independent_retrieval_requires_the_original_private_signer_without_host_delivery(self):
        from automation.harbor.signatures import SIGNER, VERIFIER, private_key, public_key
        value = manifest()
        private = private_key()
        public = public_key(private)
        credentials = {item: {field: 'synthetic-' + field for field in mapping.values()}
                       for item, mapping in independent.MATERIAL.items()}
        credentials[VERIFIER]['public_key'] = public
        credentials[SIGNER] = {'private_key': private}
        for item, mapping in independent.MATERIAL.items():
            delivered = {key: base64.b64encode(credentials[item][field].encode()).decode() for key, field in mapping.items()}
            value['secrets'][item] = hashlib.sha256(json.dumps(delivered, sort_keys=True).encode()).hexdigest()
        value['signatures'] = {'verifier_sha256': hashlib.sha256(public.encode()).hexdigest()}
        self.assertNotIn(SIGNER, value['secrets'])
        with patch.object(independent, 'fields', side_effect=lambda item, names: credentials[item]):
            self.assertEqual(independent.verify_material(value), 6)
            credentials[SIGNER]['private_key'] = private_key()
            with self.assertRaisesRegex(RuntimeError, 'Independent signing recovery material'):
                independent.verify_material(value)

    def repository(self):
        with patch('automation.data.control.secret') as cluster:
            repository = remote.Repository({'AWS_ENDPOINT': 'https://s3.us-west-004.backblazeb2.com',
                'BUCKET': 'fixture-bucket', 'REGION': 'us-west-004',
                'AWS_ACCESS_KEY_ID': 'synthetic', 'AWS_SECRET_ACCESS_KEY': 'synthetic'})
            cluster.assert_not_called()
        return repository

    def test_explicit_vault_target_uses_no_cluster_and_checks_every_native_block(self):
        repository, value = self.repository(), manifest()
        data = b'synthetic artifact and signing references'
        checksum = hashlib.sha512(data).hexdigest()[:64]
        compressed = compress(data)
        for row in value['volumes'].values():
            row['url'] = 's3://fixture-bucket@us-west-004/yasai-cloudlab/?volume=' + row['volume'] + '&backup=' + row['snapshot']
        def request(method, key, **kwargs):
            if key.endswith('.cfg'):
                row = next(row for row in value['volumes'].values() if row['snapshot'] in key)
                return {'data': json.dumps({'VolumeName': row['volume'], 'SnapshotName': row['snapshot'],
                    'CompressionMethod': 'lz4', 'Blocks': [{'BlockChecksum': checksum}]}).encode()}
            return {'data': compressed, 'bytes': len(compressed)}
        with patch.object(repository, 'request', side_effect=request):
            self.assertEqual(repository.read_blocks(value)['verified_blocks'], 3)
            compressed = compress(b'corrupted')
            with self.assertRaisesRegex(RuntimeError, 'checksum'): repository.read_blocks(value)

    def test_vault_mapping_matches_delivered_fields_and_rejects_changed_material(self):
        value = manifest()
        credentials = {item: {field: 'synthetic-' + field for field in mapping.values()}
                       for item, mapping in independent.MATERIAL.items()}
        for item, mapping in independent.MATERIAL.items():
            delivered = {key: base64.b64encode(credentials[item][field].encode()).decode() for key, field in mapping.items()}
            value['secrets'][item] = hashlib.sha256(json.dumps(delivered, sort_keys=True).encode()).hexdigest()
        with patch.object(independent, 'fields', side_effect=lambda item, names: credentials[item]):
            self.assertEqual(independent.verify_material(value), 6)
            credentials['harbor-token-signing']['tls_key'] = 'changed'
            with self.assertRaisesRegex(RuntimeError, 'material changed'): independent.verify_material(value)

    def test_off_window_retrieval_stops_before_credentials_or_cloud(self):
        with patch.object(independent, 'require_window', side_effect=RuntimeError('outside window')), \
                patch.object(independent, 'fields') as vault, patch.object(independent, 'Repository') as repository:
            with self.assertRaisesRegex(RuntimeError, 'outside window'): independent.retrieve()
            vault.assert_not_called()
            repository.assert_not_called()

    def test_retained_generation_selection_is_by_capture_time(self):
        repository = self.repository()
        first, second = manifest(), manifest()
        second['captured_at'] += 1
        with patch.object(repository, 'manifests', return_value=[second, first]):
            self.assertIs(repository.latest(), second)
        with patch.object(repository, 'manifests', return_value=[]):
            with self.assertRaises(RuntimeError): repository.latest()
