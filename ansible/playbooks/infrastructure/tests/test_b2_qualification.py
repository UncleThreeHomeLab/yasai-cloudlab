"""Exercise rejected locking and cleanup without a cloud account."""
import threading
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

from automation.data.s3 import S3Error
from playbooks.infrastructure.tests import b2_qualification as subject

VALUES = {'ENDPOINT': 's3.us-west-004.backblazeb2.com', 'REGION': 'display label',
          'KEY_ID': 'synthetic-id', 'APPLICATION_KEY': 'synthetic-secret', 'BUCKET': 'synthetic-bucket'}


class FakeS3:
    objects = {}
    mode = 'unsupported'
    mutex = threading.Lock()

    def __init__(self, *args):
        pass

    def request(self, method, bucket, key='', query=None, data=b'', headers=None):
        query = query or {}
        with self.mutex:
            if method == 'PUT':
                if headers and headers.get('If-None-Match') == '*':
                    if self.mode == 'unsupported':
                        raise S3Error(501)
                    if self.mode == 'safe' and key in self.objects:
                        raise S3Error(412)
                versions = self.objects.setdefault(key, [])
                identity = str(len(versions) + 1)
                versions.append((identity, data))
                return {'headers': {'x-amz-server-side-encryption': 'AES256', 'x-amz-version-id': identity}}
            if method == 'GET' and 'versions' in query:
                root = ET.Element('ListVersionsResult', xmlns=subject.NS['s'])
                ET.SubElement(root, 'IsTruncated').text = 'false'
                for name, versions in self.objects.items():
                    if name.startswith(query['prefix']):
                        for identity, _ in versions:
                            row = ET.SubElement(root, 'Version')
                            ET.SubElement(row, 'Key').text = name
                            ET.SubElement(row, 'VersionId').text = identity
                return {'data': ET.tostring(root)}
            if method == 'GET':
                versions = self.objects[key]
                value = next(value for identity, value in versions if identity == query['versionId']) if query else versions[-1][1]
                return {'data': value}
            if method == 'DELETE':
                self.objects[key] = [row for row in self.objects[key] if row[0] != query['versionId']]
                if not self.objects[key]:
                    del self.objects[key]
                return {}
            raise AssertionError('Unexpected operation')


class QualificationTests(unittest.TestCase):
    def test_unsupported_and_ignored_headers_never_pass_locking(self):
        for mode in ('unsupported', 'ignored', 'safe'):
            with self.subTest(mode=mode):
                FakeS3.objects = {'unrelated/backup': [('1', b'preserve')]}
                FakeS3.mode = mode
                with patch.object(subject, 'native_lock', return_value={'native_lock_rejected_501': True}):
                    result = subject.qualify(VALUES, FakeS3)
                self.assertEqual(result['eligible_for_native_locking'], mode == 'safe')
                self.assertTrue(result['version_retrieval'])
                self.assertTrue(result['cleanup'])
                self.assertEqual(FakeS3.objects, {'unrelated/backup': [('1', b'preserve')]})

    def test_endpoint_normalization_never_accepts_external_hosts(self):
        self.assertEqual(subject.endpoint(VALUES), 'https://s3.us-west-004.backblazeb2.com')
        for url in ('http://s3.us-west-004.backblazeb2.com', 'https://attacker.example',
                    'https://s3.us-west-004.backblazeb2.com.attacker.example'):
            with self.assertRaises(ValueError):
                subject.endpoint(dict(VALUES, ENDPOINT=url))

    def test_native_failure_has_exact_lock_diagnostic_and_isolated_credentials(self):
        with patch.object(subject.subprocess, 'run', side_effect=[
            Mock(returncode=0), Mock(returncode=1, stdout=b'', stderr=b'Error acquiring the state lock: StatusCode: 501')
        ]) as run:
            result = subject.native_lock(VALUES, subject.endpoint(VALUES), 'qualification/test/native.tfstate')
        self.assertTrue(result['native_lock_rejected_501'])
        self.assertEqual(run.call_args.args[0][1], 'plan')
        self.assertNotIn(VALUES['APPLICATION_KEY'], run.call_args.args[0])
        self.assertNotIn('OP_SERVICE_ACCOUNT_TOKEN', run.call_args.kwargs['env'])


if __name__ == '__main__':
    unittest.main()
