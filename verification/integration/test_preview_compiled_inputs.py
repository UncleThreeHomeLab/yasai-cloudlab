"""Preview requests compile into bounded disposable lifecycle ownership.

A reviewed prices YAML approval request validates against the approval
schema, derives its deterministic instance and namespace ownership
through requested_catalog, renders the controller chart, and retires
through the same guarded path when its request is removed or expires.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'platform/delivery/previews/runtime'))

import contract
import lifecycle

SCHEMA = json.loads(
    (ROOT / 'platform/delivery/previews/approval.schema.json').read_text())

IMAGE = ('harbor.example.test/cloudlab-public/prices@sha256:' + 'd' * 64)
NOW = 1790000000


def prices_request(**overrides):
    request = {
        'service': 'prices',
        'repository': 'example/prices',
        'repositoryId': 123456,
        'pullRequest': 42,
        'sourceRevision': 'e' * 40,
        'image': IMAGE,
        'platformRevision': 'f' * 40,
        'profile': 'application',
        'definition': {
            'profile': 'application',
            'port': 8080,
            'healthPath': '/healthz',
            'environment': {'PREVIEW_MODE': 'synthetic'},
            'resources': {
                'requests': {'cpu': '50m', 'memory': '64Mi'},
                'limits': {'cpu': '100m', 'memory': '128Mi'}}},
        'createdAt': NOW - 60,
        'expiresAt': NOW + 3540}
    request.update(overrides)
    return request


def catalog(*requests):
    return {
        'hostname': 'previews.internal.example.test',
        'issuer': 'https://login.example.test/realms/applications',
        'approvals': [],
        'privateDiscovery': False,
        'ownership': {},
        'artifacts': {
            'harbor.example.test/cloudlab-public/prices': {
                'subject': 'https://github.com/example/prices/.github/workflows/ci.yaml@refs/heads/main',
                'issuer': 'https://token.actions.githubusercontent.com',
                'sourceRepository': 'example/prices',
                'public': True}},
        'requests': list(requests)}


def render(values):
    if shutil.which('helm') is None:
        raise unittest.SkipTest('helm renders the preview controller chart')
    with tempfile.TemporaryDirectory() as workspace:
        work = Path(workspace)
        (work / 'values.yaml').write_text(yaml.safe_dump(values))
        rendered = subprocess.check_output(
            ['helm', 'template', '--kube-version', '1.36',
             '-f', str(work / 'values.yaml'),
             str(ROOT / 'platform/delivery/previews')],
            text=True, timeout=120, stderr=subprocess.STDOUT)
    return [doc for doc in yaml.safe_load_all(rendered) if doc]


class PreviewCompiledInputsTests(unittest.TestCase):
    def test_request_derives_deterministic_instance_and_ownership(self):
        request = prices_request()
        validate(request, SCHEMA)
        merged = contract.requested_catalog(catalog(request))
        settings = contract.runtime_catalog(merged)
        self.assertEqual(len(settings['approvals']), 1)
        row = settings['approvals'][0]
        self.assertEqual(row['instance'],
                         contract.digest(contract.canonical(request))[:32])
        self.assertEqual(row['sourceSha'], 'e' * 40)
        self.assertEqual(row['sourcePath'], 'previews/definition.json')
        self.assertEqual(
            row['sourceDigest'],
            contract.digest(contract.canonical(request['definition'])))
        # Identical content reuses its instance; any change enrolls a new one.
        again = contract.requested_catalog(catalog(prices_request()))
        self.assertEqual(again['approvals'][0]['instance'], row['instance'])
        changed = contract.requested_catalog(
            catalog(prices_request(pullRequest=43)))
        self.assertNotEqual(changed['approvals'][0]['instance'], row['instance'])
        namespace = 'cloudlab-preview-' + row['instance']
        self.assertEqual(settings['ownership'][namespace],
                         row['instance'] + ':' + contract.digest(
                             contract.canonical(row)))

    def test_rendered_controller_carries_catalog_and_stays_suspended(self):
        settings = contract.runtime_catalog(
            contract.requested_catalog(catalog(prices_request())))
        documents = render({
            'enabled': True,
            'permissionsEnabled': False,
            'platformRepository': 'https://github.com/example/platform.git',
            'catalog': settings})
        approvals = next(doc for doc in documents
                         if doc.get('kind') == 'ConfigMap'
                         and doc['metadata']['name'] == 'cloudlab-preview-approvals')
        self.assertEqual(json.loads(approvals['data']['catalog.json']), settings)
        code = next(doc for doc in documents
                    if doc.get('kind') == 'ConfigMap'
                    and doc['metadata']['name'] == 'cloudlab-preview-code')
        self.assertIn('controller.py', code['data'])
        cron = next(doc for doc in documents if doc.get('kind') == 'CronJob')
        self.assertIs(cron['spec']['suspend'], True)
        pod = cron['spec']['jobTemplate']['spec']['template']['spec']
        self.assertEqual(pod['serviceAccountName'], 'cloudlab-previews')
        self.assertEqual(pod['containers'][0]['image'], contract.IMAGE)

    def test_removed_or_expired_requests_retire_without_reactivation(self):
        row = contract.request(prices_request())
        state = lifecycle.enroll({'entries': {}}, row, NOW)
        record = state['entries'][row['instance']]
        record['phase'] = 'active'
        # Removing the accepted request retires; expiry retires even if kept.
        self.assertEqual(lifecycle.retirement(row, None, None, NOW), 'orphan')
        self.assertEqual(
            lifecycle.retirement(row, row, None, row['expiresAt']), 'expired')
        # Re-enrollment after retirement never reactivates the instance.
        retired = dict(record, phase='retired')
        kept = lifecycle.enroll({'entries': {row['instance']: retired}}, row, NOW)
        self.assertEqual(kept['entries'][row['instance']]['phase'], 'retired')

    def test_invalid_requests_fail_schema_or_contract(self):
        with self.assertRaises(ValidationError):
            validate(prices_request(sourceRevision='main'), SCHEMA)
        with self.assertRaises(ValueError):
            contract.request(prices_request(sourceRevision='main'))
        short = prices_request(expiresAt=NOW - 31)
        with self.assertRaises(ValueError):
            contract.request(short)
        oversized = catalog(*[prices_request(pullRequest=n) for n in range(1, 22)])
        with self.assertRaises(ValueError):
            contract.requested_catalog(oversized)


if __name__ == '__main__':
    unittest.main()
