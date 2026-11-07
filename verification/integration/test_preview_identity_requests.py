"""Identity writer merges inline preview requests like the lifecycle controller.

While ANY request exists in previews/catalog.yaml, the identity writer must
parse the same catalog (requests merged into approvals with derived
ownership) so desired includes pending rows and preview clients provision.
Malformed requests are refused, never silently skipped.
"""
import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'platform/identity/keycloak/runtime'))
sys.path.insert(0, str(ROOT / 'platform/delivery/previews/runtime'))

import contract as lifecycle_contract
import preview_clients
import preview_contract as identity_contract

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


class FakeKeycloak:
    """Minimal admin API: find/create/update/delete over one stored client."""

    def __init__(self):
        self.stored = None
        self.calls = []

    def __call__(self, action, value):
        self.calls.append(action)
        if action == 'find':
            if self.stored is None or self.stored.get('clientId') != value:
                return []
            return [dict(self.stored)]
        if action == 'create':
            self.stored = dict(value, id='uuid-1')
            return None
        if action == 'update':
            self.stored = dict(value)
            return None
        if action == 'delete':
            self.stored = None
            return None
        raise AssertionError('unknown action ' + action)


class PreviewIdentityRequestsTests(unittest.TestCase):
    def test_catalog_with_requests_parses_and_merges_on_identity_side(self):
        raw = catalog(prices_request())
        with self.assertRaises(ValueError):
            identity_contract.runtime_catalog(raw)
        settings = identity_contract.runtime_catalog(
            identity_contract.requested_catalog(raw))
        self.assertEqual(len(settings['approvals']), 1)
        row = settings['approvals'][0]
        namespace = 'cloudlab-preview-' + row['instance']
        self.assertEqual(
            settings['ownership'][namespace],
            row['instance'] + ':' + identity_contract.digest(
                identity_contract.canonical(row)))
        self.assertNotIn('requests', settings)

    def test_merge_matches_lifecycle_controller(self):
        raw = catalog(prices_request(), prices_request(pullRequest=43))
        identity = identity_contract.runtime_catalog(
            identity_contract.requested_catalog(copy.deepcopy(raw)))
        lifecycle = lifecycle_contract.runtime_catalog(
            lifecycle_contract.requested_catalog(copy.deepcopy(raw)))
        self.assertEqual(identity, lifecycle)
        self.assertEqual(
            [row['instance'] for row in identity['approvals']],
            [row['instance'] for row in lifecycle['approvals']])
        self.assertEqual(identity['ownership'], lifecycle['ownership'])

    def test_writer_desired_includes_pending_row(self):
        settings = identity_contract.runtime_catalog(
            identity_contract.requested_catalog(catalog(prices_request())))
        row = settings['approvals'][0]
        instance = row['instance']
        digest = identity_contract.digest(identity_contract.canonical(row))
        intent = {'format': 1, 'entries': {instance: {
            'approvalDigest': digest, 'phase': 'pending',
            'originVersion': identity_contract.ORIGIN_VERSION}}}
        state = {'format': 1, 'entries': {}}
        api = FakeKeycloak()
        saved = []
        preview_clients.reconcile(
            settings, intent, state, api, saved.append, NOW, set())
        self.assertIn('create', api.calls)
        record = state['entries'][instance]
        self.assertEqual(record['phase'], 'active')
        self.assertEqual(record['approvalDigest'], digest)
        self.assertEqual(record['clientId'], 'preview-' + instance)
        self.assertTrue(saved)

    def test_malformed_requests_refused(self):
        short = prices_request()
        del short['service']
        with self.assertRaises(ValueError):
            identity_contract.requested_catalog(catalog(short))
        with self.assertRaises(ValueError):
            identity_contract.requested_catalog(
                catalog(prices_request(service='Bad_Name!')))
        with self.assertRaises(ValueError):
            identity_contract.requested_catalog(
                catalog(prices_request(profile='synthetic')))
        oversized = catalog(
            *[prices_request(pullRequest=n) for n in range(1, 22)])
        with self.assertRaises(ValueError):
            identity_contract.requested_catalog(oversized)
        conflicted = catalog(prices_request())
        row = identity_contract.request(prices_request())
        conflicted['ownership']['cloudlab-preview-' + row['instance']] = (
            row['instance'] + ':' + '0' * 64)
        with self.assertRaises(ValueError):
            identity_contract.requested_catalog(conflicted)


if __name__ == '__main__':
    unittest.main()
