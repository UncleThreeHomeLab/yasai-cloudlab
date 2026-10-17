"""Existing ownership exports reject unsupported policy and publication scope."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

from playbooks.infrastructure.files import cloudflare_adoption as subject
from playbooks.infrastructure.files.cloudflare_adoption import declarations, import_document, inventory
from playbooks.infrastructure.tests.fixtures import cloudflare_owner


class AdoptionTests(unittest.TestCase):
    def test_unreviewed_provider_package_cannot_authorize_handoff(self):
        with patch.object(subject.Path, 'read_text', return_value='{"package_sha256":"review-required"}'):
            with self.assertRaisesRegex(ValueError, 'checksum has not completed review'):
                subject.require_certification(Path('/synthetic'))

    def setUp(self):
        self.snapshot, self.bundle = cloudflare_owner()

    def test_exports_every_policy_identity_without_remote_mutations(self):
        before = copy.deepcopy(self.snapshot)
        desired, imports = declarations(self.snapshot, self.bundle)
        self.assertEqual(self.snapshot, before)
        policies = desired['applications']['fixture']['policies']
        self.assertEqual({policy['id'] for policy in policies.values()},
                         {policy['id'] for policy in before['applications']['fixture.example.invalid']['policies']})
        self.assertEqual(len(imports), 3)
        self.assertEqual(len(import_document(imports)['import']), 3)
        identities = inventory(imports)
        self.assertTrue(all('import_id' not in resource for resource in identities.values()))
        self.assertEqual(identities['cloudflare_zero_trust_access_application.application["fixture"]']['aud'],
                         'existing-audience')

    def test_unrepresented_selector_or_reusable_owner_blocks_export(self):
        app = self.snapshot['applications']['fixture.example.invalid']
        app['policies'][0]['include'][0]['everyone'] = {}
        with self.assertRaisesRegex(ValueError, 'Unsupported input field'):
            declarations(self.snapshot, self.bundle)
        app['policies'][0]['include'][0].pop('everyone')
        app['policies'][0]['reusable'] = True
        with self.assertRaisesRegex(ValueError, 'application-scoped ownership'):
            declarations(self.snapshot, self.bundle)

    def test_unrelated_dns_and_missing_route_are_never_silently_removed(self):
        self.snapshot['dns']['unrelated.example.invalid'] = {}
        with self.assertRaisesRegex(ValueError, 'unrepresented routes'):
            declarations(self.snapshot, self.bundle)
        self.snapshot['dns'].clear()
        with self.assertRaisesRegex(ValueError, 'owned DNS record'):
            declarations(self.snapshot, self.bundle)

    def test_changed_tunnel_and_publication_identity_block_export(self):
        self.bundle['tunnel']['TUNNEL_ID'] = 'unrelated'
        with self.assertRaisesRegex(ValueError, 'tunnel identity'):
            declarations(self.snapshot, self.bundle)
