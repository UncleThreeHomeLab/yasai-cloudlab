"""Requests remain data-owned even when onboarding callers supply their inputs."""
import unittest

from automation.data.requests import resolve


class RequestResolutionTests(unittest.TestCase):
    def test_wrong_vault_database_and_overlapping_roles_are_rejected(self):
        request = {'service': 'fixture', 'namespace': 'cloudlab-app-fixture', 'database': {
            'name': 'fixture', 'item': 'cnpg-fixture-production', 'migrationItem': 'cnpg-fixture-migration'}}
        with self.assertRaises(ValueError):
            resolve([request], lambda *args: {'database': 'different', 'username': 'fixture_app'})
        with self.assertRaises(ValueError):
            resolve([request], lambda *args: {'database': 'fixture', 'username': 'fixture_app'})
