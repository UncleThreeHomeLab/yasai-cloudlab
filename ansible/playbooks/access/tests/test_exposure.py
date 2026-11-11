"""Consolidated exposure bundle and plan-approval binding fail closed."""
import unittest

import exposure


class BundleTests(unittest.TestCase):
    zone = 'example.test'

    def text(self, entries):
        lines = ['exposures:']
        for key, document in entries.items():
            lines.append('  %s:' % key)
            lines.append('    service: %s' % document['service'])
            lines.append('    publication: %s' % document['publication'])
            lines.append('    exposure:')
            for field, value in document['exposure'].items():
                lines.append('      %s: %s' % (field, value))
        return '\n'.join(lines) + '\n'

    def published(self, service='prices'):
        return {'service': service, 'publication': 'published',
                'exposure': {'class': 'public', 'hostname': service + '.example.test',
                             'access': 'public', 'backend': 'web', 'path': '/', 'port': 8080}}

    def test_valid_bundle_returns_sorted_documents(self):
        documents = exposure.validate_bundle(
            self.text({'b-svc': self.published('b-svc'), 'a-svc': self.published('a-svc')}),
            self.zone)
        self.assertEqual([row['service'] for row in documents], ['a-svc', 'b-svc'])

    def test_key_service_mismatch_refused(self):
        with self.assertRaisesRegex(ValueError, 'must match its service'):
            exposure.validate_bundle(self.text({'prices': self.published('other')}), self.zone)

    def test_foreign_hostname_refused(self):
        entry = self.published()
        entry['exposure']['hostname'] = 'prices.foreign.test'
        with self.assertRaisesRegex(ValueError, 'inside the declared zone'):
            exposure.validate_bundle(self.text({'prices': entry}), self.zone)

    def test_takeover_refused(self):
        entry = self.published()
        entry['exposure']['hostname'] = 'other.example.test'
        with self.assertRaisesRegex(ValueError, 'another hostname'):
            exposure.validate_bundle(self.text({'prices': entry}), self.zone)

    def test_retired_entry_compiles_to_withdrawal(self):
        entry = self.published()
        entry['publication'] = 'retired'
        compiled = exposure.compile_service_exposures([entry], {})
        self.assertEqual(compiled, {'service_exposures': {}, 'applications': {}})


class ApprovalTests(unittest.TestCase):
    revision = 'a' * 40
    plan = 'b' * 64

    def test_binding_returns_bound_revision_and_plan(self):
        revision, plan = exposure.validate_approval(
            'revision: %s\nplan: %s\n' % (self.revision, self.plan))
        self.assertEqual(revision, self.revision)
        self.assertEqual(plan, self.plan)

    def test_malformed_binding_fails_loudly(self):
        with self.assertRaises(Exception):
            exposure.validate_approval('revision: %s\n' % self.revision)
