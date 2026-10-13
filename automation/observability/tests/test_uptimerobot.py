import copy
import unittest

from automation.observability.uptimerobot import contact, desired, reconcile, remove_fixture, public_url
from automation.observability.tests.fixtures import FakeAPI, existing


class IndependentTests(unittest.TestCase):
    def test_account_contact_is_exact_active_registered_email_only(self):
        api = FakeAPI()
        self.assertEqual(contact(api), 7)
        api.contacts.append(dict(api.contacts[0], id=8))
        with self.assertRaises(RuntimeError): contact(api)
        api.contacts = [dict(api.contacts[0], value='other@example.com')]
        with self.assertRaises(RuntimeError): contact(api)
        api.contacts = [{'id': 7, 'type': 'Email', 'value': api.user['email'], 'status': 'Inactive'}]
        with self.assertRaises(RuntimeError): contact(api)
        self.assertFalse(api.writes)

    def test_reject_changed_account_plan_and_override(self):
        api = FakeAPI()
        with self.assertRaises(RuntimeError): contact(api, 8)
        api.user['activeSubscription']['plan'] = 'PRO'
        with self.assertRaises(RuntimeError): contact(api)
        self.assertFalse(api.writes)

    def test_create_repeat_preserves_unrelated_monitor_and_id(self):
        api = FakeAPI()
        other = existing()
        other.update(id=99, friendlyName='operator-owned', url='https://other.example.com/health')
        api.rows.append(copy.deepcopy(other))
        result = reconcile(api, 'notes-health', 'https://notes.example.com/health', 7, apply=True)
        self.assertEqual(result['changes'], 1)
        self.assertEqual(len(api.writes), 1)
        self.assertEqual(api.rows[0], other)
        self.assertEqual(api.rows[1]['id'], 12)
        self.assertEqual(reconcile(api, 'notes-health', 'https://notes.example.com/health', 7, apply=True)['changes'], 0)
        self.assertEqual(len(api.writes), 1)

    def test_read_only_drift_and_repair_recipient_cache_redirect_configuration(self):
        api = FakeAPI()
        row = existing()
        row.update(assignedAlertContacts=[{'alertContactId': 99, 'threshold': 5, 'recurrence': 10}],
                   followRedirections=True, successHttpResponseCodes=['2xx', '3xx'])
        api.rows = [row]
        self.assertEqual(reconcile(api, 'notes-health', row['url'], 7)['changes'], 1)
        self.assertFalse(api.writes)
        reconcile(api, 'notes-health', row['url'], 7, apply=True)
        self.assertEqual(api.rows[0]['assignedAlertContacts'], [{'alertContactId': 7, 'threshold': 0, 'recurrence': 0}])
        self.assertEqual(api.rows[0]['id'], 12)

    def test_scope_collision_endpoint_change_pagination_and_pause_fail_before_write(self):
        for setting in ('duplicate', 'endpoint', 'pagination', 'pause', 'type'):
            api = FakeAPI()
            api.rows = [existing()]
            if setting == 'duplicate': api.rows.append(existing())
            if setting == 'endpoint': api.rows[0]['url'] = 'https://other.example.com/health'
            if setting == 'pagination': api.next_link = 'https://example.com/next'
            if setting == 'pause': api.rows[0]['status'] = 'PAUSED'
            if setting == 'type': api.rows[0]['type'] = 'KEYWORD'
            with self.subTest(setting=setting), self.assertRaises(RuntimeError):
                reconcile(api, 'notes-health', 'https://notes.example.com/health', 7, apply=True)
            self.assertFalse(api.writes)

    def test_fixture_failure_recovery_cleanup_never_changes_production(self):
        api = FakeAPI()
        production = existing()
        api.rows = [copy.deepcopy(production)]
        urls = ['https://notes.example.com/monitoring-proof/' + state for state in ('ready', 'failed', 'ready')]
        for url in urls:
            reconcile(api, 'notification-proof', url, 7, apply=True, allow_fixture_change=True)
            self.assertEqual(api.rows[0], production)
        remove_fixture(api, urls[-1])
        self.assertEqual(api.rows, [production])
        self.assertTrue(remove_fixture(api, urls[-1])['already_absent'])

    def test_reject_private_secret_and_ambiguous_urls(self):
        for url in ('http://notes.example.com/health', 'https://notes.internal.example.com/health',
                    'https://127.0.0.1/health', 'https://example.com/health?token=secret',
                    'https://user:pass@example.com/health', 'https://example.com:8443/health',
                    'https://example.com/%2e%2e/admin', 'https://example.com/health#fragment'):
            with self.subTest(url=url), self.assertRaises(ValueError): public_url(url)

    def test_no_paid_delays_or_extra_recipients_and_no_credentials(self):
        row = desired('notes-health', 'https://notes.example.com/health', 7)
        self.assertEqual(row['interval'], 300)
        self.assertEqual(row['assignedAlertContacts'], [{'alertContactId': 7, 'threshold': 0, 'recurrence': 0}])
        self.assertEqual(row['authType'], 'NONE')
        self.assertFalse(row['followRedirections'])
        self.assertNotIn('customFields', row)
