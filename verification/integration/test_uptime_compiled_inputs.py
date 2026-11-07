"""Independent uptime declarations validate and join to exact monitor payloads.

Representative prices uptime and external-owner status records validate
against uptime.schema.json; malformed records fail. declared() joins a
reviewed declaration with its approved exposure host and private contact
into the exact desired() payload; unsafe hosts, paths or contacts fail
closed. Status roots stay within infra/status.contract.json. No network.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

from jsonschema import validate
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / 'platform/observability/uptime.schema.json').read_text())
CONTRACT = json.loads((ROOT / 'infra/status.contract.json').read_text())

_spec = importlib.util.spec_from_file_location(
    'cloudlab_uptimerobot', ROOT / 'platform/observability/uptimerobot.py')
uptimerobot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uptimerobot)


def prices(**overrides):
    record = {'service': 'prices',
              'independentMonitoring': {
                  'exposureReference': 'public', 'path': '/healthz',
                  'expectedStatus': 200, 'intervalSeconds': 300,
                  'notificationProfile': 'approved-operator-email'}}
    record.update(overrides)
    return record


def status(**overrides):
    record = {'externalOwnerStatus': {
        'roots': [{'name': 'cloudflare', 'enabled': True}],
        'maximumObservationAgeSeconds': 86400}}
    record.update(overrides)
    return record


class FakeAPI:
    """Canned provider inventory; reconcile(apply=False) only reads."""

    def __init__(self, rows):
        self.rows = rows

    def request(self, method, path, value=None):
        assert (method, path, value) == ('GET', 'monitors?limit=50', None)
        return {'data': copy.deepcopy(self.rows), 'nextLink': None}


class UptimeCompiledInputsTests(unittest.TestCase):
    def test_prices_uptime_and_status_records_validate(self):
        validate(prices(), SCHEMA)
        validate(status(), SCHEMA)
        self.assertLessEqual({root['name'] for root in
                              status()['externalOwnerStatus']['roots']},
                             set(CONTRACT['roots']))

    def test_malformed_records_fail_schema_and_join(self):
        monitoring = prices()['independentMonitoring']
        cases = [
            {},
            {'service': 'prices'},
            prices(extra='no'),
            prices(service='Prices'),
            # Schema service names (31 max) stay within monitor keys (32 max),
            # so every accepted declaration joins; 33 fails both here.
            prices(service='p' * 33),
            prices(independentMonitoring={}),
            prices(independentMonitoring=dict(
                monitoring, extra='no')),
            prices(independentMonitoring=dict(
                monitoring, exposureReference='Public')),
            prices(independentMonitoring=dict(
                monitoring, path='healthz')),
            prices(independentMonitoring=dict(
                monitoring, path='/a/../b')),
            prices(independentMonitoring=dict(
                monitoring, path='/%2e%2e/x')),
            prices(independentMonitoring=dict(
                monitoring, path='/x?y=1')),
            prices(independentMonitoring=dict(
                monitoring, expectedStatus=201)),
            prices(independentMonitoring=dict(
                monitoring, intervalSeconds=60)),
            prices(independentMonitoring=dict(
                monitoring, notificationProfile='Operator Email')),
            status(externalOwnerStatus={}),
            status(externalOwnerStatus={'roots': []}),
            status(externalOwnerStatus={
                'roots': [{'name': 'harbor', 'enabled': True}]}),
            status(externalOwnerStatus={
                'roots': [{'name': 'cloudflare'}]}),
            status(externalOwnerStatus={
                'roots': [{'name': 'cloudflare', 'enabled': True}],
                'maximumObservationAgeSeconds': 30}),
        ]
        for record in cases:
            with self.subTest(record=record):
                with self.assertRaises(ValidationError):
                    validate(record, SCHEMA)
                if 'service' in record:
                    with self.assertRaises(ValueError):
                        uptimerobot.declared(copy.deepcopy(record),
                                             'prices.example.com', 7)

    def test_declared_joins_approved_host_into_exact_payload(self):
        self.assertEqual(
            uptimerobot.declared(prices(), 'prices.example.com', 7),
            uptimerobot.desired('prices', 'https://prices.example.com/healthz', 7))

    def test_declared_rejects_unsafe_hosts_and_contacts(self):
        for host in ('https://prices.example.com', 'prices.example.com:443',
                     'prices.example.com/x', 'Prices.example.com', '10.0.0.11',
                     'prices.internal.example.com', 'user@prices.example.com',
                     '', None, 443):
            with self.subTest(host=host):
                with self.assertRaises(ValueError):
                    uptimerobot.declared(prices(), host, 7)
        for contact in (0, -1, '7', None):
            with self.subTest(contact=contact):
                with self.assertRaises(ValueError):
                    uptimerobot.declared(prices(), 'prices.example.com', contact)

    def test_owned_monitors_refuse_duplicates_and_changed_endpoints(self):
        rows = [{'id': 11, 'friendlyName': 'cloudlab-owned:prices', 'type': 'HTTP',
                 'url': 'https://prices.example.com/healthz'}]
        self.assertIsNone(uptimerobot.owned([], 'prices'))
        self.assertEqual(uptimerobot.owned(rows, 'prices'), rows[0])
        with self.assertRaises(RuntimeError):
            uptimerobot.owned(rows + rows, 'prices')
        moved = [dict(rows[0], url='https://other.example.com/healthz')]
        with self.assertRaisesRegex(RuntimeError, 'explicit migration'):
            uptimerobot.reconcile(FakeAPI(moved), 'prices',
                                  'https://prices.example.com/healthz', 7)
        observed = dict(uptimerobot.desired(
            'prices', 'https://prices.example.com/healthz', 7), id=11)
        settled = uptimerobot.reconcile(
            FakeAPI([observed]), 'prices',
            'https://prices.example.com/healthz', 7)
        self.assertEqual((settled['configured'], settled['changes']), (True, 0))


if __name__ == '__main__':
    unittest.main()
