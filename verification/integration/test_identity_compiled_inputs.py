"""Compiled identity inputs survive the chart-to-compiler round trip.

Renders platform/identity/keycloak with representative merged values, feeds
the rendered ConfigMap files through load_compiled_inputs into
compile_clients, and checks a public-only and a mixed service.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'platform/identity/keycloak/runtime'))

import configuration

# Multiline PEM shaped like the CNPG public CA: must survive byte-identical.
MULTILINE_CA = (
    '-----BEGIN CERTIFICATE-----\n'
    'MIIBdzCCASGgAwIBAgIRAL0VhW8L8XJ6QZ5K9mJ+3w0wCgYIKoZIzj0EAwIw\n'
    'EjEQMA4GA1UEAxMHdGVzdC1jYTAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEw\n'
    'MDAwMDBaMBIxEDAOBgNVBAMTB3Rlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjO\n'
    'PQMBBwNCAAS7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJMA0GCSqGSIb3DQEBCwUA\n'
    'A0EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n'
    'AAAAAAAAAAA=\n'
    '-----END CERTIFICATE-----\n'
)


def merged_values():
    def entry(service, audience, roles):
        return {
            'approval': {'name': service},
            'definition': {'oidc': {
                'enabled': True, 'realm': 'applications', 'client': service,
                'public': True, 'callbackPaths': ['/oauth/callback'],
                'audience': audience, 'scopes': ['profile'], 'roleMapping': roles}},
            'publication': 'ready',
        }

    def published(service):
        return {
            'service': service, 'publication': 'published',
            'exposure': {'class': 'public', 'hostname': service + '.example.test',
                         'access': 'public', 'backend': 'web', 'path': '/', 'port': 8080},
        }

    return {
        'enabled': True,
        'trustedProxyAddresses': ['10.0.0.1'],
        'databaseCA': 'round-trip-fixture',
        'catalog': [entry('prices', 'prices-api', {}),
                    entry('shop', 'shop-api', {'viewer': ['viewer']})],
        'exposures': {'prices': published('prices'), 'shop': published('shop')},
        'tailnet': {'splitDNS': {'zone': 'internal.example.test'}},
        'privateDNS': {'services': [
            {'service': 'shop', 'name': 'shop', 'backend': 'web', 'path': '/', 'port': 8080}]},
    }


class CompiledInputsRoundTripTests(unittest.TestCase):
    def test_rendered_inputs_compile_public_only_and_mixed_clients(self):
        if shutil.which('helm') is None:
            raise unittest.SkipTest('helm renders the compiled-inputs ConfigMap')
        with tempfile.TemporaryDirectory() as workspace:
            work = Path(workspace)
            (work / 'values.yaml').write_text(yaml.safe_dump(merged_values()))
            rendered = subprocess.check_output(
                ['helm', 'template', '--kube-version', '1.36',
                 '--show-only', 'templates/compiled-state.yaml',
                 '-f', str(work / 'values.yaml'),
                 str(ROOT / 'platform/identity/keycloak')],
                text=True, timeout=120)
            config = yaml.safe_load(rendered)
            private = work / 'private'
            private.mkdir()
            for key in ('catalog', 'policy', 'exposures'):
                (private / key).write_text(config['data'][key])
            catalog, policy, exposures = configuration.load_compiled_inputs(private)
            clients, pending, skipped = configuration.compile_clients(
                catalog, policy, exposures, {'applications': {}},
                {'format': 1, 'realms': {}})
        self.assertEqual([row['id'] for row in clients], ['prices', 'shop'])
        self.assertEqual((pending, skipped), ([], []))
        prices = next(row for row in clients if row['id'] == 'prices')
        self.assertEqual(prices['callbacks'], ['https://prices.example.test/oauth/callback'])
        self.assertEqual(prices['web_origins'], ['https://prices.example.test'])
        shop = next(row for row in clients if row['id'] == 'shop')
        self.assertEqual(shop['callbacks'], ['https://shop.example.test/oauth/callback',
                                             'https://shop.internal.example.test/oauth/callback'])
        self.assertEqual(shop['roles'], ['viewer'])

    def test_multiline_database_ca_rides_generator_file_verbatim(self):
        if shutil.which('helm') is None:
            raise unittest.SkipTest('helm renders the identity root and server chart')
        values = {'identity': {'argo': {
            'valuesRepository': 'https://github.com/example/private.git',
            'valuesRevision': 'b' * 40}},
            'services': {'acceptanceCommitment': '2' * 64}}
        rendered = subprocess.check_output(
            ['helm', 'template', 'root', str(ROOT / 'gitops/roots/public'), '-f', '-'],
            input=json.dumps(values), text=True, timeout=120)
        parent = next(obj for obj in yaml.safe_load_all(rendered)
                      if obj and obj.get('kind') == 'ApplicationSet'
                      and obj['metadata']['name'] == 'cloudlab-identity')
        helm_source = parent['spec']['template']['spec']['sources'][0]['helm']
        self.assertNotIn('databaseCA', helm_source['valuesObject'])
        self.assertIn('$identityValues/identity/keycloak-values.yaml',
                      helm_source['valueFiles'])
        slots = {key for key, value in helm_source['valuesObject'].items()
                 if isinstance(value, str) and '{{' in value}
        self.assertEqual(slots, {'loginHost', 'adminHost', 'database', 'databaseRole',
                                 'databaseHost', 'databasePort', 'trustedProxyAddresses',
                                 'retiredEmergencyItem'})
        with tempfile.TemporaryDirectory() as workspace:
            work = Path(workspace)
            (work / 'values.yaml').write_text(yaml.safe_dump(merged_values()))
            (work / 'keycloak-values.yaml').write_text(
                'databaseCA: |\n' + textwrap.indent(MULTILINE_CA, '  '))
            server = subprocess.check_output(
                ['helm', 'template', '--kube-version', '1.36',
                 '--show-only', 'templates/server.yaml',
                 '-f', str(work / 'values.yaml'), '-f', str(work / 'keycloak-values.yaml'),
                 str(ROOT / 'platform/identity/keycloak')],
                text=True, timeout=120)
        bundle = next(obj for obj in yaml.safe_load_all(server)
                      if obj and obj.get('kind') == 'ConfigMap'
                      and obj['metadata']['name'] == 'keycloak-database-ca')
        self.assertEqual(bundle['data']['ca.crt'], MULTILINE_CA)
        folded = yaml.safe_load("databaseCA: '" + MULTILINE_CA + "'")['databaseCA']
        self.assertNotEqual(folded, MULTILINE_CA)


if __name__ == '__main__':
    unittest.main()
