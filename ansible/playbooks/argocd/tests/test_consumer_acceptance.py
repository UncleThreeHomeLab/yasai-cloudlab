"""Consumer proof validation and exact native gate; no controller qualification."""
import base64
import copy
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml
from jinja2 import Template
from private_sources import CONSUMER_ACCEPTANCE_VERSION, consumer_contract, validate_consumer_acceptance, accepted_consumer

ROOT = Path(__file__).resolve().parents[4]
REPOSITORY = 'https://github.com/example/private.git'


def fixture(consumer='observability', path='services/catalog-v2.yaml'):
    paths = ([path, 'platform/observability.yaml'] if consumer == 'observability'
             else [path, 'identity/argo-values.yaml'] if consumer == 'services' else ['platform/permissions.yaml'])
    receipt = {'version': CONSUMER_ACCEPTANCE_VERSION, 'consumer': consumer, 'paths': paths, 'revision': 'b' * 40, 'nonce': '1' * 64}
    digest = hashlib.sha256(('\n'.join([receipt['version'], consumer, REPOSITORY, str(len(paths)), *paths,
        receipt['revision'], receipt['nonce'], ''])).encode()).hexdigest()
    public = {'repository': 'https://github.com/example/platform.git', 'revision': 'main',
        'identity': {'enabled': True}, 'externalSecrets': {'enabled': True, 'reconcile': True}, 'admission': {'enabled': True},
        'services': {'enabled': True, 'revision': 'd' * 40, 'catalogPath': path},
        'observability': {'enabled': True, 'configuration': {'enabled': True, 'paused': False, 'revision': 'e' * 40}},
        'permissions': {'enabled': True, 'revision': 'f' * 40}}
    settings = (public['observability']['configuration'] if consumer == 'observability'
                else public['services'] if consumer == 'services' else public['permissions'])
    settings['acceptanceCommitment'] = digest
    return public, receipt


def document(raw, path):
    return {'type': 'file', 'path': path, 'encoding': 'base64', 'size': len(raw),
        'sha': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(), 'content': base64.b64encode(raw).decode()}


class ConsumerAcceptanceTests(unittest.TestCase):
    def gate(self, contract, params, *, repository=REPOSITORY, policy=None):
        policy = policy if policy is not None else (ROOT / 'gitops/roots/public/consumer-source-acceptance.tmpl').read_text()
        constants = {'VERSION': contract['version'], 'CONSUMER': contract['consumer'], 'PRIVATE_REPOSITORY': repository,
            'COMMITMENT': contract['acceptanceCommitment'], 'PATHS_LF': '\n'.join(contract['paths'])}
        for key, value in constants.items(): policy = policy.replace('@@' + key + '@@', json.dumps(value))
        with tempfile.TemporaryDirectory() as directory:
            chart = Path(directory); (chart / 'templates').mkdir()
            (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: consumer-proof\nversion: 1.0.0\n')
            (chart / 'templates/proof.yaml').write_text('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: consumer-proof}\ndata:\n  revision: {{ tpl .Values.policy .Values.params | quote }}\n')
            return subprocess.run(['helm', 'template', 'proof', str(chart), '-f', '-'],
                input=json.dumps({'policy': policy, 'params': params}), text=True, capture_output=True, timeout=30)

    def params(self, receipt):
        # Git-files GoTemplate mode preserves the array and injects this path map.
        return dict(copy.deepcopy(receipt), path={'path': 'platform/acceptance', 'basename': 'acceptance',
            'basenameNormalized': 'acceptance', 'filename': str(receipt['consumer']) + '.yaml',
            'filenameNormalized': str(receipt['consumer']) + '.yaml', 'segments': ['platform', 'acceptance']})

    def test_both_consumers_match_exact_native_effective_input_and_alternate_catalog_paths(self):
        for consumer, path in (('observability', 'services/catalog.json'), ('observability', 'services/catalog-selected.yaml'), ('permissions', 'services/catalog.json'),
                               ('services', 'services/catalog.json'), ('services', 'services/catalog-selected.yaml')):
            public, receipt = fixture(consumer, path); contract = consumer_contract(public, consumer)
            validate_consumer_acceptance(receipt, REPOSITORY, contract)
            result = self.gate(contract, self.params(receipt))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(yaml.safe_load(result.stdout)['data']['revision'], receipt['revision'])
            self.assertEqual(contract['receiptPath'], 'platform/acceptance/' + consumer + '.yaml')

    def test_python_and_native_refuse_cross_scope_types_replay_and_unknown_effective_fields(self):
        for consumer in ('observability', 'permissions', 'services'):
            public, receipt = fixture(consumer); contract = consumer_contract(public, consumer)
            for case in ('consumer', 'version', 'path', 'order', 'count', 'duplicate', 'path-type', 'paths-type', 'revision', 'nonce', 'unknown', 'revision-type', 'nonce-type'):
                invalid = copy.deepcopy(receipt)
                if case == 'consumer': invalid['consumer'] = 'observability' if consumer == 'permissions' else 'permissions'
                if case == 'version': invalid['version'] = 'cloudlab-private-source-acceptance/v1'
                if case == 'path': invalid['paths'][0] = 'platform/private.yaml'
                if case == 'order': invalid['paths'] = list(reversed(invalid['paths'])) if consumer in ('observability', 'services') else []
                if case == 'count': invalid['paths'].append('platform/extra.yaml')
                if case == 'duplicate': invalid['paths'] = [invalid['paths'][0]] * (len(invalid['paths']) + 1)
                if case == 'path-type': invalid['paths'][0] = True
                if case == 'paths-type': invalid['paths'] = 'platform/permissions.yaml'
                if case == 'revision': invalid['revision'] = 'a' * 40
                if case == 'nonce': invalid['nonce'] = '2' * 64
                if case == 'unknown': invalid['unexpected'] = True
                if case == 'revision-type': invalid['revision'] = 123
                if case == 'nonce-type': invalid['nonce'] = False
                with self.subTest(consumer=consumer, case=case):
                    with self.assertRaisesRegex(ValueError, '^Consumer source acceptance refused$'):
                        validate_consumer_acceptance(invalid, REPOSITORY, contract)
                    self.assertNotEqual(self.gate(contract, self.params(invalid)).returncode, 0)
            with self.assertRaises(ValueError): validate_consumer_acceptance(receipt, 'https://github.com/example/foreign.git', contract)
            self.assertNotEqual(self.gate(contract, self.params(receipt), repository='https://github.com/example/foreign.git').returncode, 0)

    def test_finite_contracts_require_typed_enabled_approval_and_keep_disabled_reads_empty(self):
        for consumer in ('observability', 'permissions', 'services'):
            public, receipt = fixture(consumer)
            for case in ('enabled-type', 'missing-approval', 'pin', 'prerequisite', 'unsafe-path'):
                invalid = copy.deepcopy(public)
                settings = (invalid['observability']['configuration'] if consumer == 'observability'
                            else invalid['services'] if consumer == 'services' else invalid['permissions'])
                if case == 'enabled-type': settings['enabled'] = 1
                if case == 'missing-approval': settings.pop('acceptanceCommitment')
                if case == 'pin': settings['revision'] = 'main'
                if case == 'prerequisite': invalid['externalSecrets']['reconcile'] = False
                if case == 'unsafe-path':
                    if consumer in ('observability', 'services'): invalid['services']['catalogPath'] = 'services/../identity.yaml'
                    else: settings['enabled'] = 'false'
                with self.subTest(consumer=consumer, case=case), self.assertRaises(ValueError): consumer_contract(invalid, consumer)
            settings = (public['observability']['configuration'] if consumer == 'observability'
                        else public['services'] if consumer == 'services' else public['permissions'])
            settings['enabled'] = False
            client = Mock(request=Mock(side_effect=AssertionError('Disabled receipt must not read private Git')))
            self.assertIsNone(accepted_consumer(client, '', 'not-a-sha', public, consumer))
            with self.assertRaises(ValueError): validate_consumer_acceptance(receipt, REPOSITORY, consumer_contract(public, consumer))
            client.request.assert_not_called()
        with self.assertRaises(ValueError): consumer_contract(public, 'private-sources')
