import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

from playbooks.services.tests.fixtures import data_secret_values, data_secret_render, data_secret_documents


class CredentialTests(unittest.TestCase):
    def test_live_fixture_namespace_renders_with_its_canonical_service_identity(self):
        service = 'data-proof-0123456789abcdef'
        namespace = 'cloudlab-app-' + service
        values = data_secret_values(namespace)
        entry = values['catalog'][0]
        self.assertEqual(entry['approval']['name'], service)
        self.assertEqual(entry['definition']['name'], service)
        self.assertEqual({scope['service'] for scope in values['dataApprovals'].values()}, {service})
        selected = data_secret_documents(namespace)
        native_namespace = selected['namespace_document']
        self.assertEqual(native_namespace['kind'], 'Namespace')
        self.assertEqual(native_namespace['metadata']['name'], namespace)
        self.assertEqual(native_namespace['metadata']['labels'], {
            'cloudlab.io/owner': 'service-platform', 'istio.io/dataplane-mode': 'ambient',
            'cloudlab.io/service-secrets': 'approved', 'pod-security.kubernetes.io/enforce': 'restricted',
            'pod-security.kubernetes.io/enforce-version': 'v1.36'})
        self.assertEqual(native_namespace['metadata']['annotations']['argocd.argoproj.io/sync-options'], 'Prune=false,Delete=false')
        secrets = selected['documents']
        self.assertEqual({obj['metadata']['name'] for obj in secrets}, {'database', 'bucket'})
        self.assertEqual({obj['metadata']['namespace'] for obj in secrets}, {namespace})
        for obj in secrets:
            name = obj['metadata']['name']
            self.assertEqual(obj['spec']['target']['name'], name)
            self.assertEqual(obj['spec']['dataFrom'], [{'extract': {'key': 'approved-' + name + '-item'}}])

    def test_data_templates_project_exact_fields_and_refuse_each_missing_or_empty_value(self):
        result = data_secret_render(data_secret_values())
        self.assertEqual(result.returncode, 0, result.stderr)
        objects = [obj for obj in yaml.safe_load_all(result.stdout) if obj and obj['kind'] == 'ExternalSecret']
        self.assertEqual(len(objects), 2)
        fields = {'database': ('username', 'password'),
                  'bucket': ('BUCKET', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY', 'ENDPOINT', 'REGION')}
        with tempfile.TemporaryDirectory() as temporary:
            chart = Path(temporary)
            (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: secret-template-check\nversion: 0.0.0\n')
            (chart / 'templates').mkdir()
            (chart / 'templates/secret.yaml').write_text('apiVersion: v1\nkind: Secret\nmetadata: {name: synthetic}\nstringData:\n'
                '{{- range $key, $template := .Values.templates }}\n'
                '  {{ $key | quote }}: {{ tpl $template (merge (dict "Template" $.Template) $.Values.input) | quote }}\n'
                '{{- end }}\n')
            for obj in objects:
                name, spec = obj['metadata']['name'], obj['spec']
                self.assertEqual(obj['metadata']['namespace'], 'cloudlab-app-synthetic')
                self.assertEqual(spec['refreshInterval'], '24h')
                self.assertEqual(spec['secretStoreRef'], {'name': 'cloudlab', 'kind': 'ClusterSecretStore'})
                self.assertEqual(spec['target']['name'], name)
                self.assertEqual(spec['target']['creationPolicy'], 'Owner')
                self.assertEqual(spec['target']['deletionPolicy'], 'Retain')
                self.assertNotIn('data', spec)
                self.assertEqual(spec['dataFrom'], [{'extract': {'key': 'approved-' + name + '-item'}}])
                template = spec['target']['template']
                self.assertEqual(template['engineVersion'], 'v2')
                self.assertEqual(template['mergePolicy'], 'Replace')
                self.assertEqual(set(template['data']), set(fields[name]))
                source = {field: '0' if index == 0 else 'synthetic\nvalue\n'
                          for index, field in enumerate(fields[name])}
                source['unapproved'] = 'must-not-copy'

                def evaluate(data):
                    return subprocess.run(['helm', 'template', 'secret-template-check', str(chart), '-f', '-'],
                        input=yaml.safe_dump({'templates': template['data'], 'input': data}),
                        capture_output=True, text=True, timeout=30)

                valid = evaluate(source)
                self.assertEqual(valid.returncode, 0, valid.stderr)
                self.assertEqual(yaml.safe_load(valid.stdout)['stringData'], {field: source[field] for field in fields[name]})
                for field in fields[name]:
                    for missing in (True, False):
                        with self.subTest(name=name, field=field, missing=missing):
                            data = dict(source)
                            if missing: del data[field]
                            else: data[field] = ''
                            invalid = evaluate(data)
                            self.assertNotEqual(invalid.returncode, 0)
                            self.assertIn('Required data secret field is missing or empty', invalid.stderr)
                            self.assertNotIn('<nil>', invalid.stdout)
                            self.assertNotIn('<no value>', invalid.stdout)

    def test_data_scope_mismatch_stays_blocked(self):
        values = data_secret_values()
        for field, wrong in (('service', 'foreign'), ('name', 'foreign'), ('kind', 'bucket')):
            invalid = copy.deepcopy(values)
            invalid['dataApprovals']['database'][field] = wrong
            result = data_secret_render(invalid)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Unapproved data scope', result.stderr)
